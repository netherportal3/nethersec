import { describe, expect, it } from 'vitest'
import {
  classifyLockfilePath,
  isDevRequirementsPath,
  isIgnoredLockfilePath,
  normalizePypiName,
  parseBunLock,
  parseLockfile,
  parsePackageLock,
  parsePnpmKey,
  parsePnpmLock,
  parsePythonLock,
  parseRequirements,
  parseYarnLock,
  pnpmLockMajor,
  selectLockfiles,
  stripJsonc,
  type InstalledPackage,
} from '../src/scanner/lockfiles.js'

// Every sample is inline and synthetic. A test file NAMED like a real manifest
// (package-lock.json, requirements.txt, ...) would be picked up by GitHub's
// dependency graph and by this very bot, so none is kept on disk.
const LF = '\n'
const CR = '\r'
const find = (pkgs: InstalledPackage[], name: string) => pkgs.filter((p) => p.name === name)

describe('lockfile path selection', () => {
  it('classifies the supported, the recognized-but-unsupported, and the rest', () => {
    expect(classifyLockfilePath('package-lock.json')).toBe('npm')
    expect(classifyLockfilePath('web/npm-shrinkwrap.json')).toBe('npm')
    expect(classifyLockfilePath('pnpm-lock.yaml')).toBe('pnpm')
    expect(classifyLockfilePath('bun.lock')).toBe('bun')
    expect(classifyLockfilePath('yarn.lock')).toBe('yarn')
    expect(classifyLockfilePath('api/uv.lock')).toBe('uv')
    expect(classifyLockfilePath('poetry.lock')).toBe('poetry')
    expect(classifyLockfilePath('requirements.txt')).toBe('pip')
    expect(classifyLockfilePath('requirements-dev.txt')).toBe('pip')
    expect(classifyLockfilePath('requirements/base.txt')).toBe('pip')
    expect(classifyLockfilePath('bun.lockb')).toBe('unsupported')
    expect(classifyLockfilePath('Pipfile.lock')).toBe('unsupported')
    expect(classifyLockfilePath('package.json')).toBeNull()
    expect(classifyLockfilePath('docs/notes.txt')).toBeNull()
  })

  it('ignores lockfiles inside installed, vendored or fixture trees', () => {
    expect(isIgnoredLockfilePath('node_modules/x/package-lock.json')).toBe(true)
    expect(isIgnoredLockfilePath('.venv/lib/requirements.txt')).toBe(true)
    expect(isIgnoredLockfilePath('test/fixtures/package-lock.json')).toBe(true)
    expect(isIgnoredLockfilePath('apps/web/package-lock.json')).toBe(false)
    expect(isIgnoredLockfilePath('node_modules')).toBe(false)
  })

  it('picks lockfiles from a tree, skipping too-big, unsupported and over-cap ones WITH a reason', () => {
    const tree = [
      { path: 'b/package-lock.json', type: 'blob', sha: 's2', size: 10 },
      { path: 'a/package-lock.json', type: 'blob', sha: 's1', size: 10 },
      { path: 'c/package-lock.json', type: 'blob', sha: 's3', size: 10 },
      { path: 'big/pnpm-lock.yaml', type: 'blob', sha: 's4', size: 999 },
      { path: 'bun.lockb', type: 'blob', sha: 's5', size: 10 },
      { path: 'src', type: 'tree', sha: 's6' },
      { path: 'node_modules/x/package-lock.json', type: 'blob', sha: 's7', size: 10 },
    ]
    const sel = selectLockfiles(tree, { maxFiles: 2, maxBytes: 100 })
    expect(sel.selected.map((s) => s.path)).toEqual(['a/package-lock.json', 'b/package-lock.json'])
    expect(sel.skipped).toEqual([
      { path: 'big/pnpm-lock.yaml', reason: 'too big' },
      { path: 'bun.lockb', reason: 'format not supported' },
      { path: 'c/package-lock.json', reason: 'over the per-repo lockfile cap' },
    ])
  })
})

describe('package-lock', () => {
  it('v3: names from the segment after the LAST node_modules/, dev flags, links and aliases', () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { a: '^1' } },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/a/node_modules/@s/b': { version: '2.0.0' },
        'node_modules/typescript': { version: '5.0.0', dev: true },
        'node_modules/both': { version: '1.0.0', devOptional: true },
        'node_modules/alias': { name: 'real-pkg', version: '3.1.0' },
        'node_modules/ws-link': { link: true, resolved: 'packages/ws' },
        'packages/ws': { name: 'ws', version: '0.0.1' },
        'node_modules/gitdep': { version: 'git+https://example.invalid/x.git' },
      },
    }
    const pkgs = parsePackageLock(JSON.stringify(lock))
    expect(pkgs).toEqual([
      { name: 'a', version: '1.0.0', dev: false },
      { name: '@s/b', version: '2.0.0', dev: false },
      { name: 'typescript', version: '5.0.0', dev: true },
      { name: 'both', version: '1.0.0', dev: false },
      { name: 'real-pkg', version: '3.1.0', dev: false },
    ])
  })

  it('v1: walks nested dependencies, resolves npm: aliases, skips git versions', () => {
    const lock = {
      lockfileVersion: 1,
      dependencies: {
        a: { version: '1.0.0', dependencies: { b: { version: '2.0.0', dev: true } } },
        b: { version: '2.1.0' },
        al: { version: 'npm:real@4.0.0' },
        g: { version: 'github:me/g#abc' },
      },
    }
    const pkgs = parsePackageLock(JSON.stringify(lock))
    expect(find(pkgs, 'b').map((p) => p.version).sort()).toEqual(['2.0.0', '2.1.0'])
    expect(find(pkgs, 'b').find((p) => p.version === '2.0.0')?.dev).toBe(true)
    expect(find(pkgs, 'real')).toEqual([{ name: 'real', version: '4.0.0', dev: false }])
    expect(find(pkgs, 'g')).toEqual([])
  })

  it('a package is dev-only only when every copy is', () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        'node_modules/x': { version: '1.0.0', dev: true },
        'node_modules/y/node_modules/x': { version: '1.0.0' },
      },
    }
    expect(parsePackageLock(JSON.stringify(lock))).toEqual([{ name: 'x', version: '1.0.0', dev: false }])
  })

  it('a key like "constructor" does not reach Object.prototype', () => {
    const text = '{"lockfileVersion":3,"packages":{"node_modules/constructor":{"version":"1.0.0"}}}'
    expect(parsePackageLock(text)).toEqual([{ name: 'constructor', version: '1.0.0', dev: false }])
  })
})

describe('pnpm-lock.yaml', () => {
  it('reads the major version from each header form', () => {
    expect(pnpmLockMajor('lockfileVersion: 5.4\n')).toBe(5)
    expect(pnpmLockMajor("lockfileVersion: '6.0'\n")).toBe(6)
    expect(pnpmLockMajor("lockfileVersion: '9.0'\r\n")).toBe(9)
    expect(pnpmLockMajor('nope: 1\n')).toBeNull()
  })

  it('parses package keys for v5, v6 and v9 including scopes and peer suffixes', () => {
    expect(parsePnpmKey('/next/12.3.1_biqbaboplfbrettd7655fr4n2y', 5)).toEqual({ name: 'next', version: '12.3.1' })
    expect(parsePnpmKey('/@next/env/12.3.1', 5)).toEqual({ name: '@next/env', version: '12.3.1' })
    expect(parsePnpmKey('/next@14.0.3(react-dom@18.2.0)(react@18.2.0)', 6)).toEqual({ name: 'next', version: '14.0.3' })
    expect(parsePnpmKey("'/@next/env@14.0.3'", 6)).toEqual({ name: '@next/env', version: '14.0.3' })
    expect(parsePnpmKey("'@next/env@15.5.26'", 9)).toEqual({ name: '@next/env', version: '15.5.26' })
    expect(parsePnpmKey('next@15.5.26(@types/node@20.19.43)(react-dom@19.2.8(react@19.2.8))(react@19.2.8)', 9)).toEqual({
      name: 'next',
      version: '15.5.26',
    })
    expect(parsePnpmKey('github.com/someone/fork/0123456789abcdef', 5)).toBeNull()
    expect(parsePnpmKey('fork@https://codeload.github.com/x/y/tar.gz/abc', 9)).toBeNull()
    expect(parsePnpmKey('ui@link:packages/ui', 9)).toBeNull()
  })

  it('v6: dev true/false, and an absent dev flag (used by both) is unknown', () => {
    const text = [
      "lockfileVersion: '6.0'",
      '',
      'dependencies:',
      '  react:',
      '    specifier: ^18',
      '    version: 18.2.0',
      '',
      'packages:',
      '',
      '  /react@18.2.0:',
      '    resolution: {integrity: sha512-FIXTURE}',
      '    dev: false',
      '',
      '  /eslint@8.0.0:',
      '    resolution: {integrity: sha512-FIXTURE}',
      '    dev: true',
      '',
      '  /postcss@8.4.31:',
      '    resolution: {integrity: sha512-FIXTURE}',
      '',
    ].join(LF)
    expect(parsePnpmLock(text)).toEqual([
      { name: 'react', version: '18.2.0', dev: false },
      { name: 'eslint', version: '8.0.0', dev: true },
      { name: 'postcss', version: '8.4.31', dev: null },
    ])
    expect(parsePnpmLock(text.replace(/\n/g, '\r\n'))).toHaveLength(3)
  })

  it('throws on a file with no lockfileVersion', () => {
    expect(() => parsePnpmLock('packages:\n  /a@1.0.0:\n')).toThrow()
  })
})

describe('dev or runtime from the dependency graph', () => {
  const pnpmV9 = (snapshots: string[]) =>
    [
      "lockfileVersion: '9.0'",
      '',
      'importers:',
      '',
      '  .:',
      '    dependencies:',
      '      next:',
      '        specifier: ^15.0.0',
      '        version: 15.5.26(react@19.2.0)',
      '    devDependencies:',
      '      eslint:',
      '        specifier: ^9',
      '        version: 9.1.0',
      '      str-cjs:',
      '        specifier: npm:string-width@^4',
      '        version: string-width@4.2.3',
      '',
      'packages:',
      '',
      ...['next@15.5.26', 'react@19.2.0', 'eslint@9.1.0', 'debug@4.3.4', 'ms@2.1.3', 'string-width@4.2.3'].flatMap((k) => [
        `  ${k}:`,
        '    resolution: {integrity: sha512-FIXTURE}',
        '',
      ]),
      'snapshots:',
      '',
      ...snapshots,
    ].join(LF)
  const graph = [
    '  next@15.5.26(react@19.2.0):',
    '    dependencies:',
    '      react: 19.2.0',
    '      ms: 2.1.3',
    '',
    '  react@19.2.0: {}',
    '',
    '  eslint@9.1.0:',
    '    dependencies:',
    '      debug: 4.3.4',
    '    transitivePeerDependencies:',
    '      - supports-color',
    '',
    '  debug@4.3.4:',
    '    dependencies:',
    '      ms: 2.1.3',
    '',
    '  ms@2.1.3: {}',
    '',
    '  string-width@4.2.3: {}',
    '',
  ]
  const devOf = (pkgs: InstalledPackage[]) => Object.fromEntries(pkgs.map((p) => [p.name, p.dev]))

  it('pnpm v9: only what devDependencies alone reach is dev', () => {
    expect(devOf(parseLockfile('pnpm-lock.yaml', 'pnpm', pnpmV9(graph)).packages)).toEqual({
      next: false,
      react: false,
      ms: false, // also under eslint > debug, but next needs it
      eslint: true,
      debug: true,
      'string-width': true, // an alias in devDependencies
    })
    // The packages-only parse keeps the format's own answer (unknown).
    expect(parsePnpmLock(pnpmV9(graph)).every((p) => p.dev === null)).toBe(true)
  })

  it('pnpm v9: an edge to a snapshot that is not there leaves every package unknown', () => {
    const broken = graph.filter((l) => l !== '  ms@2.1.3: {}')
    expect(parseLockfile('pnpm-lock.yaml', 'pnpm', pnpmV9(broken)).packages.every((p) => p.dev === null)).toBe(true)
  })

  it('bun: resolves like node_modules (nested copy first), a dev-only subtree is dev', () => {
    const lock = {
      lockfileVersion: 1,
      workspaces: { '': { name: 'app', dependencies: { a: '^1' }, devDependencies: { b: '^1' } } },
      packages: {
        a: ['a@1.0.0', '', { dependencies: { c: '^1' } }, 'sha512-FIXTURE'],
        b: ['b@1.0.0', '', { dependencies: { c: '^1', d: '^2' }, peerDependencies: { missing: '*' } }, 'sha512-FIXTURE'],
        c: ['c@1.0.0', '', {}, 'sha512-FIXTURE'],
        d: ['d@1.0.0', '', {}, 'sha512-FIXTURE'],
        'b/d': ['d@2.0.0', '', {}, 'sha512-FIXTURE'],
      },
    }
    const pkgs = parseLockfile('bun.lock', 'bun', JSON.stringify(lock)).packages
    expect(Object.fromEntries(pkgs.map((p) => [`${p.name}@${p.version}`, p.dev]))).toEqual({
      'a@1.0.0': false,
      'b@1.0.0': true,
      'c@1.0.0': false,
      'd@1.0.0': null, // nothing reaches the hoisted copy
      'd@2.0.0': true,
    })
    const unresolved = { ...lock, packages: { ...lock.packages, a: ['a@1.0.0', '', { dependencies: { gone: '^1' } }, 'sha512-FIXTURE'] } }
    expect(parseLockfile('bun.lock', 'bun', JSON.stringify(unresolved)).packages.every((p) => p.dev === null)).toBe(true)
  })

  it('pip: a requirements file is dev by its name, runtime otherwise', () => {
    for (const p of ['requirements-dev.txt', 'api/requirements_test.txt', 'requirements.lint.txt', 'requirements/docs.txt', 'requirements/ci.txt']) {
      expect(isDevRequirementsPath(p), p).toBe(true)
    }
    for (const p of ['requirements.txt', 'requirements-prod.txt', 'requirements-devops.txt', 'requirements/base.txt', 'dev/requirements.txt']) {
      expect(isDevRequirementsPath(p), p).toBe(false)
    }
    expect(parseLockfile('requirements-dev.txt', 'pip', 'pytest==8.0.0\n').packages).toEqual([{ name: 'pytest', version: '8.0.0', dev: true }])
    expect(parseLockfile('requirements.txt', 'pip', 'flask==3.0.0\n').packages).toEqual([{ name: 'flask', version: '3.0.0', dev: false }])
  })
})

describe('bun.lock', () => {
  it('strips trailing commas and comments without touching strings', () => {
    const text = '{ "a": "x, }", // c\n "b": [1, 2, ], /* d */ "c": "//not" , }'
    expect(JSON.parse(stripJsonc(text))).toEqual({ a: 'x, }', b: [1, 2], c: '//not' })
  })

  it('reads name@version from element 0, including nested keys and scopes', () => {
    const text = `{
      "lockfileVersion": 1,
      "workspaces": { "": { "name": "app", "dependencies": { "axios": "^1" } } },
      "packages": {
        "axios": ["axios@1.20.0", "", {}, "sha512-FIXTURE"],
        "@discordjs/rest": ["@discordjs/rest@2.6.3", "", {}, "sha512-FIXTURE"],
        "wif/bs58check/bs58": ["bs58@4.0.1", "", {}, "sha512-FIXTURE"],
      },
    }`
    const pkgs = parseBunLock(text)
    expect(find(pkgs, 'axios')).toEqual([{ name: 'axios', version: '1.20.0', dev: null }])
    expect(find(pkgs, '@discordjs/rest')).toHaveLength(1)
    expect(find(pkgs, 'bs58')).toEqual([{ name: 'bs58', version: '4.0.1', dev: null }])
  })
})

describe('requirements*.txt', () => {
  it('skips options, URLs and VCS lines; handles markers, hashes and continuations', () => {
    const text = [
      '-r base.txt',
      '--index-url https://example.invalid/simple',
      '-e git+https://github.com/x/y.git#egg=y',
      'git+https://github.com/x/z.git',
      'pkg @ https://example.invalid/pkg.whl',
      'urllib3==1.26.5 ; python_version < "3.10"',
      'idna==3.4 \\',
      '    --hash=sha256:0000',
      'Flask[async]==3.0.0  # web',
      'wild==1.2.*',
      'ranged>=1,<2',
    ].join(LF)
    const { packages, unpinned } = parseRequirements(text)
    expect(packages).toEqual([
      { name: 'urllib3', version: '1.26.5', dev: null },
      { name: 'idna', version: '3.4', dev: null },
      { name: 'flask', version: '3.0.0', dev: null },
    ])
    expect(unpinned).toBe(2)
  })

  it('normalizes PyPI names', () => {
    expect(normalizePypiName('Flask_SQLAlchemy')).toBe('flask-sqlalchemy')
    expect(normalizePypiName('python.dateutil')).toBe('python-dateutil')
  })
})

describe('yarn.lock, uv.lock and poetry.lock', () => {
  it('yarn v1: registry entries by their first descriptor, aliases as the real package, no git or file ones', () => {
    const yarnV1 = [
      '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.',
      '# yarn lockfile v1',
      '',
      '"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":',
      '  version "7.12.13"',
      '',
      'lodash@^4.17.20, lodash@^4.17.21:',
      '  version "4.17.21"',
      '',
      '"string-width-cjs@npm:string-width@^4.2.0":',
      '  version "4.2.3"',
      '',
      '"my-lib@github:me/my-lib#main":',
      '  version "1.0.0"',
      '',
      '"local@file:./local":',
      '  version "0.0.1"',
      '',
    ]
    expect(parseYarnLock(yarnV1.join(LF))).toEqual([
      { name: '@babel/code-frame', version: '7.12.13', dev: null },
      { name: 'lodash', version: '4.17.21', dev: null },
      { name: 'string-width', version: '4.2.3', dev: null },
    ])
    expect(parseYarnLock(yarnV1.join('\r\n'))).toHaveLength(3)
  })

  it('yarn berry: npm: resolutions only, and anything else throws', () => {
    const berry = [
      '__metadata:',
      '  version: 8',
      '',
      '"axios@npm:^1.6.0":',
      '  version: 1.6.8',
      '  resolution: "axios@npm:1.6.8"',
      '',
      '"resolve@patch:resolve@npm%3A^1.22.1#~builtin<compat/resolve>":',
      '  version: 1.22.8',
      '  resolution: "resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8&hash=c3c19d"',
      '',
      '"@scope/app@workspace:.":',
      '  version: 0.0.0-use.local',
      '  resolution: "@scope/app@workspace:."',
      '',
    ]
    expect(parseYarnLock(berry.join(LF))).toEqual([{ name: 'axios', version: '1.6.8', dev: null }])
    expect(() => parseYarnLock('lodash@^4:\n  version "4.17.21"\n')).toThrow()
  })

  it('uv.lock: registry packages only, names normalized', () => {
    const uv = [
      'version = 1',
      '',
      '[[package]]',
      'name = "Flask_Cors"',
      'version = "4.0.0"',
      'source = { registry = "https://pypi.org/simple" }',
      '',
      '[[package]]',
      'name = "my-app"',
      'version = "0.1.0"',
      'source = { editable = "." }',
      '',
      '[package.metadata]',
      'requires-dist = [{ name = "flask-cors", specifier = ">=4" }]',
      '',
      '[[package]]',
      'name = "mylib"',
      'version = "0.2.0"',
      'source = { git = "https://github.com/me/mylib?rev=main#abc" }',
      '',
    ]
    const lf = parseLockfile('uv.lock', 'uv', uv.join(LF))
    expect(lf).toMatchObject({ kind: 'uv', ecosystem: 'PyPI', unpinned: 0 })
    expect(lf.packages).toEqual([{ name: 'flask-cors', version: '4.0.0', dev: null }])
    expect(() => parsePythonLock('not a lockfile', 'uv')).toThrow()
  })

  it('poetry.lock: index packages with their dev scope, never a git source', () => {
    const poetry = [
      '[[package]]',
      'name = "certifi"',
      'version = "2024.2.2"',
      'groups = ["main"]',
      '',
      '[[package]]',
      'name = "pytest"',
      'version = "8.0.0"',
      'groups = ["dev", "test"]',
      '',
      '[package.dependencies]',
      'name = ">=1"',
      '',
      '[[package]]',
      'name = "black"',
      'version = "23.1.0"',
      'category = "dev"',
      '',
      '[[package]]',
      'name = "private"',
      'version = "1.0.0"',
      '',
      '[package.source]',
      'type = "git"',
      'url = "https://github.com/me/private.git"',
      '',
      '[metadata]',
      'lock-version = "2.1"',
      '',
    ]
    expect(parsePythonLock(poetry.join(LF), 'poetry')).toEqual([
      { name: 'certifi', version: '2024.2.2', dev: false },
      { name: 'pytest', version: '8.0.0', dev: true },
      { name: 'black', version: '23.1.0', dev: true },
    ])
  })
})

describe('hostile or broken input stays cheap', () => {
  const ms = (fn: () => unknown) => {
    const t = performance.now()
    fn()
    return performance.now() - t
  }
  const N = 200_000

  it('requirements: long blank runs, lone CRs and repeated " #" parse in linear time', () => {
    expect(ms(() => parseRequirements('a' + ' '.repeat(N) + 'x' + CR + 'y' + LF))).toBeLessThan(500)
    expect(ms(() => parseRequirements(' #'.repeat(N) + CR))).toBeLessThan(500)
    expect(ms(() => parseRequirements(('flask ' + '['.repeat(4000) + LF).repeat(50)))).toBeLessThan(500)
  })

  it('pnpm: long blank runs on column-0, key and header lines parse in linear time', () => {
    const head = "lockfileVersion: '9.0'" + LF + LF + 'packages:' + LF
    expect(ms(() => parsePnpmLock(head + ':' + ' '.repeat(N) + 'x' + LF))).toBeLessThan(500)
    expect(ms(() => parsePnpmLock(head + '  a:' + ' '.repeat(N) + 'x' + LF))).toBeLessThan(500)
    expect(ms(() => parsePnpmLock(head + 'lockfileVersion:' + ' '.repeat(N) + LF))).toBeLessThan(500)
  })

  it('a CR-only file is read line by line, not as one line', () => {
    const { packages, unpinned } = parseRequirements(['flask==2.0.0', 'requests==2.30.0', 'gunicorn>=20', ''].join(CR))
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual(['flask@2.0.0', 'requests@2.30.0'])
    expect(unpinned).toBe(1)
    const pnpm = ["lockfileVersion: '9.0'", '', 'packages:', '', '  next@16.2.3:', '    resolution: {}', ''].join(CR)
    expect(parsePnpmLock(pnpm)).toEqual([{ name: 'next', version: '16.2.3', dev: null }])
  })

  it('malformed JSON throws so the scan can report the file as unparseable', () => {
    expect(() => parseLockfile('package-lock.json', 'npm', '{nope')).toThrow()
    expect(() => parseLockfile('bun.lock', 'bun', '[')).toThrow()
  })
})
