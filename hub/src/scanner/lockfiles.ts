/**
 * Lockfile discovery and parsing.
 *
 * Everything here is PURE: text in, installed packages out. No I/O, no clock.
 *
 * Formats:
 *   - npm   package-lock.json / npm-shrinkwrap.json, v1 (nested `dependencies`)
 *           and v2/v3 (flat `packages` map, keyed by install path).
 *   - pnpm  pnpm-lock.yaml v5 (`/name/1.2.3`), v6 (`/name@1.2.3(peer@x)`) and
 *           v9 (`name@1.2.3` under `packages:`, peer suffixes under `snapshots:`).
 *           Read with a line-based scan of the package KEYS only; no YAML
 *           dependency.
 *   - bun   bun.lock (text, JSON with trailing commas). The binary bun.lockb is
 *           reported as unsupported.
 *   - yarn  yarn.lock, classic v1 and berry (v2+). Only registry entries are
 *           read: v1 a plain range, berry an `@npm:` resolution.
 *   - pip   requirements*.txt. Only exact `==` pins can be matched to an
 *           advisory; anything else is counted as "not checked", never guessed.
 *   - uv / poetry  uv.lock and poetry.lock (TOML), line by line: the
 *           `[[package]]` tables from a package index. Git, path and URL
 *           sources are skipped. Pipfile.lock and pdm.lock are unsupported.
 *
 * Versions that are not plain semver (git/file/link/workspace/tarball specs)
 * are skipped: no advisory database can match them anyway.
 *
 * Lockfiles come from repos other people can write to, and parsing is
 * synchronous, so every parser is linear in its input: string operations and
 * regexes without nested quantifiers, and a cap on the line length looked at.
 */
import semver from 'semver'

export type LockEcosystem = 'npm' | 'PyPI'

export type LockKind = 'npm' | 'pnpm' | 'bun' | 'yarn' | 'pip' | 'uv' | 'poetry' | 'unsupported'

export interface InstalledPackage {
  name: string
  version: string
  /**
   * true = dev-only in this lockfile, false = runtime, null = unknown. Unknown
   * is treated as runtime when deciding to ping. pnpm v9 and bun do not record
   * it: parseLockfile works it out from the dependency graph when the graph
   * reads in full. A requirements file is dev by its name. yarn and uv: null.
   */
  dev: boolean | null
}

export interface ParsedLockfile {
  path: string
  kind: Exclude<LockKind, 'unsupported'>
  ecosystem: LockEcosystem
  packages: InstalledPackage[]
  /** pip only: requirement lines without an exact `==` pin (not checked). */
  unpinned: number
}

/**
 * Lockfiles we recognize but cannot read. They are listed as "format not
 * supported" so a repo that only has these is visibly unchecked, never
 * silently clean.
 */
const UNSUPPORTED_LOCKFILES = new Set(['bun.lockb', 'Pipfile.lock', 'pdm.lock'])

/**
 * Longest line the text parsers look at. Real lockfile lines are far shorter;
 * anything longer is skipped (a guard for hostile or broken files).
 */
const MAX_LINE_CHARS = 8192

/** bun.lock scope: deepest key read (real installs nest a handful of levels). */
const MAX_BUN_KEY_DEPTH = 32
/** bun.lock scope: total characters of candidate keys built while resolving. */
const MAX_BUN_RESOLVE_CHARS = 20_000_000

/**
 * Split text into lines on ANY line ending, including a lone CR (old Mac style).
 * Linear. Keeping a lone CR inside a line would hide the rest of the file.
 */
export function splitLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/)
}

/**
 * Path segments that hold vendored or installed trees, or test fixtures, never
 * a lockfile the project ships with.
 */
const IGNORED_SEGMENTS = new Set([
  'node_modules',
  'venv',
  '.venv',
  'site-packages',
  'vendor',
  '__fixtures__',
  'fixtures',
  'testdata',
])

/** True when a repo path sits under an installed, vendored or fixture tree. */
export function isIgnoredLockfilePath(path: string): boolean {
  const parts = path.split('/')
  // The last segment is the file itself; only its directories can be ignored.
  for (let i = 0; i < parts.length - 1; i++) {
    if (IGNORED_SEGMENTS.has(parts[i])) return true
  }
  return false
}

/**
 * Classify a repo path as a lockfile we can read, one we recognize but cannot
 * read (reported as skipped), or not a lockfile at all (null).
 */
export function classifyLockfilePath(path: string): LockKind | null {
  const slash = path.lastIndexOf('/')
  const base = path.slice(slash + 1)
  const dir = slash >= 0 ? path.slice(0, slash) : ''
  const parent = dir.slice(dir.lastIndexOf('/') + 1)
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return 'npm'
  if (base === 'pnpm-lock.yaml') return 'pnpm'
  if (base === 'bun.lock') return 'bun'
  if (base === 'yarn.lock') return 'yarn'
  if (base === 'uv.lock') return 'uv'
  if (base === 'poetry.lock') return 'poetry'
  if (UNSUPPORTED_LOCKFILES.has(base)) return 'unsupported'
  if (/^requirements[^/]*\.txt$/i.test(base)) return 'pip'
  // The split layout: requirements/base.txt, requirements/prod.txt, ...
  if (parent.toLowerCase() === 'requirements' && /\.txt$/i.test(base)) return 'pip'
  return null
}

export interface TreeEntryLite {
  path: string
  type: string
  sha: string
  size?: number
}

export interface SelectedLockfile {
  path: string
  sha: string
  size: number
  kind: Exclude<LockKind, 'unsupported'>
}

export interface LockfileSelection {
  /** Lockfiles to download and parse, in path order. */
  selected: SelectedLockfile[]
  /** Lockfiles seen but not read, with a reason. */
  skipped: Array<{ path: string; reason: string }>
}

/**
 * Pick the lockfiles out of a GitHub recursive tree listing. Anything over the
 * byte cap or the per-repo count cap is SKIPPED with a reason, never silently
 * dropped.
 */
export function selectLockfiles(tree: TreeEntryLite[], opts: { maxFiles: number; maxBytes: number }): LockfileSelection {
  const candidates: SelectedLockfile[] = []
  const skipped: LockfileSelection['skipped'] = []
  const sorted = [...tree].sort((a, b) => a.path.localeCompare(b.path))
  for (const entry of sorted) {
    if (entry.type !== 'blob' || !entry.path || !entry.sha) continue
    const kind = classifyLockfilePath(entry.path)
    if (!kind) continue
    if (isIgnoredLockfilePath(entry.path)) continue
    if (kind === 'unsupported') {
      skipped.push({ path: entry.path, reason: 'format not supported' })
      continue
    }
    const size = Number(entry.size) || 0
    if (size > opts.maxBytes) {
      skipped.push({ path: entry.path, reason: 'too big' })
      continue
    }
    candidates.push({ path: entry.path, sha: entry.sha, size, kind })
  }
  const selected = candidates.slice(0, Math.max(0, opts.maxFiles))
  for (const extra of candidates.slice(Math.max(0, opts.maxFiles))) {
    skipped.push({ path: extra.path, reason: 'over the per-repo lockfile cap' })
  }
  return { selected, skipped }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** A version any advisory DB could match: plain semver (prereleases allowed). */
function isMatchableVersion(v: string): boolean {
  return semver.valid(v) !== null
}

/**
 * Collapse repeats of the same name@version. A package is dev-only only if EVERY
 * occurrence is dev-only; a single runtime (or unknown) occurrence makes it
 * runtime (or unknown), which is the safe direction for alerting.
 */
function dedupePackages(pkgs: InstalledPackage[]): InstalledPackage[] {
  const byKey = new Map<string, InstalledPackage>()
  for (const p of pkgs) {
    const key = `${p.name}@${p.version}`
    const prev = byKey.get(key)
    if (!prev) {
      byKey.set(key, { ...p })
      continue
    }
    if (prev.dev === true && p.dev === true) continue
    if (prev.dev === false || p.dev === false) prev.dev = false
    else prev.dev = null
  }
  return [...byKey.values()]
}

/** Split `name@version` at the version separator (scoped names start with '@'). */
function splitNameAtVersion(spec: string): { name: string; version: string } | null {
  const at = spec.lastIndexOf('@')
  if (at <= 0) return null
  const name = spec.slice(0, at)
  const version = spec.slice(at + 1)
  if (!name || !version) return null
  return { name, version }
}

/** A JSON object (not null, not an array). Lockfile JSON is untrusted, so every level is checked. */
function isPlainObject(v: unknown): v is Record<string, any> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Own property only: a key such as `constructor` must not reach Object.prototype. */
function own(obj: Record<string, any>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined
}

/**
 * Walk a dependency graph from its roots ([node, runtime]). A package
 * (`nameOf(node)`) reached from a runtime root is runtime (false); one reached
 * only from dev roots is dev-only (true); one not reached is left out
 * (unknown). undefined when an edge or root points at a node the graph does
 * not have: the walk would be partial, and a missed runtime edge would make a
 * runtime package look dev-only.
 */
function reachScope(
  roots: Array<[string, boolean]>,
  edges: Map<string, string[]>,
  nameOf: (node: string) => string | null,
): Map<string, boolean> | undefined {
  const reached = [new Set<string>(), new Set<string>()] // [runtime, dev]
  for (const pass of [0, 1]) {
    const seen = reached[pass]
    const stack = roots.filter(([, runtime]) => runtime === (pass === 0)).map(([node]) => node)
    while (stack.length) {
      const node = stack.pop() as string
      if (seen.has(node)) continue
      const next = edges.get(node)
      if (!next) return undefined
      seen.add(node)
      for (const n of next) stack.push(n)
    }
  }
  const out = new Map<string, boolean>()
  for (const pass of [0, 1]) {
    for (const node of reached[pass]) {
      const nv = nameOf(node)
      if (nv && !out.has(nv)) out.set(nv, pass === 1)
    }
  }
  return out
}

/** Fill the dev flags a format does not record from the graph's scope. */
function withScope(packages: InstalledPackage[], scope: Map<string, boolean> | undefined): InstalledPackage[] {
  if (!scope) return packages
  return packages.map((p) => {
    const dev = p.dev === null ? scope.get(`${p.name}@${p.version}`) : undefined
    return dev === undefined ? p : { ...p, dev }
  })
}

/** Remove one pair of surrounding YAML quotes. */
function unquoteYaml(v: string): string {
  if (v.length >= 2 && ((v[0] === "'" && v[v.length - 1] === "'") || (v[0] === '"' && v[v.length - 1] === '"'))) {
    return v.slice(1, -1)
  }
  return v
}

// ---------------------------------------------------------------------------
// npm: package-lock.json / npm-shrinkwrap.json
// ---------------------------------------------------------------------------

/** Parse a package-lock (v1, v2 or v3). Throws on malformed JSON. */
export function parsePackageLock(text: string): InstalledPackage[] {
  const lock = JSON.parse(text)
  const out: InstalledPackage[] = []

  if (isPlainObject(lock) && isPlainObject(lock.packages)) {
    // v2/v3: flat map keyed by install path, e.g. "node_modules/a/node_modules/@s/b".
    for (const [key, raw] of Object.entries<any>(lock.packages)) {
      if (!key || !isPlainObject(raw)) continue // "" is the root project
      if (raw.link === true) continue // workspace symlink; its target has its own entry
      const idx = key.lastIndexOf('node_modules/')
      // No node_modules/ in the key = a local workspace folder, not an installed package.
      if (idx < 0) continue
      // `name` is set when the install path differs from the real package (npm aliases).
      const name = typeof raw.name === 'string' && raw.name ? raw.name : key.slice(idx + 'node_modules/'.length)
      const version = typeof raw.version === 'string' ? raw.version : ''
      if (!name || !isMatchableVersion(version)) continue
      out.push({ name, version, dev: raw.dev === true })
    }
    return dedupePackages(out)
  }

  // v1: nested `dependencies` tree.
  const walk = (deps: unknown, depth: number) => {
    if (!isPlainObject(deps) || depth > 64) return
    for (const [name, raw] of Object.entries<any>(deps)) {
      if (!isPlainObject(raw)) continue
      let pkgName = name
      let version = typeof raw.version === 'string' ? raw.version : ''
      // npm alias in v1: "version": "npm:real-name@1.2.3".
      if (version.startsWith('npm:')) {
        const parsed = splitNameAtVersion(version.slice(4))
        if (parsed) {
          pkgName = parsed.name
          version = parsed.version
        }
      }
      if (isMatchableVersion(version)) out.push({ name: pkgName, version, dev: raw.dev === true })
      walk(raw.dependencies, depth + 1)
    }
  }
  walk(isPlainObject(lock) ? lock.dependencies : undefined, 0)
  return dedupePackages(out)
}

// ---------------------------------------------------------------------------
// pnpm: pnpm-lock.yaml v5 / v6 / v9
// ---------------------------------------------------------------------------

/** Read the major lockfile version (5, 6, 9, ...) from the header line. */
export function pnpmLockMajor(text: string): number | null {
  return pnpmHeaderMajor(splitLines(text))
}

function pnpmHeaderMajor(lines: string[]): number | null {
  // Line-based and regex-light on purpose: the header is one short line.
  for (const line of lines) {
    if (!line.startsWith('lockfileVersion:')) continue
    if (line.length > 64) return null
    const v = unquoteYaml(line.slice('lockfileVersion:'.length).trim())
    const m = v.match(/^(\d+)(?:\.\d+)?$/)
    return m ? Number(m[1]) : null
  }
  return null
}

/** Turn one pnpm package KEY into name + version, or null if not a registry package. */
export function parsePnpmKey(rawKey: string, major: number): { name: string; version: string } | null {
  let key = unquoteYaml(rawKey.trim())
  if (major < 9) {
    // v5/v6 registry keys are absolute: "/name/1.2.3" or "/name@1.2.3".
    // Anything else (github.com/..., file:..., link:...) is not a registry package.
    if (!key.startsWith('/')) return null
    key = key.slice(1)
  }
  // Drop the peer-dependency suffix: v6/v9 "(peer@1.0.0)(other@2)", v5 "_peer@1.0.0".
  const paren = key.indexOf('(')
  if (paren >= 0) key = key.slice(0, paren)

  let name: string
  let version: string
  if (major < 6) {
    // v5: "@scope/name/1.2.3" or "name/1.2.3", optionally "_peer@x+other@y".
    const slash = key.lastIndexOf('/')
    if (slash <= 0) return null
    name = key.slice(0, slash)
    version = key.slice(slash + 1)
    const underscore = version.indexOf('_')
    if (underscore >= 0) version = version.slice(0, underscore)
  } else {
    const parsed = splitNameAtVersion(key)
    if (!parsed) return null
    name = parsed.name
    version = parsed.version
  }
  if (!name || !isMatchableVersion(version)) return null
  return { name, version }
}

/** `key:` or `key: {}` -> `key`; anything else -> null. Plain string ops. */
function stripTrailingMapKey(line: string): string | null {
  let t = line.trimEnd()
  if (t.endsWith('{}')) t = t.slice(0, -2).trimEnd()
  if (!t.endsWith(':')) return null
  return t.slice(0, -1)
}

/**
 * Split a YAML mapping line into key and value, reading from `start` (the end
 * of the indent). An unquoted key ends at the first ':' followed by a space or
 * the end of the line; a quoted key ('@types/react' or "x") ends at its closing
 * quote, which must be followed by ':'. Plain string ops, linear in the line.
 */
function splitYamlKey(line: string, start: number): { key: string; value: string } | null {
  let key: string
  let colon: number
  const quote = line[start]
  if (quote === "'" || quote === '"') {
    const close = line.indexOf(quote, start + 1)
    if (close < 0 || line[close + 1] !== ':') return null
    key = line.slice(start + 1, close)
    colon = close + 1
  } else {
    colon = line.indexOf(':', start)
    while (colon >= 0 && colon + 1 < line.length && line[colon + 1] !== ' ') colon = line.indexOf(':', colon + 1)
    if (colon < 0) return null
    key = line.slice(start, colon)
  }
  if (!key || (colon + 1 < line.length && line[colon + 1] !== ' ')) return null
  return { key, value: line.slice(colon + 1).trim() }
}

/**
 * Parse a pnpm-lock.yaml by scanning package keys. Throws when the header is
 * missing (not a pnpm lockfile we understand). Dev flags: v5/v6 record them;
 * v9 does not, so use parseLockfile to get them from the dependency graph.
 */
export function parsePnpmLock(text: string): InstalledPackage[] {
  const lines = splitLines(text)
  const major = pnpmHeaderMajor(lines)
  if (major === null) throw new Error('pnpm lockfile has no lockfileVersion')
  return scanPnpmPackages(lines, major)
}

/** Installed packages from the 2-space keys of the `packages:` / `snapshots:` blocks. */
function scanPnpmPackages(lines: string[], major: number): InstalledPackage[] {
  const out: InstalledPackage[] = []
  let section: 'packages' | 'snapshots' | null = null
  let current: InstalledPackage | null = null

  for (const line of lines) {
    if (line === '' || line.trimStart().startsWith('#')) continue
    // A column-0 line opens (or closes) a top-level block.
    if (line[0] !== ' ') {
      current = null
      const top = stripTrailingMapKey(line)
      section = top === 'packages' ? 'packages' : top === 'snapshots' ? 'snapshots' : null
      continue
    }
    if (!section || line.length > MAX_LINE_CHARS) continue
    // Package key: exactly two spaces of indent, ends with ':' (or ': {}').
    if (line[1] === ' ' && line.length > 2 && line[2] !== ' ') {
      const key = stripTrailingMapKey(line.slice(2))
      if (key !== null) {
        const parsed = parsePnpmKey(key, major)
        if (parsed) {
          current = { name: parsed.name, version: parsed.version, dev: null }
          out.push(current)
        } else {
          current = null
        }
        continue
      }
    }
    // v5/v6 carry `dev: true|false` on the package entry (4-space indent).
    if (current && section === 'packages' && major < 9 && line.startsWith('    dev:')) {
      const v = line.slice('    dev:'.length).trim()
      if (v === 'true' || v === 'false') current.dev = v === 'true'
    }
  }
  return dedupePackages(out)
}

/**
 * Who reaches each package of a v9 lockfile: the importers' dependencies and
 * optionalDependencies (runtime) and devDependencies (dev), followed through
 * the `snapshots:` dependency lists (reachScope). undefined when a line cannot
 * be read: a missed runtime edge would make a runtime package look dev-only.
 */
function scanPnpmScope(lines: string[]): Map<string, boolean> | undefined {
  const edges = new Map<string, string[]>()
  const roots: Array<[string, boolean]> = []
  let top: string | null = null
  let block: string | null = null
  let current: string[] | null = null
  let dep: string | null = null
  for (const line of lines) {
    if (line === '' || line.trimStart().startsWith('#')) continue
    let indent = 0
    while (indent < line.length && line[indent] === ' ') indent++
    if (dep !== null && indent <= 6) return undefined // a declaration without its version
    if (indent === 0) {
      const key = stripTrailingMapKey(line)
      top = key === 'importers' || key === 'snapshots' ? key : null
      block = current = null
      continue
    }
    if (!top) continue
    if (indent % 2 === 1) return undefined
    if (indent === 2) block = null
    if (indent === 2 && top === 'importers') continue
    const inDeps =
      block === 'dependencies' || block === 'optionalDependencies' || (top === 'importers' && block === 'devDependencies')
    // Only the lines that make an edge or a root; the rest (resolution, transitivePeerDependencies, ...) are skipped.
    if (indent > 4 && !(inDeps && (indent === 6 || (top === 'importers' && indent === 8)))) continue
    const kv = line.length > MAX_LINE_CHARS ? null : splitYamlKey(line, indent)
    if (!kv) return undefined
    if (indent === 2) edges.set(unquoteYaml(kv.key), (current = []))
    else if (indent === 4) block = kv.value === '' ? kv.key : null
    else if (top === 'snapshots') {
      const to = pnpmNodeKey(kv.key, unquoteYaml(kv.value))
      if (to && current) current.push(to)
    } else if (indent === 6) dep = kv.key
    else if (dep !== null && kv.key === 'version') {
      const to = pnpmNodeKey(dep, unquoteYaml(kv.value))
      if (to) roots.push([to, block !== 'devDependencies'])
      dep = null
    }
  }
  if (dep !== null) return undefined
  return reachScope(roots, edges, (key) => {
    const p = parsePnpmKey(key, 9)
    return p ? `${p.name}@${p.version}` : null
  })
}

/**
 * A v9 dependency value -> its snapshot key: `dep@1.2.3(peer@1)`, or the value
 * itself for an alias (`real@1.2.3`). null for a workspace `link:` (that
 * importer's own blocks are roots already).
 */
function pnpmNodeKey(name: string, value: string): string | null {
  if (value.startsWith('link:')) return null
  const paren = value.indexOf('(')
  return (paren >= 0 ? value.slice(0, paren) : value).lastIndexOf('@') > 0 ? value : `${name}@${value}`
}

function parsePnpmWithScope(text: string): InstalledPackage[] {
  const lines = splitLines(text)
  const major = pnpmHeaderMajor(lines)
  if (major === null) throw new Error('pnpm lockfile has no lockfileVersion')
  const packages = scanPnpmPackages(lines, major)
  if (major < 9) return packages
  let scope: Map<string, boolean> | undefined
  try {
    scope = scanPnpmScope(lines)
  } catch {
    // Scope unknown: the packages keep dev null (runtime).
  }
  return withScope(packages, scope)
}

// ---------------------------------------------------------------------------
// bun: bun.lock
// ---------------------------------------------------------------------------

/**
 * Strip `//` and `/* *\/` comments and trailing commas from JSONC, leaving
 * strings alone, so JSON.parse can read a bun.lock.
 */
export function stripJsonc(text: string): string {
  let out = ''
  let inString = false
  let i = 0
  while (i < text.length) {
    const ch = text[i]
    if (inString) {
      out += ch
      if (ch === '\\' && i + 1 < text.length) {
        out += text[i + 1]
        i += 2
        continue
      }
      if (ch === '"') inString = false
      i++
      continue
    }
    if (ch === '"') {
      inString = true
      out += ch
      i++
      continue
    }
    if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++
      continue
    }
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? text.length : end + 2
      continue
    }
    if (ch === ',') {
      // Drop a trailing comma: the next significant character closes the container.
      let j = i + 1
      while (j < text.length && /\s/.test(text[j])) j++
      if (text[j] === '}' || text[j] === ']') {
        i++
        continue
      }
    }
    out += ch
    i++
  }
  return out
}

/** Parse a text bun.lock. Throws on malformed input. */
export function parseBunLock(text: string): InstalledPackage[] {
  return bunPackages(JSON.parse(stripJsonc(text)))
}

/** The installed packages of an already-parsed bun.lock. */
function bunPackages(lock: unknown): InstalledPackage[] {
  const out: InstalledPackage[] = []
  const packages = isPlainObject(lock) ? lock.packages : undefined
  if (!isPlainObject(packages)) return out
  for (const entry of Object.values<any>(packages)) {
    // Each entry is ["name@version", registry, { deps }, integrity]. Nested keys
    // ("parent/child") still carry the real name@version in element 0.
    if (!Array.isArray(entry) || typeof entry[0] !== 'string') continue
    const parsed = splitNameAtVersion(entry[0])
    if (!parsed || !isMatchableVersion(parsed.version)) continue
    out.push({ name: parsed.name, version: parsed.version, dev: null })
  }
  return dedupePackages(out)
}

/** A bun.lock packages key (`a/@s/b/c`) -> its package names (`a`, `@s/b`, `c`), or null. */
function bunKeyNames(key: string): string[] | null {
  const segs = key.split('/')
  const names: string[] = []
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i]
    if (!seg) return null
    if (seg[0] === '@') {
      if (i + 1 >= segs.length || !segs[i + 1]) return null
      names.push(`${seg}/${segs[i + 1]}`)
      i++
    } else {
      names.push(seg)
    }
  }
  return names.length ? names : null
}

/**
 * Who reaches each package of a bun.lock (reachScope). A dependency of the
 * package at key `a/b` resolves like node_modules: `a/b/<dep>`, then
 * `a/<dep>`, then `<dep>`; a workspace member's from `<member name>/<dep>`.
 * Workspace dependencies and devDependencies are the roots. A peer that
 * resolves nowhere is skipped (optional peers); any other unresolved
 * dependency makes the scope unknown.
 */
function bunScope(lock: unknown): Map<string, boolean> | undefined {
  if (!isPlainObject(lock)) return undefined
  const pkgs = lock.packages
  const workspaces = lock.workspaces
  if (!isPlainObject(pkgs) || !isPlainObject(workspaces)) return undefined
  // Resolving walks up the key, so its cost grows with depth: a hostile file
  // with very deep keys would block the process. Past either cap the scope is
  // just unknown.
  let budget = MAX_BUN_RESOLVE_CHARS
  let overBudget = false
  const resolve = (from: string[], dep: string): string | null => {
    for (let i = from.length; i >= 0; i--) {
      const key = i === 0 ? dep : `${from.slice(0, i).join('/')}/${dep}`
      budget -= key.length
      if (budget < 0) {
        overBudget = true
        return null
      }
      if (Array.isArray(own(pkgs, key))) return key
    }
    return null
  }
  const edges = new Map<string, string[]>()
  const roots: Array<[string, boolean]> = []
  // Returns false when a non-peer dependency resolves nowhere.
  const link = (from: string[], info: unknown, add: (key: string, field: string) => void): boolean => {
    if (!isPlainObject(info)) return true
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies']) {
      const deps = info[field]
      if (!isPlainObject(deps)) continue
      for (const name of Object.keys(deps)) {
        const key = resolve(from, name)
        if (key) add(key, field)
        else if (field !== 'peerDependencies') return false
      }
    }
    return true
  }
  for (const wsKey of Object.keys(workspaces)) {
    const ws = workspaces[wsKey]
    const from = wsKey !== '' && isPlainObject(ws) && typeof ws.name === 'string' && ws.name ? [ws.name] : []
    if (!link(from, ws, (key, field) => roots.push([key, field !== 'devDependencies']))) return undefined
    if (overBudget) return undefined
  }
  for (const key of Object.keys(pkgs)) {
    const entry = pkgs[key]
    const names = Array.isArray(entry) ? bunKeyNames(key) : null
    if (!names || names.length > MAX_BUN_KEY_DEPTH) return undefined
    const next: string[] = []
    // A workspace entry's own dependencies are roots already (its workspaces block).
    const info =
      typeof entry[0] === 'string' && entry[0].includes('@workspace:') ? null : entry.slice(1).find(isPlainObject)
    if (!link(names, info, (k, field) => field !== 'devDependencies' && next.push(k))) return undefined
    if (overBudget) return undefined
    edges.set(key, next)
  }
  return reachScope(roots, edges, (key) => {
    const entry = pkgs[key]
    const p = typeof entry[0] === 'string' ? splitNameAtVersion(entry[0]) : null
    return p && isMatchableVersion(p.version) ? `${p.name}@${p.version}` : null
  })
}

function parseBunWithScope(text: string): InstalledPackage[] {
  const lock = JSON.parse(stripJsonc(text))
  const packages = bunPackages(lock)
  let scope: Map<string, boolean> | undefined
  try {
    scope = bunScope(lock)
  } catch {
    // Scope unknown: the packages keep dev null (runtime).
  }
  return withScope(packages, scope)
}

// ---------------------------------------------------------------------------
// yarn: yarn.lock (classic v1 and berry)
// ---------------------------------------------------------------------------

/**
 * The package a yarn v1 descriptor (`name@range`, unquoted) installs, or null
 * when the range is not a registry range (git, file, link, a tarball URL,
 * GitHub shorthand). An alias `x@npm:real@^1` installs `real`.
 */
function yarnV1Name(descriptor: string): string | null {
  const at = descriptor.indexOf('@', 1)
  if (at <= 0) return null
  const range = descriptor.slice(at + 1)
  if (range.startsWith('npm:')) return splitNameAtVersion(range.slice(4))?.name ?? (range.slice(4) || null)
  return range.includes(':') || range.includes('/') ? null : descriptor.slice(0, at)
}

/** Parse a yarn.lock (v1 or berry). Throws when it is neither. */
export function parseYarnLock(text: string): InstalledPackage[] {
  const lines = splitLines(text)
  const out: InstalledPackage[] = []
  if (lines.includes('__metadata:')) {
    // Berry: `  resolution: "name@npm:1.2.3"`. workspace:, patch:, git and file
    // resolutions are not registry packages (a patch: entry's base has its own npm: entry).
    for (const line of lines) {
      if (!line.startsWith('  resolution: ') || line.length > MAX_LINE_CHARS) continue
      const res = unquoteYaml(line.slice('  resolution: '.length).trim())
      const i = res.lastIndexOf('@npm:')
      if (i > 0 && isMatchableVersion(res.slice(i + 5))) out.push({ name: res.slice(0, i), version: res.slice(i + 5), dev: null })
    }
    return dedupePackages(out)
  }
  if (!lines.some((l) => l.startsWith('# yarn lockfile v1'))) throw new Error('not a yarn lockfile')
  // v1: a column-0 header `"a@^1", a@^1.2:` (the first descriptor names the package), then `  version "1.2.3"`.
  let name: string | null = null
  for (const line of lines) {
    if (line === '' || line[0] === '#' || line.length > MAX_LINE_CHARS) continue
    if (line[0] !== ' ') {
      const first = line.endsWith(':') ? line.slice(0, -1).split(',')[0].trim() : ''
      name = first ? yarnV1Name(unquoteYaml(first)) : null
    } else if (name && line.startsWith('  version ')) {
      const version = unquoteYaml(line.slice('  version '.length).trim())
      if (isMatchableVersion(version)) out.push({ name, version, dev: null })
      name = null
    }
  }
  return dedupePackages(out)
}

// ---------------------------------------------------------------------------
// uv.lock and poetry.lock (TOML)
// ---------------------------------------------------------------------------

/** A PyPI version as a lockfile writes it (PEP 440 characters only). */
const PY_LOCK_VERSION_RE = /^[0-9][0-9A-Za-z.+!_-]{0,63}$/

/** Dependency groups that never ship (poetry groups, requirements file names). */
const DEV_GROUP_RE = /^(?:dev|test|tests|testing|lint|docs|typing|ci)$/i

/** `key = "value"` at column 0 -> value, else null. Plain strings only (no escapes). */
function tomlString(line: string, key: string): string | null {
  if (!line.startsWith(`${key} = "`) || !line.endsWith('"')) return null
  const v = line.slice(key.length + 4, -1)
  return v.includes('"') || v.includes('\\') ? null : v
}

/**
 * Parse a uv.lock or poetry.lock from its `[[package]]` tables. Kept: uv
 * `source = { registry = ... }`; poetry without a `[package.source]`, or with
 * a `legacy` (package index) one. Dev-only: poetry 1.x `category = "dev"`,
 * or poetry 2 `groups` that are all dev groups; uv does not say (null).
 * Throws when the text has no package table and no `[metadata]`.
 */
export function parsePythonLock(text: string, kind: 'uv' | 'poetry'): InstalledPackage[] {
  const out: InstalledPackage[] = []
  type Cur = { name?: string; version?: string; registry: boolean; dev: boolean | null }
  let cur: Cur | null = null
  let table: 'package' | 'source' | 'other' = 'other'
  let seen = false
  const flush = () => {
    if (cur?.name && cur.version && cur.registry && PY_LOCK_VERSION_RE.test(cur.version)) {
      out.push({ name: normalizePypiName(cur.name), version: cur.version, dev: cur.dev })
    }
    cur = null
  }
  for (const raw of splitLines(text)) {
    if (raw.length > MAX_LINE_CHARS) continue
    const line = raw.trimEnd()
    if (line.startsWith('[')) {
      if (line === '[[package]]' || line === '[metadata]') seen = true
      if (line === '[[package]]') {
        flush()
        cur = { registry: kind === 'poetry', dev: null }
        table = 'package'
      } else if (cur && line === '[package.source]') table = 'source'
      else if (cur && (line.startsWith('[package.') || line.startsWith('[[package.'))) table = 'other'
      else {
        flush()
        table = 'other'
      }
      continue
    }
    if (!cur || table === 'other') continue
    const c: Cur = cur
    if (table === 'source') {
      const type = tomlString(line, 'type')
      if (type !== null) c.registry = type === 'legacy'
      continue
    }
    c.name = tomlString(line, 'name') ?? c.name
    c.version = tomlString(line, 'version') ?? c.version
    if (kind === 'uv' && line.startsWith('source = ')) c.registry = line.startsWith('source = { registry = "')
    if (kind === 'poetry') {
      const category = tomlString(line, 'category')
      if (category !== null) c.dev = category === 'dev'
      if (line.startsWith('groups = [') && line.endsWith(']')) {
        const groups = line
          .slice('groups = ['.length, -1)
          .split(',')
          .map((g) => unquoteYaml(g.trim()))
          .filter(Boolean)
        c.dev = groups.length > 0 && groups.every((g) => DEV_GROUP_RE.test(g))
      }
    }
  }
  flush()
  if (!seen) throw new Error(`not a ${kind} lockfile`)
  return dedupePackages(out)
}

// ---------------------------------------------------------------------------
// pip: requirements*.txt
// ---------------------------------------------------------------------------

/** PEP 503 name normalization, so `Flask_SQLAlchemy` and `flask-sqlalchemy` match. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-')
}

/** Cut a `#` comment: one at line start or after whitespace (not a URL fragment). */
function stripRequirementComment(line: string): string {
  for (let i = line.indexOf('#'); i >= 0; i = line.indexOf('#', i + 1)) {
    if (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t') return line.slice(0, i)
  }
  return line
}

const NAME_START = /[A-Za-z0-9]/
const NAME_CHAR = /[A-Za-z0-9._-]/

/**
 * `name [extras] spec` -> { name, spec }. One left-to-right pass: read the
 * name, skip blanks, skip an optional `[extras]`, and the rest is the spec.
 */
function splitRequirement(line: string): { name: string; spec: string } | null {
  if (!NAME_START.test(line[0] || '')) return null
  let i = 1
  while (i < line.length && NAME_CHAR.test(line[i])) i++
  const name = line.slice(0, i)
  while (line[i] === ' ' || line[i] === '\t') i++
  if (line[i] === '[') {
    const close = line.indexOf(']', i)
    if (close >= 0) i = close + 1
  }
  return { name, spec: line.slice(i).trim() }
}

/**
 * Read one (continuation-joined) requirements line: an exact pin (name as
 * written), 'unpinned' (a requirement we cannot match, or a line too long to
 * read), or null (blank, comment, option, URL, VCS).
 */
function readRequirementLine(rawLine: string): { name: string; version: string } | 'unpinned' | null {
  if (rawLine.length > MAX_LINE_CHARS) return 'unpinned'
  let line = stripRequirementComment(rawLine).trim()
  if (!line) return null
  if (line.startsWith('-')) return null // -r / -c / -e / --index-url / --hash etc.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(line) || /^(git|hg|svn|bzr)\+/i.test(line)) return null
  // Environment markers and per-line options (e.g. --hash) do not change the pin.
  line = line
    .split(';')[0]
    .split(/[ \t]+/)
    .filter((tok, i) => i === 0 || !tok.startsWith('--'))
    .join(' ')
    .trim()
  if (!line) return null
  if (line.includes(' @ ')) return null // PEP 508 direct URL reference
  const req = splitRequirement(line)
  if (!req) return null
  const pin = req.spec.match(/^===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$/)
  if (pin && !pin[1].includes('*')) return { name: req.name, version: pin[1] }
  return 'unpinned'
}

/**
 * Parse requirements text. Exact `==` pins become packages; any other
 * requirement line counts toward `unpinned`. Options (`-r`, `-e`, `--index-url`),
 * URLs and VCS lines are neither.
 */
export function parseRequirements(text: string): { packages: InstalledPackage[]; unpinned: number } {
  const out: InstalledPackage[] = []
  let unpinned = 0
  // Join backslash line continuations first (any line ending).
  const joined = text.replace(/\\(?:\r\n|\r|\n)/g, ' ')
  for (const rawLine of splitLines(joined)) {
    const read = readRequirementLine(rawLine)
    if (read === 'unpinned') unpinned++
    else if (read) out.push({ name: normalizePypiName(read.name), version: read.version, dev: null })
  }
  // Same name@version twice is one install.
  const seen = new Set<string>()
  const packages = out.filter((p) => {
    const k = `${p.name}@${p.version}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  return { packages, unpinned }
}

/**
 * A requirements file for development only, by its name: a `dev`, `test`,
 * `lint`, `docs`, `typing` or `ci` part (`requirements-dev.txt`,
 * `requirements/test.txt`). Any other requirements file is runtime.
 */
export function isDevRequirementsPath(path: string): boolean {
  const parts = path.split('/')
  const base = parts[parts.length - 1].replace(/\.txt$/i, '')
  const words =
    (parts[parts.length - 2] ?? '').toLowerCase() === 'requirements' ? base.split(/[-_.]/) : base.split(/[-_.]/).slice(1)
  return words.some((w) => DEV_GROUP_RE.test(w))
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/** Parse one downloaded lockfile by kind. Throws on malformed input. */
export function parseLockfile(path: string, kind: Exclude<LockKind, 'unsupported'>, text: string): ParsedLockfile {
  switch (kind) {
    case 'pip': {
      const { packages, unpinned } = parseRequirements(text)
      const dev = isDevRequirementsPath(path)
      return { path, kind, ecosystem: 'PyPI', packages: packages.map((p) => ({ ...p, dev })), unpinned }
    }
    case 'uv':
    case 'poetry':
      return { path, kind, ecosystem: 'PyPI', packages: parsePythonLock(text, kind), unpinned: 0 }
    case 'yarn':
      return { path, kind, ecosystem: 'npm', packages: parseYarnLock(text), unpinned: 0 }
    case 'pnpm':
      return { path, kind, ecosystem: 'npm', packages: parsePnpmWithScope(text), unpinned: 0 }
    case 'bun':
      return { path, kind, ecosystem: 'npm', packages: parseBunWithScope(text), unpinned: 0 }
    case 'npm':
      return { path, kind, ecosystem: 'npm', packages: parsePackageLock(text), unpinned: 0 }
  }
}
