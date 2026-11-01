import { readFile, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { runCli } from '../src/cli.js'
import { KEYS_FILE, KeyRing, bearer, matchKey, parseKeysFile, sha256 } from '../src/reports/keys.js'
import { DM_USER, fakeKey, keyLineFor, tempDir } from './hubHelpers.js'

const hashOf = (seed: string) => sha256(fakeKey(seed)).toString('hex')

describe('parseKeysFile', () => {
  it('reads sources, hashes and flags, and skips comments', () => {
    const text = [
      '# a comment',
      '',
      keyLineFor('web1', 'a'),
      `${keyLineFor('db1', 'b', 'page')}   # trailing comment`,
      keyLineFor('pc1', 'c', `dm=${DM_USER}`),
      `   ${hashOf('d').toUpperCase().replace(/^/, 'ci1 ')}`,
    ].join('\n')
    const { keys, refused } = parseKeysFile(text)
    expect(refused).toEqual([])
    expect(keys.map((k) => [k.source, k.page, k.dmUserId, k.line])).toEqual([
      ['web1', false, null, 3],
      ['db1', true, null, 4],
      ['pc1', false, DM_USER, 5],
      ['ci1', false, null, 6],
    ])
    expect(keys[3].hash.toString('hex')).toBe(hashOf('d'))
  })

  it('refuses a bad line by its line number, never trusting it', () => {
    const text = [
      keyLineFor('ok', 'ok'),
      keyLineFor('both', 'e', `page dm=${DM_USER}`),
      'short abc123',
      keyLineFor('Web1', 'f'),
      keyLineFor('odd', 'g', 'loud'),
      keyLineFor('pc2', 'h', 'dm=12345'),
      'lonely',
    ].join('\n')
    const { keys, refused } = parseKeysFile(text)
    expect(keys.map((k) => k.source)).toEqual(['ok'])
    expect(refused).toEqual([
      { line: 2, reason: 'page and dm= cannot be combined' },
      { line: 3, reason: 'the hash is not 64 hex characters (a SHA-256)' },
      { line: 4, reason: 'the source must be lowercase letters, digits or dashes (at most 40)' },
      { line: 5, reason: 'unknown flag (use page or dm=<Discord user id>)' },
      { line: 6, reason: 'dm= needs a Discord user ID (17 to 20 digits)' },
      { line: 7, reason: 'expected <source> <sha256> [page | dm=<id>]' },
    ])
  })

  it('refuses every line of a key listed twice', () => {
    const { keys, refused } = parseKeysFile([keyLineFor('web1', 'x'), keyLineFor('web2', 'y'), keyLineFor('web1', 'x', 'page')].join('\n'))
    expect(keys.map((k) => k.source)).toEqual(['web2'])
    expect(refused.map((r) => r.line)).toEqual([1, 3])
  })
})

describe('matching a key', () => {
  it('finds the key a bearer token belongs to, by its hash', () => {
    const { keys } = parseKeysFile([keyLineFor('web1', 'a'), keyLineFor('db1', 'b')].join('\n'))
    expect(matchKey(fakeKey('b'), keys)?.source).toBe('db1')
    expect(matchKey(fakeKey('nope'), keys)).toBeNull()
    // The hash itself is not a key.
    expect(matchKey(hashOf('a'), keys)).toBeNull()
  })

  it('reads only a well-formed Bearer header', () => {
    expect(bearer('Bearer abc')).toBe('abc')
    expect(bearer('bearer abc')).toBeNull()
    expect(bearer('Basic abc')).toBeNull()
    expect(bearer('Bearer a b')).toBeNull()
    expect(bearer(undefined)).toBeNull()
  })
})

describe('KeyRing', () => {
  it('reloads the file when it changes and logs refused lines by number only', async () => {
    const dir = await tempDir()
    const file = path.join(dir, KEYS_FILE)
    const logs: string[] = []
    const ring = new KeyRing(file, { log: (m) => logs.push(m), minCheckMs: 0 })
    expect(await ring.match(`Bearer ${fakeKey('a')}`)).toBeNull()
    expect(logs.some((l) => l.includes('No keys.txt'))).toBe(true)

    await writeFile(file, `${keyLineFor('web1', 'a')}\n${keyLineFor('pc1', 'b', `page dm=${DM_USER}`)}\n`)
    expect((await ring.match(`Bearer ${fakeKey('a')}`))?.source).toBe('web1')
    expect(await ring.match(`Bearer ${fakeKey('b')}`)).toBeNull()
    const refusal = logs.find((l) => l.includes('line 2'))!
    expect(refusal).toBe('keys.txt line 2: refused, page and dm= cannot be combined.')
    expect(logs.join('\n')).not.toContain(DM_USER)
    expect(logs.join('\n')).not.toContain(hashOf('b'))

    // Revoked: gone at the next check.
    await writeFile(file, '# nothing\n')
    expect(await ring.match(`Bearer ${fakeKey('a')}`)).toBeNull()
  })

  it('checks the file at most once per interval', async () => {
    const dir = await tempDir()
    const file = path.join(dir, KEYS_FILE)
    let now = 0
    const ring = new KeyRing(file, { now: () => now, minCheckMs: 1000 })
    await writeFile(file, `${keyLineFor('web1', 'a')}\n`)
    expect((await ring.current()).length).toBe(1)
    await writeFile(file, '')
    now = 500
    expect((await ring.current()).length).toBe(1)
    now = 1000
    expect((await ring.current()).length).toBe(0)
  })
})

describe('the key CLI', () => {
  async function cli(dir: string, ...argv: string[]) {
    const out: string[] = []
    const err: string[] = []
    const code = await runCli(argv, { out: (l) => out.push(l), err: (l) => err.push(l), env: { DATA_DIR: dir }, now: () => new Date('2025-02-27T00:00:00Z') })
    return { code, out, err }
  }

  it('key new prints the key once on stdout and stores only its hash', async () => {
    const dir = await tempDir()
    const r = await cli(dir, 'key', 'new', 'web1', '--page')
    expect(r.code).toBe(0)
    expect(r.out).toHaveLength(1)
    const key = r.out[0]
    expect(key).toMatch(/^[0-9a-f]{64}$/)
    const text = await readFile(path.join(dir, KEYS_FILE), 'utf8')
    expect(text).not.toContain(key)
    expect(text).toContain(`web1 ${sha256(key).toString('hex')} page # added 2025-02-27`)
    expect(r.err.join('\n')).not.toContain(key)
    const ring = new KeyRing(path.join(dir, KEYS_FILE), { minCheckMs: 0 })
    expect(await ring.match(`Bearer ${key}`)).toMatchObject({ source: 'web1', page: true })
    if (process.platform !== 'win32') expect((await stat(path.join(dir, KEYS_FILE))).mode & 0o777).toBe(0o600)
  })

  it('key add stores a hash made elsewhere, with dm=', async () => {
    const dir = await tempDir()
    expect((await cli(dir, 'key', 'add', 'pc1', hashOf('pc'), '--dm', DM_USER)).code).toBe(0)
    const ring = new KeyRing(path.join(dir, KEYS_FILE), { minCheckMs: 0 })
    expect(await ring.match(`Bearer ${fakeKey('pc')}`)).toMatchObject({ source: 'pc1', page: false, dmUserId: DM_USER })
    expect((await cli(dir, 'key', 'add', 'pc1', hashOf('pc'))).code).toBe(1)
  })

  it('refuses bad input with a usage error', async () => {
    const dir = await tempDir()
    expect((await cli(dir, 'key', 'new', 'web1', '--page', '--dm', DM_USER)).code).toBe(2)
    expect((await cli(dir, 'key', 'new', 'Web1')).code).toBe(2)
    expect((await cli(dir, 'key', 'new', 'web1', '--dm', '123')).code).toBe(2)
    expect((await cli(dir, 'key', 'add', 'web1', 'abc')).code).toBe(2)
    expect((await cli(dir, 'nope')).code).toBe(2)
    expect((await cli(dir, 'key', 'help')).code).toBe(0)
  })

  it('key list shows sources, flags and short hashes; key revoke removes them', async () => {
    const dir = await tempDir()
    await cli(dir, 'key', 'add', 'web1', hashOf('w1'))
    await cli(dir, 'key', 'add', 'web1', hashOf('w2'), '--page')
    await cli(dir, 'key', 'add', 'pc1', hashOf('p'), '--dm', DM_USER)
    const list = await cli(dir, 'key', 'list')
    expect(list.out).toEqual([`web1\t-\t${hashOf('w1').slice(0, 12)}`, `web1\tpage\t${hashOf('w2').slice(0, 12)}`, `pc1\tdm\t${hashOf('p').slice(0, 12)}`])
    expect(list.out.join('\n')).not.toContain(DM_USER)

    // One key of a source, by hash prefix.
    expect((await cli(dir, 'key', 'revoke', 'web1', hashOf('w1').slice(0, 8))).code).toBe(0)
    expect((await cli(dir, 'key', 'list')).out.map((l) => l.split('\t')[0])).toEqual(['web1', 'pc1'])
    // Every key of a source.
    expect((await cli(dir, 'key', 'revoke', 'web1')).code).toBe(0)
    expect((await cli(dir, 'key', 'revoke', 'web1')).code).toBe(1)
    expect((await cli(dir, 'key', 'list')).out.map((l) => l.split('\t')[0])).toEqual(['pc1'])
    expect(await readFile(path.join(dir, KEYS_FILE), 'utf8')).toMatch(/^# nethersec hub report keys/)
  })
})
