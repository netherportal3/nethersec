import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultWatchConfig, loadWatchConfig, parseWatchConfig, WatchConfigError } from '../../src/watch/index.js'

const EXAMPLE = fileURLToPath(new URL('../../src/watch/watch.example.json', import.meta.url))

let dir: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'watch-config-'))
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

function errorsOf(raw: unknown): string[] {
  try {
    parseWatchConfig(raw)
  } catch (e) {
    expect(e).toBeInstanceOf(WatchConfigError)
    return (e as WatchConfigError).errors
  }
  throw new Error('expected a WatchConfigError')
}

describe('loadWatchConfig', () => {
  it('a missing file gives the defaults: no components, kernel off, container check on, acknowledged advisory cards close after 90 days', () => {
    expect(loadWatchConfig(join(dir, 'watch.json'))).toEqual({
      components: [],
      kernel: null,
      containers: { enabled: true },
      advisoryCards: { closeAcknowledgedAfterDays: 90 },
    })
    expect(defaultWatchConfig()).toEqual(loadWatchConfig(join(dir, 'watch.json')))
  })

  it('takes the data directory or the file', () => {
    writeFileSync(join(dir, 'watch.json'), JSON.stringify({ containers: { enabled: false } }))
    expect(loadWatchConfig(dir).containers.enabled).toBe(false)
    expect(loadWatchConfig(join(dir, 'watch.json')).containers.enabled).toBe(false)
  })

  it('a file that is not JSON is an error, never the defaults', () => {
    writeFileSync(join(dir, 'watch.json'), '{ "components": [ }')
    expect(() => loadWatchConfig(dir)).toThrow(WatchConfigError)
    expect(() => loadWatchConfig(dir)).toThrow(/not valid JSON/)
  })

  it('reads a file saved with a byte order mark', () => {
    writeFileSync(join(dir, 'watch.json'), String.fromCharCode(0xfeff) + JSON.stringify({ kernel: { ubuntu: ['22.04'] } }))
    expect(loadWatchConfig(dir).kernel?.releases).toEqual([{ codename: 'jammy', name: 'Ubuntu 22.04' }])
  })

  it('the example file loads, with the KEV feed and patterns that compile', () => {
    const cfg = loadWatchConfig(EXAMPLE)
    expect(cfg.components.find((c) => c.feed?.kind === 'kev')?.id).toBe('kev')
    expect(cfg.components.length).toBeGreaterThan(10)
    expect(cfg.kernel?.releases).toEqual([{ codename: 'noble', name: 'Ubuntu 24.04' }])
    expect(cfg.containers.enabled).toBe(true)
    for (const c of cfg.components) {
      if (c.feed?.kind !== 'kev') expect(c.kev?.length, c.id).toBeGreaterThan(0)
      for (const m of c.kev ?? []) for (const re of [m.vendor, m.product]) if (re) expect(re.flags).toBe('i')
    }
    const openssh = cfg.components.find((c) => c.id === 'openssh')!
    expect(openssh.kev![0].product!.test('OpenSSH')).toBe(true)
  })
})

describe('parseWatchConfig', () => {
  it('reads every feed kind, with patterns compiled case-insensitive', () => {
    const cfg = parseWatchConfig({
      _note: 'ignored',
      components: [
        { id: 'kev', name: 'CISA KEV', feed: { kind: 'kev' } },
        { id: 'engine', name: 'Engine', runsOn: ' web1,  web2 ', feed: { kind: 'github', repo: 'example/engine' }, kev: [{ product: '^Engine$' }] },
        { id: 'bulletins', name: 'Bulletins', feed: { kind: 'rss', url: 'https://example.com/feed.xml', match: 'security' } },
        { id: 'ssh', name: 'SSH', kev: [{ vendor: '^Example', product: 'ssh' }] },
      ],
      kernel: { ubuntu: ['24.04', 'noble', '26.04', 'futurename'] },
    })
    expect(cfg.components.map((c) => [c.id, c.feed?.kind ?? null])).toEqual([
      ['kev', 'kev'],
      ['engine', 'github'],
      ['bulletins', 'rss'],
      ['ssh', null],
    ])
    expect(cfg.components[1].runsOn).toBe('web1, web2')
    const rss = cfg.components[2].feed
    expect(rss?.kind === 'rss' && rss.match?.test('SECURITY release')).toBe(true)
    expect(cfg.components[3].kev![0].vendor!.test('example corp')).toBe(true)
    expect(cfg.kernel?.releases).toEqual([
      { codename: 'noble', name: 'Ubuntu 24.04' },
      { codename: 'resolute', name: 'Ubuntu 26.04' },
      { codename: 'futurename', name: 'Ubuntu futurename' },
    ])
  })

  it('names every problem at once', () => {
    const errors = errorsOf({
      componets: [],
      components: [
        { id: 'Bad Id', name: 'x', feed: { kind: 'kev' } },
        { id: 'dup', name: 'One', feed: { kind: 'github', repo: 'not a repo' } },
        { id: 'dup', name: 'Two', feed: { kind: 'rss', url: 'http://example.com/feed.xml' } },
        { id: 'linux-kernel', name: 'Kernel', kev: [{ product: 'kernel' }] },
        { id: 'regex', name: 'Regex', kev: [{ product: '([' }] },
        { id: 'nothing', name: 'Nothing' },
        { id: 'kev2', name: 'Second KEV', feed: { kind: 'kev' }, kev: [{ product: 'x' }] },
        { id: 'kind', name: 'Kind', feed: { kind: 'atom', url: 'https://example.com' } },
        { id: 'empty', name: '', kev: [{}] },
        { id: 'typo', name: 'Typo', feed: { kind: 'github', repo: 'a/b' }, runson: 'web1' },
      ],
      kernel: { ubuntu: ['23.99'] },
      containers: { enabled: 'yes' },
    })
    const expected = [
      /^watch\.json: unknown key "componets"/,
      /components\[0\] \(Bad Id\)\.id: 1 to 40 lowercase/,
      /components\[1\] \(dup\)\.feed\.repo: must be "owner\/repo"/,
      /components\[2\] \(dup\)\.id: used twice/,
      /components\[2\] \(dup\)\.feed\.url: must be an https:\/\/ address/,
      /components\[3\] \(linux-kernel\)\.id: "linux-kernel" is the kernel feed's/,
      /components\[4\] \(regex\)\.kev\[0\]\.product: not a valid regular expression/,
      /components\[5\] \(nothing\): needs a "feed", "kev" names, or both/,
      /components\[6\] \(kev2\): the KEV feed reads the catalog/,
      /components\[7\] \(kind\)\.feed\.kind: must be "github", "rss" or "kev"/,
      /components\[8\] \(empty\)\.name: must not be empty/,
      /components\[8\] \(empty\)\.kev\[0\]: needs "vendor", "product" or both/,
      /components\[9\] \(typo\): unknown key "runson"/,
      /^components: only one component can have the "kev" feed/,
      /^kernel\.ubuntu\[0\]: not an Ubuntu release/,
      /^containers\.enabled: must be true or false/,
    ]
    for (const re of expected) expect(errors.some((e) => re.test(e)), `${re}\n${errors.join('\n')}`).toBe(true)
    expect(errors).toHaveLength(expected.length)
  })

  it('advisoryCards.closeAcknowledgedAfterDays: 0 turns it off, 7 to 3650 days, anything else is refused', () => {
    expect(parseWatchConfig({ advisoryCards: { closeAcknowledgedAfterDays: 0 } }).advisoryCards).toEqual({ closeAcknowledgedAfterDays: 0 })
    expect(parseWatchConfig({ advisoryCards: { closeAcknowledgedAfterDays: 7 } }).advisoryCards).toEqual({ closeAcknowledgedAfterDays: 7 })
    expect(parseWatchConfig({ advisoryCards: {} }).advisoryCards).toEqual({ closeAcknowledgedAfterDays: 90 })
    for (const bad of [1, 6, 3651, 30.5, '90', -1]) {
      expect(errorsOf({ advisoryCards: { closeAcknowledgedAfterDays: bad } })).toEqual([
        'advisoryCards.closeAcknowledgedAfterDays: must be 0 (never) or a whole number of days from 7 to 3650',
      ])
    }
    expect(errorsOf({ advisoryCards: true })[0]).toMatch(/^advisoryCards: must be an object/)
    expect(errorsOf({ advisoryCards: { closeAckedAfterDays: 30 } })[0]).toMatch(/^advisoryCards: unknown key "closeAckedAfterDays"/)
  })

  it('refuses what is not an object, and an empty kernel list', () => {
    expect(errorsOf([])).toEqual(['the file must hold one JSON object'])
    expect(errorsOf({ kernel: { ubuntu: [] } })[0]).toMatch(/kernel\.ubuntu: must list at least one/)
    expect(errorsOf({ components: {} })).toEqual(['components: must be a list'])
  })

  it('the error message lists the problems for the hub to show', () => {
    try {
      parseWatchConfig({ components: [{ id: 'a', name: 'A' }] })
    } catch (e) {
      expect((e as Error).message).toMatch(/^watch\.json has a problem:\n- components\[0\] \(a\): needs a "feed"/)
      return
    }
    throw new Error('expected an error')
  })
})
