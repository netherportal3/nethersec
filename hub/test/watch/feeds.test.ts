import vm from 'node:vm'
import { describe, expect, it } from 'vitest'
import {
  cardsAdvisory,
  extractFixedIn,
  groupAdvisoriesByFix,
  kevInventory,
  kevMatches,
  parseGithubAdvisories,
  parseKevCatalog,
  parseRssAdvisories,
  plainText,
  type Advisory,
} from '../../src/watch/feeds.js'
import { WATCH_ID_RE } from '../../src/cards/ops.js'
import { advisoryCardKey } from '../../src/watch/advisories.js'
import { parseWatchConfig } from '../../src/watch/config.js'
import { cardId } from '../../src/watch/util.js'
import { ghAdvisory as gh, kevEntry, rss, rssItem } from './fixtures.js'

const NOW = Date.parse('2025-03-24T12:00:00Z')

describe('RSS', () => {
  it('reads an item: id, summary, fixed version and date', () => {
    const xml = rss(rssItem('EX-0002', Date.parse('2025-03-19T00:00:00Z'), 'A crafted request can crash the server', 'Example v2.3.1 or later fixes it.'))
    const [item] = parseRssAdvisories(xml, 'Example')!
    expect(item).toEqual({
      id: 'https://example.com/bulletins/#ex-0002',
      title: 'EX-0002',
      summary: 'A crafted request can crash the server',
      url: 'https://example.com/bulletins/#ex-0002',
      published: Date.parse('2025-03-19T00:00:00Z'),
      severity: null,
      fixedIn: 'Example 2.3.1',
    })
  })

  it('reads CDATA, keeps a plain http link out of the card, and refuses what is not RSS', () => {
    const xml = `<rss><channel><item><title>X-1</title><link>http://example.com/x-1</link><guid>x-1</guid><description><![CDATA[<p>Plain summary</p>]]></description></item></channel></rss>`
    expect(parseRssAdvisories(xml, 'X')![0]).toMatchObject({ id: 'x-1', summary: 'Plain summary', url: '', published: null })
    expect(parseRssAdvisories('<html><body>moved</body></html>', 'X')).toBeNull()
    expect(parseRssAdvisories('<feed xmlns="http://www.w3.org/2005/Atom"></feed>', 'X')).toBeNull()
  })

  it('with a match, cards only items whose title or a category matches', () => {
    const xml = rss(
      rssItem('Example 4.2 Released!', NOW, 'An update release.', ''),
      rssItem('Example 5 Beta 1', NOW, 'A beta.', ''),
      rssItem('Bulletin 12', NOW, 'Another product.', '', ['product-b']),
      rssItem('Bulletin 11', NOW, 'Our product.', '', ['Product-A']),
    )
    const items = parseRssAdvisories(xml, 'Example', /\bExample\s+\d+\.\d+\b.*\breleased\b|^product-a$/i)!
    expect(items.map((a) => [a.title, cardsAdvisory(a)])).toEqual([
      ['Example 4.2 Released!', true],
      ['Example 5 Beta 1', false],
      ['Bulletin 12', false],
      ['Bulletin 11', true],
    ])
  })

  it('names the fixed version the way the bulletin does', () => {
    expect(extractFixedIn('This is fixed in Example version 2.2.9 or newer.', 'Example')).toBe('Example 2.2.9')
    expect(extractFixedIn('Update to libexample 0.2.0 or newer.', 'Example')).toBe('libexample 0.2.0')
    expect(extractFixedIn('Please upgrade to version 2.1 or later.', 'Engine')).toBe('Engine 2.1')
    expect(extractFixedIn('No fix yet.', 'Engine')).toBeNull()
  })

  it('hashes a very long item id so the state stays small', () => {
    const long = 'x'.repeat(500)
    const xml = `<rss><channel><item><title>T</title><guid>${long}</guid></item></channel></rss>`
    expect(parseRssAdvisories(xml, 'X')![0].id).toMatch(/^sha256:[0-9a-f]{64}$/)
  })
})

describe('hostile RSS near the 2 MiB feed cap', () => {
  /** Just under the cap the advisory watch reads a feed up to. */
  const FILL = 2 * 1024 * 1024 - 1024
  /** Each parse should take milliseconds. The bound is generous so a slow CI box does not flake. */
  const BOUND_MS = 1000

  /**
   * Runs `fn` with a hard stop, so a pattern that would run for hours fails the
   * test after a few seconds instead of hanging it. Returns how long it took.
   */
  function timed<T>(fn: () => T): { ms: number; value: T } {
    const t0 = performance.now()
    const value = vm.runInNewContext('fn()', { fn }, { timeout: 5_000 }) as T
    return { ms: performance.now() - t0, value }
  }

  const item = (title: string, description: string) =>
    `<rss><channel><item><title>${title}</title><guid>x-1</guid><description><![CDATA[${description}]]></description></item></channel></rss>`

  it('a description that is one long run of "<"', () => {
    expect(timed(() => plainText('<'.repeat(FILL))).ms).toBeLessThan(BOUND_MS)
    const { ms, value } = timed(() => parseRssAdvisories(item('X-1', '<'.repeat(FILL)), 'X'))
    expect(ms).toBeLessThan(BOUND_MS)
    expect(value).toHaveLength(1)
    expect(value![0].summary.length).toBeLessThanOrEqual(300)
  })

  it('a title that is one long run of "<"', () => {
    const xml = `<rss><channel><item><title>${'<'.repeat(FILL)}</title><guid>x-1</guid></item></channel></rss>`
    const { ms } = timed(() => parseRssAdvisories(xml, 'X'))
    expect(ms).toBeLessThan(BOUND_MS)
  })

  it('item tags that never close', () => {
    const xml = `<rss><channel>${'<item>'.repeat(FILL / 6)}</channel></rss>`
    const { ms, value } = timed(() => parseRssAdvisories(xml, 'X'))
    expect(ms).toBeLessThan(BOUND_MS)
    expect(value).toEqual([])
  })

  it('item tags that never close after one good item, which is still read', () => {
    const xml = `<rss><channel><item><title>X-1</title><guid>x-1</guid></item>${'<item foo="1"'.repeat(FILL / 13)}</channel></rss>`
    const { ms, value } = timed(() => parseRssAdvisories(xml, 'X'))
    expect(ms).toBeLessThan(BOUND_MS)
    expect(value!.map((a) => a.id)).toEqual(['x-1'])
  })

  it('title, category and paragraph tags that never close inside one item', () => {
    for (const tag of ['<title>', '<category>', '<title x="']) {
      const xml = `<rss><channel><item><guid>x-1</guid>${tag.repeat(FILL / tag.length)}</item></channel></rss>`
      const { ms } = timed(() => parseRssAdvisories(xml, 'X'))
      expect(ms, tag).toBeLessThan(BOUND_MS)
    }
    const { ms, value } = timed(() => parseRssAdvisories(item('X-1', '<p>'.repeat(FILL / 3)), 'X'))
    expect(ms).toBeLessThan(BOUND_MS)
    expect(value).toHaveLength(1)
  })

  it('a description that is one long run of digits or spaces, for the fixed version', () => {
    for (const fill of ['1'.repeat(FILL), `Example ${' '.repeat(FILL)}`, '1.'.repeat(FILL / 2)]) {
      const { ms } = timed(() => parseRssAdvisories(item('X-1', fill), 'X'))
      expect(ms).toBeLessThan(BOUND_MS)
      expect(timed(() => extractFixedIn(fill, 'X')).ms).toBeLessThan(BOUND_MS)
    }
    // Still found after a long field, when it is in the first part.
    expect(parseRssAdvisories(item('X-1', `<p>Example v1.2.3 or later fixes it.</p>${'<'.repeat(FILL)}`), 'X')![0].fixedIn).toBe('Example 1.2.3')
  })
})

describe('GitHub advisories', () => {
  it('reads severity and every fixed version; drops withdrawn ones', () => {
    const items = parseGithubAdvisories([
      gh('GHSA-aaaa-aaaa-aaaa', 'high', NOW, { vulnerabilities: [{ patched_versions: '9.1.3' }, { patched_versions: '8.1.11' }, { patched_versions: '9.1.3' }] }),
      gh('GHSA-bbbb-bbbb-bbbb', 'moderate', NOW),
      gh('GHSA-cccc-cccc-cccc', 'critical', NOW, { withdrawn_at: '2025-03-23T00:00:00Z' }),
      gh('GHSA-dddd-dddd-dddd', 'unknown', NOW, { vulnerabilities: [] }),
      { not: 'an advisory' },
    ])
    expect(items!.map((a) => [a.id, a.severity, a.fixedIn])).toEqual([
      ['GHSA-aaaa-aaaa-aaaa', 'high', '9.1.3; 8.1.11'],
      ['GHSA-bbbb-bbbb-bbbb', 'medium', '2.0.1'],
      ['GHSA-dddd-dddd-dddd', null, null],
    ])
    expect(parseGithubAdvisories({ message: 'Not Found' })).toBeNull()
  })
})

describe('what cards', () => {
  const base: Advisory = { id: 'x', title: 'x', summary: 'x', url: '', published: NOW, severity: null, fixedIn: null }

  it('critical, high and bulletins with no severity card; medium and low do not', () => {
    expect(['critical', 'high', null, 'medium', 'low'].map((severity) => cardsAdvisory({ ...base, severity } as Advisory))).toEqual([true, true, true, false, false])
    expect(cardsAdvisory({ ...base, noCard: true })).toBe(false)
  })

  it('groups advisories one update fixes; one with no fixed version stays alone', () => {
    const groups = groupAdvisoriesByFix([
      { ...base, id: 'a', fixedIn: 'Example 2.3.4' },
      { ...base, id: 'b', fixedIn: 'Example 2.2.9' },
      { ...base, id: 'c' },
      { ...base, id: 'd', fixedIn: 'example 2.3.4 ' },
      { ...base, id: 'e' },
    ])
    expect(groups.map((g) => g.map((a) => a.id))).toEqual([['a', 'd'], ['b'], ['c'], ['e']])
  })
})

const CONFIG = parseWatchConfig({
  components: [
    { id: 'kev', name: 'CISA KEV', feed: { kind: 'kev' } },
    { id: 'linux', name: 'Linux kernel', runsOn: 'every server', kev: [{ vendor: '^Linux$', product: '\\bkernel\\b' }] },
    { id: 'engine', name: 'Engine', runsOn: 'web1', feed: { kind: 'github', repo: 'example/engine' }, kev: [{ vendor: '^Docker$' }] },
    { id: 'shim', name: 'Shim', kev: [{ product: '\\bcontainerd\\b' }] },
  ],
})

describe('the KEV catalog', () => {
  const inventory = kevInventory(CONFIG.components)

  it('builds the inventory from every component with kev names, the KEV feed itself left out', () => {
    expect(inventory.map((p) => p.id)).toEqual(['linux', 'engine', 'shim'])
  })

  it('needs every pattern a matcher gives, and at least one', () => {
    expect(kevMatches('Linux', 'Kernel', { vendor: /^Linux$/i, product: /kernel/i })).toBe(true)
    expect(kevMatches('Android', 'Kernel', { vendor: /^Linux$/i, product: /kernel/i })).toBe(false)
    expect(kevMatches(' Microsoft ', 'Windows ', { vendor: /^Microsoft$/i, product: /^windows$/i })).toBe(true)
    expect(kevMatches('Linux', 'Kernel', {})).toBe(false)
  })

  it('an entry for something listed is critical and names each match; the rest are recorded', () => {
    const out = parseKevCatalog(
      {
        catalogVersion: '2025.03.26',
        vulnerabilities: [
          kevEntry('CVE-2026-50003', 'Linux', 'Kernel'),
          kevEntry('CVE-2026-46301', 'Android', 'Kernel'),
          kevEntry('CVE-2026-46302', 'Docker', 'containerd shim', '2025-03-25', { knownRansomwareCampaignUse: 'Known' }),
          kevEntry('not-a-cve', 'Linux', 'Kernel'),
          null,
        ],
      },
      inventory,
    )!
    expect(out.map((a) => [a.id, a.severity, Boolean(a.noCard)])).toEqual([
      ['CVE-2026-50003', 'critical', false],
      ['CVE-2026-46301', null, true],
      ['CVE-2026-46302', 'critical', false],
    ])
    expect(out[0]).toMatchObject({
      title: 'CVE-2026-50003',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-50003',
      published: Date.parse('2025-03-26'),
      fixedIn: null,
      kev: { listedAs: 'Linux Kernel', products: [{ name: 'Linux kernel', runsOn: 'every server' }], dateAdded: '2025-03-26', dueDate: '2025-04-16', ransomware: false },
    })
    expect(out[2].kev).toMatchObject({ products: [{ name: 'Engine', runsOn: 'web1' }, { name: 'Shim' }], ransomware: true })
  })

  it('refuses what is not the catalog', () => {
    expect(parseKevCatalog({ message: 'Access Denied' }, inventory)).toBeNull()
    expect(parseKevCatalog([], inventory)).toBeNull()
  })
})

describe('watch card ids', () => {
  it('are always ids the card sink accepts, even from a feed guid with #, ?, = or spaces', () => {
    const odd = ['https://example.com/advisory?id=1&x=2#top', 'tag:example.com,2026:advisory 7', 'a'.repeat(300)]
    for (const guid of odd) expect(advisoryCardKey('example-feed', guid)).toMatch(WATCH_ID_RE)
    expect(cardId('kernel', 'x'.repeat(300))).toMatch(WATCH_ID_RE)
    // two guids that differ only in a refused character still get two cards
    expect(advisoryCardKey('example-feed', 'item?id=1')).not.toBe(advisoryCardKey('example-feed', 'item#id=1'))
    // an id that was already fine is unchanged, so cards already open keep their key
    expect(advisoryCardKey('example-feed', 'EX-2026-0001')).toBe('advisory:example-feed:EX-2026-0001')
  })
})
