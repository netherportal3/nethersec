import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ADVISORY_CARD_CAP, advisoryCardKey, createAdvisoryWatch, feedStateName, feedUnreadableKey, KEV_URL } from '../../src/watch/advisories.js'
import { parseWatchConfig, type WatchConfig } from '../../src/watch/config.js'
import { ghAdvisory, kevEntry, rss, rssItem } from './fixtures.js'
import { makeHub } from '../hubHelpers.js'
import { advanceClock, checkCardText, DAY, fakeDeps, HOUR, json, MASKED_LINK, pinClock, stateOf, text, type FakeDeps } from './helpers.js'

const NOW = Date.parse('2025-03-24T12:00:00Z')
const RSS_URL = 'https://example.com/bulletins/index.xml'
const GH_URL = 'https://api.github.com/repos/example/engine/security-advisories'
const TOKEN = ['test', 'token', 'value'].join('-')

const config = (components: unknown[]): WatchConfig => parseWatchConfig({ components })
const EX = { id: 'example', name: 'Example', runsOn: 'every box', feed: { kind: 'rss', url: RSS_URL } }
const ENGINE = { id: 'engine', name: 'Engine', runsOn: 'web1', feed: { kind: 'github', repo: 'example/engine' } }

const feeds = {
  rss: { body: rss(), status: 200, etag: '' },
  gh: { body: [] as unknown, status: 200, etag: '' },
  kev: { body: { vulnerabilities: [] } as unknown, status: 200, etag: '' },
}

let deps: FakeDeps
beforeEach(() => {
  pinClock(NOW)
  feeds.rss = { body: rss(), status: 200, etag: '' }
  feeds.gh = { body: [], status: 200, etag: '' }
  feeds.kev = { body: { vulnerabilities: [] }, status: 200, etag: '' }
  deps = fakeDeps(
    (url) => {
      if (url === RSS_URL) return text(feeds.rss.body, feeds.rss.etag || undefined, feeds.rss.status)
      if (url.startsWith(`${GH_URL}?`)) return json(feeds.gh.body, feeds.gh.etag || undefined, feeds.gh.status)
      if (url === KEV_URL) return typeof feeds.kev.body === 'string' ? text(feeds.kev.body, feeds.kev.etag || undefined, feeds.kev.status) : json(feeds.kev.body, feeds.kev.etag || undefined, feeds.kev.status)
      return null
    },
    { githubToken: TOKEN },
  )
})
afterEach(() => {
  vi.useRealTimers()
})

async function run(cfg: WatchConfig, after = 0) {
  if (after) advanceClock(after)
  const report = await createAdvisoryWatch(cfg, deps).run()
  checkCardText(deps.sink.upserts)
  return report
}

describe('feeds', () => {
  it('first read: cards only recent advisories that qualify, and records everything', async () => {
    feeds.rss.body = rss(
      rssItem('EX-0002', NOW - 5 * DAY, 'A crafted request crashes it.', 'Example v2.3.1 or later fixes it.'),
      rssItem('EX-0001', NOW - 200 * DAY, 'Old bulletin', 'Fixed in Example version 2.0.0 or newer.'),
    )
    feeds.gh.body = [ghAdvisory('GHSA-new1-high-0001', 'high', NOW - 3 * DAY), ghAdvisory('GHSA-new2-medi-0002', 'medium', NOW - 3 * DAY)]
    const cfg = config([EX, ENGINE])

    const report = await run(cfg)
    expect(report).toMatchObject({ kind: 'advisories', ok: true, feeds: 2, read: 2, emitted: 2, baselined: ['example', 'engine'], failed: [], deferred: 0, errors: [] })
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([
      advisoryCardKey('example', 'https://example.com/bulletins/#ex-0002'),
      advisoryCardKey('engine', 'GHSA-new1-high-0001'),
    ])
    const ex = deps.sink.upserts[0]
    expect(ex).toMatchObject({ severity: 'warning', ping: false, title: 'Security advisory for Example: EX-0002', url: 'https://example.com/bulletins/#ex-0002' })
    expect(ex.body).toBe(
      'A crafted request crashes it. Check whether it applies where Example runs, and compare the fixed version with what is installed there.\n\nRuns on: every box\nFixed in: Example 2.3.1\nPublished: 2025-03-19',
    )
    // A long id is hashed into a short, stable card id.
    expect(ex.id.length).toBeLessThanOrEqual(100)

    deps.sink.clear()
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 0, baselined: [], belowThreshold: 0 })
    expect(deps.sink.upserts).toEqual([])
  })

  it('after the first read: a new high is quiet, a new critical pages, a new medium is only counted', async () => {
    const cfg = config([ENGINE])
    await run(cfg)
    feeds.gh.body = [
      ghAdvisory('GHSA-crit-crit-crit', 'critical', NOW - 400 * DAY, { vulnerabilities: [{ patched_versions: '1.9.9' }] }),
      ghAdvisory('GHSA-high-high-high', 'high', NOW),
      ghAdvisory('GHSA-medi-medi-medi', 'medium', NOW),
    ]
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 2, belowThreshold: 1 })
    const byId = new Map(deps.sink.upserts.map((c) => [c.id, c]))
    expect(byId.get(advisoryCardKey('engine', 'GHSA-crit-crit-crit'))).toMatchObject({ severity: 'critical', ping: true, title: 'Critical advisory for Engine: GHSA-crit-crit-crit' })
    expect(byId.get(advisoryCardKey('engine', 'GHSA-high-high-high'))).toMatchObject({ severity: 'warning', ping: false, title: 'High advisory for Engine: GHSA-high-high-high' })
  })

  it('advisories one update fixes share a card, which pages when any is critical', async () => {
    const cfg = config([ENGINE])
    await run(cfg)
    feeds.gh.body = [
      ghAdvisory('GHSA-high-high-high', 'high', NOW),
      ghAdvisory('GHSA-crit-crit-crit', 'critical', NOW - DAY),
      ghAdvisory('GHSA-othr-othr-othr', 'high', NOW, { vulnerabilities: [{ patched_versions: '1.9.9' }] }),
    ]
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 2 })
    expect(deps.sink.upserts.map((c) => [c.id, c.title, c.severity, c.ping])).toEqual([
      [advisoryCardKey('engine', 'GHSA-crit-crit-crit+GHSA-high-high-high'), 'Critical advisories for Engine: GHSA-crit-crit-crit and GHSA-high-high-high', 'critical', true],
      [advisoryCardKey('engine', 'GHSA-othr-othr-othr'), 'High advisory for Engine: GHSA-othr-othr-othr', 'warning', false],
    ])
    const group = deps.sink.upserts[0].body
    expect(group).toContain('GHSA-crit-crit-crit: Summary of GHSA-crit-crit-crit https://github.com/example/engine/security/advisories/GHSA-crit-crit-crit')
    // The version is escaped for Discord (a number then a dot could start a list); Discord shows 2.0.1.
    expect(group).toContain('All 2 are fixed in 2\\.0.1. Check whether it applies')
    expect(group).toContain('Published: 2025-03-23 to 2025-03-24')
  })

  it('a long group list ends with how many more, and the card stays under the size limit', async () => {
    const cfg = config([ENGINE])
    await run(cfg)
    feeds.gh.body = Array.from({ length: 12 }, (_, i) => ghAdvisory(`GHSA-one${i}-fixx-fixx`, 'high', NOW, { summary: 'x'.repeat(290) }))
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 1, deferred: 0 })
    expect(deps.sink.upserts[0].body).toMatch(/\nAnd \d+ more\.\n\nAll 12 are fixed in 2\\\.0\.1\. /)
  })

  it('caps cards per run and cards the rest next run, keeping no ETag until then', async () => {
    const cfg = config([ENGINE])
    await run(cfg)
    feeds.gh.etag = 'W/"v2"'
    feeds.gh.body = Array.from({ length: ADVISORY_CARD_CAP + 2 }, (_, i) =>
      ghAdvisory(`GHSA-cap${i}-xxxx-xxxx`, 'high', NOW, { vulnerabilities: [{ patched_versions: `2.0.${i + 2}` }] }),
    )
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: ADVISORY_CARD_CAP, deferred: 2 })
    expect(stateOf<{ etag?: string }>(deps, feedStateName('engine'))?.etag).toBeUndefined()

    deps.requests.length = 0
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 2, deferred: 0 })
    expect(deps.requests[0].headers.get('if-none-match')).toBeNull()
    expect(new Set(deps.sink.upserts.map((c) => c.id)).size).toBe(ADVISORY_CARD_CAP + 2)

    // Complete now: the ETag is kept and a 304 changes nothing.
    deps.sink.clear()
    deps.requests.length = 0
    expect(await run(cfg, HOUR)).toMatchObject({ notModified: 1, read: 0, emitted: 0 })
    expect(deps.requests[0].headers.get('if-none-match')).toBe('W/"v2"')
  })

  it('a card the sink could not take is tried again next run', async () => {
    const cfg = config([ENGINE])
    await run(cfg)
    feeds.gh.body = [ghAdvisory('GHSA-retr-retr-retr', 'high', NOW)]
    deps.sink.accept = false
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 0, deferred: 1 })
    deps.sink.accept = true
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 1, deferred: 0 })
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([advisoryCardKey('engine', 'GHSA-retr-retr-retr')])
  })

  it('with a match, an RSS item that does not match is recorded without a card', async () => {
    const cfg = config([{ ...EX, feed: { kind: 'rss', url: RSS_URL, match: 'released' } }])
    await run(cfg)
    feeds.rss.body = rss(rssItem('Example 2.1 Released', NOW, 'An update.', ''), rssItem('Example meetup', NOW, 'News.', ''))
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 1, skipped: 1 })
    expect(deps.sink.upserts.map((c) => c.title)).toEqual(['Security advisory for Example: Example 2.1 Released'])
  })
})

describe('a feed that cannot be read', () => {
  it('changes nothing, cards once after a day, and closes when it reads again', async () => {
    const cfg = config([ENGINE])
    feeds.gh.body = [ghAdvisory('GHSA-seen-seen-seen', 'high', NOW - 100 * DAY)]
    await run(cfg)
    const before = stateOf<{ seen: string[] }>(deps, feedStateName('engine'))
    feeds.gh.status = 500
    for (let i = 1; i <= 24; i++) expect(await run(cfg, HOUR)).toMatchObject({ failed: ['engine'] })
    expect(stateOf<{ seen: string[] }>(deps, feedStateName('engine'))?.seen).toEqual(before?.seen)
    // The 24th failed read is 23 hours after the first: no card yet.
    expect(deps.sink.upserts).toEqual([])
    await run(cfg, HOUR)
    expect(deps.sink.upserts.map((c) => [c.id, c.severity, c.ping, c.title])).toEqual([[feedUnreadableKey('engine'), 'warning', false, "Can't read Engine advisories"]])
    expect(deps.sink.upserts[0].body).toMatch(/failed every read since 2025-03-24 13:00 UTC \(25 reads\).*It is not a clean bill of health\./)
    expect(deps.logs.some((l) => l === 'advisory watch: could not read the engine feed (HTTP 500)')).toBe(true)
    await run(cfg, HOUR)
    expect(deps.sink.upserts).toHaveLength(1)

    feeds.gh.status = 200
    deps.sink.clear()
    expect(await run(cfg, HOUR)).toMatchObject({ failed: [], emitted: 0, closed: 1 })
    expect(deps.sink.closes.map((c) => [c.id, c.wasOpen])).toEqual([[feedUnreadableKey('engine'), true]])
  })

  it("sends the can't-read card again every 6 hours while the feed still fails, so one a person resolved opens again", async () => {
    const cfg = config([ENGINE])
    feeds.gh.body = []
    await run(cfg)
    feeds.gh.status = 500
    for (let i = 1; i <= 25; i++) await run(cfg, HOUR)
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([feedUnreadableKey('engine')])
    // A person resolved it while the feed still fails.
    deps.sink.open.delete(feedUnreadableKey('engine'))
    deps.sink.clear()
    for (let i = 1; i <= 5; i++) expect(await run(cfg, HOUR)).toMatchObject({ resent: 0 })
    expect(await run(cfg, HOUR)).toMatchObject({ resent: 1, emitted: 0 })
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([feedUnreadableKey('engine')])
    expect(deps.sink.upserts[0].body).toContain('(31 reads)')
    expect(deps.sink.upserts[0].body).toContain('If you resolve it before that, it opens again within about 6 hours.')

    // Readable again: it closes, and the timer goes with it.
    feeds.gh.status = 200
    expect(await run(cfg, HOUR)).toMatchObject({ closed: 1 })
    expect(stateOf<Record<string, unknown>>(deps, feedStateName('engine'))).not.toHaveProperty('unreadableSentAt')
  })

  it('an advisory card is a notice: it is sent once, and a person resolving it does not bring it back', async () => {
    const cfg = config([ENGINE])
    feeds.gh.body = [ghAdvisory('GHSA-once-once-once', 'high', NOW - 3 * DAY)]
    expect(await run(cfg)).toMatchObject({ emitted: 1 })
    deps.sink.open.clear()
    deps.sink.clear()
    for (let i = 0; i < 4; i++) expect(await run(cfg, 6 * HOUR)).toMatchObject({ emitted: 0, resent: 0 })
    expect(deps.sink.upserts).toEqual([])
  })

  it('a body that is not a list or not RSS is a failed read, never an empty one', async () => {
    feeds.gh.body = { message: 'Not Found' }
    feeds.rss.body = '<html>moved</html>'
    const report = await run(config([EX, ENGINE]))
    expect(report.failed.sort()).toEqual(['engine', 'example'])
    expect(report.baselined).toEqual([])
    expect(stateOf<{ seen?: string[] }>(deps, feedStateName('engine'))?.seen).toBeUndefined()

    // A later good read is still the first read.
    feeds.gh.body = [ghAdvisory('GHSA-late-late-late', 'high', NOW - 100 * DAY)]
    expect(await run(config([ENGINE]), HOUR)).toMatchObject({ baselined: ['engine'], emitted: 0 })
  })

  it('a state that cannot be loaded skips that feed instead of reading it again from scratch', async () => {
    const cfg = config([ENGINE, EX])
    await run(cfg)
    deps.failLoad.add(feedStateName('engine'))
    feeds.gh.body = [ghAdvisory('GHSA-skip-skip-skip', 'high', NOW)]
    const report = await run(cfg, HOUR)
    expect(report).toMatchObject({ ok: false, read: 1, emitted: 0 })
    expect(report.errors).toEqual(['advisory watch: could not load watch-advisories-engine; skipping that feed this run'])
    expect(deps.requests.filter((r) => r.url.startsWith(GH_URL))).toHaveLength(1)
  })

  it('a state that cannot be saved is reported, and run() still resolves', async () => {
    deps.failSave.add(feedStateName('engine'))
    const report = await run(config([ENGINE]))
    expect(report.ok).toBe(false)
    expect(report.errors[0]).toMatch(/could not save watch-advisories-engine/)
  })

  it('never throws, even when fetch itself throws', async () => {
    deps.fetch = (() => {
      throw new Error('boom')
    }) as unknown as typeof fetch
    const report = await run(config([ENGINE, EX]))
    expect(report.failed.sort()).toEqual(['engine', 'example'])
  })
})

describe('requests', () => {
  it('sends the token to GitHub only, asks conditionally, and refuses redirects', async () => {
    feeds.rss.etag = '"r1"'
    const cfg = config([EX, ENGINE, { id: 'kev', name: 'CISA KEV', feed: { kind: 'kev' } }])
    await run(cfg)
    const github = deps.requests.filter((r) => r.url.startsWith('https://api.github.com/'))
    const others = deps.requests.filter((r) => !r.url.startsWith('https://api.github.com/'))
    expect(github.map((r) => r.url)).toEqual([`${GH_URL}?state=published&sort=published&direction=desc&per_page=20`])
    for (const r of github) expect(r.headers.get('authorization')).toBe(`Bearer ${TOKEN}`)
    expect(others.map((r) => r.url).sort()).toEqual([RSS_URL, KEV_URL].sort())
    for (const r of others) expect(r.headers.get('authorization')).toBeNull()
    for (const r of deps.requests) expect(r.redirect).toBe('error')

    deps.requests.length = 0
    expect(await run(cfg, HOUR)).toMatchObject({ notModified: 1 })
    expect(deps.requests.find((r) => r.url === RSS_URL)?.headers.get('if-none-match')).toBe('"r1"')
  })

  it('without a token, GitHub gets no Authorization header', async () => {
    deps.githubToken = undefined
    await run(config([ENGINE]))
    expect(deps.requests[0].headers.get('authorization')).toBeNull()
  })
})

describe('the KEV feed', () => {
  const KEV = { id: 'kev', name: 'CISA KEV', feed: { kind: 'kev' } }
  const LINUX = { id: 'linux', name: 'Linux kernel', runsOn: 'every server', kev: [{ vendor: '^Linux$', product: '\\bkernel\\b' }] }
  const cfg = config([ENGINE, KEV, LINUX])
  const KERNEL_BUG = 'CVE-2026-50003'
  const catalog = (...extra: ReturnType<typeof kevEntry>[]) => ({
    catalogVersion: '2025.03.26',
    vulnerabilities: [kevEntry('CVE-2014-6271', 'GNU', 'Bash', '2022-01-28'), kevEntry('CVE-2026-11111', 'Linux', 'Kernel', '2025-03-18'), ...extra],
  })

  it('cards nothing on its first read, even for recent entries, and records every entry', async () => {
    feeds.kev = { body: catalog(), status: 200, etag: '"v1"' }
    expect(await run(cfg)).toMatchObject({ baselined: ['kev', 'engine'], emitted: 0 })
    expect(deps.sink.upserts).toEqual([])
    expect(stateOf<{ seen: string[]; etag: string }>(deps, feedStateName('kev'))).toMatchObject({ seen: ['CVE-2014-6271', 'CVE-2026-11111'], etag: '"v1"' })
  })

  it('pages once for a new entry for a listed component, whatever the catalog does next', async () => {
    feeds.kev = { body: catalog(), status: 200, etag: '"v1"' }
    await run(cfg)
    feeds.kev = { body: catalog(kevEntry(KERNEL_BUG, 'Linux', 'Kernel')), status: 200, etag: '"v2"' }
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 1, skipped: 0, baselined: [] })
    const card = deps.sink.upserts[0]
    expect(card).toEqual({
      id: advisoryCardKey('kev', KERNEL_BUG),
      severity: 'critical',
      ping: true,
      title: `Exploited in the wild: ${KERNEL_BUG} in Linux kernel`,
      url: `https://nvd.nist.gov/vuln/detail/${KERNEL_BUG}`,
      body:
        'Linux Kernel contains a flaw that lets a remote attacker run code. CISA lists it as exploited in the wild. Check whether it applies where it runs, then patch or mitigate it by the due date. A fix may not be out yet.\n\n' +
        'Runs on: every server\nListed as: Linux Kernel\nAdded to KEV: 2025-03-26\nCISA due date: 2025-04-16',
    })

    deps.sink.clear()
    expect(await run(cfg, HOUR)).toMatchObject({ notModified: 1, emitted: 0 })
    feeds.kev.etag = '"v3"'
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 0 })
    expect(deps.sink.upserts).toEqual([])
  })

  it('records a new entry for something not listed, and names known ransomware use', async () => {
    feeds.kev = { body: catalog(), status: 200, etag: '"v1"' }
    await run(cfg)
    feeds.kev = { body: catalog(kevEntry('CVE-2026-22222', 'Example', 'Router'), kevEntry(KERNEL_BUG, 'Linux', 'Kernel', '2025-03-26', { knownRansomwareCampaignUse: 'Known' })), status: 200, etag: '"v2"' }
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 1, skipped: 1 })
    expect(deps.sink.upserts[0].body).toContain('Ransomware: known to be used in ransomware campaigns')
  })

  it('a catalog that does not read changes nothing', async () => {
    feeds.kev = { body: catalog(), status: 200, etag: '"v1"' }
    await run(cfg)
    const before = stateOf(deps, feedStateName('kev'))
    for (const body of ['<html>Access Denied</html>', { message: 'not the catalog' }]) {
      feeds.kev = { body, status: 200, etag: '' }
      expect(await run(cfg, HOUR)).toMatchObject({ failed: ['kev'], emitted: 0 })
    }
    feeds.kev = { body: catalog(), status: 503, etag: '' }
    expect(await run(cfg, HOUR)).toMatchObject({ failed: ['kev'] })
    expect(deps.sink.upserts).toEqual([])
    expect(stateOf(deps, feedStateName('kev'))).toEqual({ ...before, fails: 3, failingSince: NOW + HOUR, unreadableCarded: false })
  })

  it('reads the KEV feed first, so the card cap never holds a page back', async () => {
    feeds.kev = { body: catalog(), status: 200, etag: '' }
    await run(cfg)
    feeds.gh.body = Array.from({ length: ADVISORY_CARD_CAP }, (_, i) => ghAdvisory(`GHSA-cap${i}-xxxx-xxxx`, 'high', NOW, { vulnerabilities: [{ patched_versions: `3.0.${i}` }] }))
    feeds.kev = { body: catalog(kevEntry(KERNEL_BUG, 'Linux', 'Kernel')), status: 200, etag: '' }
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: ADVISORY_CARD_CAP, deferred: 1 })
    expect(deps.sink.upserts[0].id).toBe(advisoryCardKey('kev', KERNEL_BUG))
  })
})

describe('more feed rules', () => {
  it('a component added later is matched against the KEV entries added from then on', async () => {
    const KEV = { id: 'kev', name: 'CISA KEV', feed: { kind: 'kev' } }
    const before = config([KEV])
    feeds.kev = { body: { vulnerabilities: [kevEntry('CVE-2026-30001', 'Example', 'Router', '2025-03-23')] }, status: 200, etag: '' }
    await run(before)
    const after = config([KEV, { id: 'router', name: 'Router', kev: [{ product: '^Router$' }] }])
    expect(await run(after, HOUR)).toMatchObject({ emitted: 0 })
    feeds.kev = { body: { vulnerabilities: [kevEntry('CVE-2026-30001', 'Example', 'Router', '2025-03-23'), kevEntry('CVE-2026-30002', 'Example', 'Router')] }, status: 200, etag: '' }
    expect(await run(after, HOUR)).toMatchObject({ emitted: 1 })
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([advisoryCardKey('kev', 'CVE-2026-30002')])
  })

  it('reads at most the first 500 items of an RSS feed', async () => {
    const cfg = config([EX])
    feeds.rss.body = rss(...Array.from({ length: 510 }, (_, i) => rssItem(`EX-${i}`, NOW - 100 * DAY, 'Old.', '')))
    await run(cfg)
    expect(stateOf<{ seen: string[] }>(deps, feedStateName('example'))?.seen).toHaveLength(500)
  })
})

describe('feed text on a card', () => {
  const HIDDEN = '[Download the official patch](https://evil.example/patch.exe)'
  const SHOWN = '\\[Download the official patch\\]'

  /** The card as the hub posts it: the embed's description. */
  async function shown(card: (typeof deps.sink.upserts)[number]): Promise<string> {
    const hub = await makeHub()
    await hub.ops.upsert(card)
    return hub.discord.sent[0].payload.embeds[0].description ?? ''
  }

  it('an RSS description cannot hide a link or format the card', async () => {
    // Its own XML: the fixture's ids hold a "#", which a hub card id cannot.
    const description = `<p>${HIDDEN} **now**</p><p>Example v2.3.1 or later fixes it.</p>`
    feeds.rss.body = rss(
      `<item><title>EX-0009</title><guid>ex-0009</guid><pubDate>${new Date(NOW - HOUR).toUTCString()}</pubDate><description><![CDATA[${description}]]></description></item>`,
    )
    expect(await run(config([EX]))).toMatchObject({ emitted: 1 })
    const card = deps.sink.upserts[0]
    expect(card.body).toContain(`${SHOWN}(https://evil.example/patch.exe) \\*\\*now\\*\\*`)
    expect(card.body).not.toMatch(MASKED_LINK)
    const embed = await shown(card)
    expect(embed).toContain(SHOWN)
    expect(embed).not.toMatch(MASKED_LINK)
  })

  it('GitHub and KEV text is escaped too, and a link that could end early is left out', async () => {
    const odd = 'https://example.com/a)[b](https://evil.example'
    const fix = { vulnerabilities: [{ patched_versions: '[2.0.1](https://evil.example)' }] }
    feeds.gh.body = [ghAdvisory('GHSA-aaaa-aaaa-aaaa', 'high', NOW, { ...fix, summary: HIDDEN, html_url: odd }), ghAdvisory('GHSA-bbbb-bbbb-bbbb', 'high', NOW, { ...fix, summary: '**loud**' })]
    const KEV = { id: 'kev', name: 'CISA KEV', feed: { kind: 'kev' } }
    const LINUX = { id: 'linux', name: 'Linux kernel', kev: [{ vendor: '^Linux$', product: '\\bkernel\\b' }] }
    const cfg = config([ENGINE, KEV, LINUX])
    await run(cfg)
    feeds.kev.body = { vulnerabilities: [kevEntry('CVE-2026-50009', 'Linux', `Kernel ${HIDDEN}`, '2025-03-24', { shortDescription: HIDDEN, dueDate: '**soon**' })] }
    expect(await run(cfg, HOUR)).toMatchObject({ emitted: 1 })
    const group = deps.sink.upserts.find((c) => c.id === advisoryCardKey('engine', 'GHSA-aaaa-aaaa-aaaa+GHSA-bbbb-bbbb-bbbb'))!
    const kev = deps.sink.upserts.find((c) => c.id === advisoryCardKey('kev', 'CVE-2026-50009'))!
    for (const card of [group, kev]) {
      expect(card.body, card.id).not.toMatch(MASKED_LINK)
      expect(card.body, card.id).toContain(SHOWN)
      expect(await shown(card), card.id).not.toMatch(MASKED_LINK)
    }
    expect(group.body).toContain('\\*\\*loud\\*\\*')
    expect(group.body).toContain('Fixed in: \\[2.0.1\\](https://evil.example)')
    expect(group.body).not.toContain(odd)
    expect(kev.body).toContain(`Listed as: Linux Kernel ${SHOWN}`)
    expect(kev.body).toContain('CISA due date: \\*\\*soon\\*\\*')
  })
})
