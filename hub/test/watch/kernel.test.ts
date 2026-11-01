import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createAdvisoryWatch, feedStateName, feedUnreadableKey } from '../../src/watch/advisories.js'
import { parseWatchConfig } from '../../src/watch/config.js'
import {
  describeUbuntuStatus,
  KERNEL_CNA_SOURCE,
  kernelCardKey,
  kernelCvss,
  kernelFirstReadCardKey,
  kernelFixMissing,
  noUbuntuRecord,
  NVD_CVE_API,
  NVD_PAGE_SIZE,
  NVD_PAGES_PER_RUN,
  parseNvdKernelPage,
  parseUbuntuKernelStatus,
  UBUNTU_CVE_URL,
  UBUNTU_LOOKUP_CAP,
  ubuntuStatusLines,
} from '../../src/watch/kernel.js'
import { advanceClock, checkCardText, DAY, fakeDeps, HOUR, json, MASKED_LINK, pinClock, stateOf, text, type FakeDeps } from './helpers.js'
import { makeHub } from '../hubHelpers.js'

const NOW = Date.parse('2025-03-28T12:00:00Z')
const CFG = parseWatchConfig({ kernel: { ubuntu: ['24.04', '22.04'], runsOn: 'every server' } })
const RELEASES = CFG.kernel!.releases
const STATE = feedStateName('linux-kernel')
const TARGET = 'CVE-2026-50001'

/** A kernel record in NVD's shape, scored by the kernel CNA unless `source` says otherwise. */
function nvdRecord(id: string, score = 9.8, av: 'NETWORK' | 'LOCAL' = 'NETWORK', published = '2025-03-18T10:00:00.000', source = KERNEL_CNA_SOURCE) {
  return {
    cve: {
      id,
      sourceIdentifier: KERNEL_CNA_SOURCE,
      published,
      lastModified: published,
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: `In the Linux kernel, the following vulnerability has been resolved:\n\nnet: fix ${id}\n\nDetails.` }],
      metrics: {
        cvssMetricV31: [
          {
            source,
            type: 'Secondary',
            cvssData: { version: '3.1', vectorString: `CVSS:3.1/AV:${av === 'NETWORK' ? 'N' : 'L'}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, baseScore: score, attackVector: av },
          },
        ],
      },
    },
  }
}

/** Ubuntu's record of a CVE with these kernel statuses per release. */
function ubuntuRecord(id: string, statuses: Record<string, [string, string?]>) {
  return {
    id,
    priority: 'high',
    packages: [
      {
        name: 'linux',
        statuses: Object.entries(statuses).map(([release_codename, [status, description = '']]) => ({ release_codename, status, description, pocket: 'security' })),
      },
    ],
  }
}

const PENDING = { noble: ['pending', '6.8.0-101.101'], jammy: ['pending', '5.15.0-201.201'] } as Record<string, [string, string?]>

const nvd = { records: [] as unknown[], status: 200 }
const ubuntu = { records: {} as Record<string, unknown>, status: {} as Record<string, number> }
let deps: FakeDeps

beforeEach(() => {
  pinClock(NOW)
  nvd.records = [
    nvdRecord(TARGET, 9.8, 'NETWORK', '2025-03-13T09:30:00.000'),
    nvdRecord('CVE-2026-50002', 9.4),
    nvdRecord('CVE-2026-60001', 8.8, 'LOCAL'),
    nvdRecord('CVE-2026-60002', 9.8, 'LOCAL'),
    nvdRecord('CVE-2026-60003', 7.5),
    nvdRecord('CVE-2026-60004', 9.8, 'NETWORK', undefined, 'af854a3a-2127-422b-91ae-364da2661108'),
  ]
  nvd.status = 200
  ubuntu.records = {
    [TARGET]: ubuntuRecord(TARGET, PENDING),
    'CVE-2026-50002': ubuntuRecord('CVE-2026-50002', { noble: ['not-affected'], jammy: ['released', '5.15.0-180.180'] }),
  }
  ubuntu.status = {}
  deps = fakeDeps(
    (url) => {
      if (url.startsWith(`${NVD_CVE_API}?`)) {
        if (nvd.status !== 200) return text('unavailable', undefined, nvd.status)
        const q = new URL(url).searchParams
        const start = Number(q.get('startIndex'))
        const size = Number(q.get('resultsPerPage'))
        const page = nvd.records.slice(start, start + size)
        return json({ resultsPerPage: page.length, startIndex: start, totalResults: nvd.records.length, format: 'NVD_CVE', version: '2.0', vulnerabilities: page })
      }
      if (url.startsWith(`${UBUNTU_CVE_URL}/`)) {
        const id = url.slice(UBUNTU_CVE_URL.length + 1).replace(/\.json$/, '')
        const status = ubuntu.status[id] ?? ubuntu.status['*'] ?? 200
        if (status !== 200) return text('error', undefined, status)
        return id in ubuntu.records ? json(ubuntu.records[id]) : text('not found', undefined, 404)
      }
      return null
    },
    { githubToken: 'unused' },
  )
})
afterEach(() => {
  vi.useRealTimers()
})

const nvdRequests = () => deps.requests.filter((r) => r.url.startsWith(`${NVD_CVE_API}?`)).map((r) => new URL(r.url).searchParams)
const ubuntuLookups = () => deps.requests.filter((r) => r.url.startsWith(`${UBUNTU_CVE_URL}/`)).map((r) => r.url.slice(UBUNTU_CVE_URL.length + 1, -5))
type KState = { seen?: string[]; queue?: Array<{ id: string }>; through?: number; pass?: Record<string, number>; open?: Array<{ key: string; label: string; members: Array<{ cve: { id: string } }> }> }
const kstate = () => stateOf<KState>(deps, STATE)

async function run(after = 0) {
  if (after) advanceClock(after)
  const report = await createAdvisoryWatch(CFG, deps).run()
  checkCardText(deps.sink.upserts)
  return report
}

/** One run with an empty NVD window, so later runs are past the first read. */
async function finishBaseline() {
  const saved = nvd.records
  nvd.records = []
  vi.setSystemTime(NOW - HOUR)
  await run()
  vi.setSystemTime(NOW)
  nvd.records = saved
  deps.sink.clear()
  deps.requests.length = 0
}

describe('parsing', () => {
  it('keeps records scored 9.0 or more with a network attack vector, on the kernel CNA score', () => {
    const page = parseNvdKernelPage({ totalResults: 6, vulnerabilities: nvd.records })!
    expect(page).toMatchObject({ total: 6, count: 6 })
    expect(page.cves.map((c) => c.id)).toEqual([TARGET, 'CVE-2026-50002'])
    expect(page.cves[0]).toEqual({
      id: TARGET,
      summary: `net: fix ${TARGET}`,
      score: 9.8,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      scoredBy: 'kernel',
      // NVD's timestamps carry no offset and are UTC.
      published: Date.parse('2025-03-13T09:30:00.000Z'),
    })
    expect(parseNvdKernelPage({ message: 'Not Found' })).toBeNull()
    expect(parseNvdKernelPage([])).toBeNull()
  })

  it("prefers the kernel CNA's score to NVD's, and ignores anyone else's", () => {
    const split = nvdRecord('CVE-2026-90001', 7.8, 'LOCAL').cve
    split.metrics.cvssMetricV31.push({
      source: 'nvd@nist.gov',
      type: 'Primary',
      cvssData: { version: '3.1', baseScore: 9.8, attackVector: 'NETWORK', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    })
    expect(kernelCvss(split)).toMatchObject({ score: 7.8, scoredBy: 'kernel', network: false })
    const nvdOnly = nvdRecord('CVE-2026-90002', 9.1, 'NETWORK', undefined, 'nvd@nist.gov').cve
    expect(kernelCvss(nvdOnly)).toMatchObject({ score: 9.1, scoredBy: 'nvd', network: true })
    expect(kernelCvss(nvdRecord('CVE-2026-90003', 9.8, 'NETWORK', undefined, 'someone-else').cve)).toBeNull()
    expect(kernelCvss({ id: 'CVE-2026-90004', metrics: {} })).toBeNull()
  })

  it("reads Ubuntu's status per release, and what counts as no fix", () => {
    const statuses = parseUbuntuKernelStatus(ubuntuRecord(TARGET, PENDING), TARGET, RELEASES)!
    expect(statuses).toEqual([
      { codename: 'noble', name: 'Ubuntu 24.04', status: 'pending', version: '6.8.0-101.101' },
      { codename: 'jammy', name: 'Ubuntu 22.04', status: 'pending', version: '5.15.0-201.201' },
    ])
    expect(kernelFixMissing(statuses)).toBe(true)
    // A release with no row is fixed from before it existed.
    const old = parseUbuntuKernelStatus(ubuntuRecord('CVE-2024-36288', { noble: ['released', '6.8.0-40.40'] }), 'CVE-2024-36288', RELEASES)!
    expect(old.map((s) => s.status)).toEqual(['released', 'unlisted'])
    expect(kernelFixMissing(old)).toBe(false)
    // No kernel entry yet is no record yet, which is no fix.
    const bare = parseUbuntuKernelStatus({ id: 'CVE-2026-90005', packages: [] }, 'CVE-2026-90005', RELEASES)!
    expect(bare).toEqual(noUbuntuRecord(RELEASES))
    expect(kernelFixMissing(bare)).toBe(true)
    for (const status of ['needed', 'needs-triage', 'deferred', 'ignored', 'something-new']) {
      expect(kernelFixMissing(parseUbuntuKernelStatus(ubuntuRecord('CVE-2026-90006', { noble: [status], jammy: ['released'] }), 'CVE-2026-90006', RELEASES)!)).toBe(true)
    }
    expect(parseUbuntuKernelStatus(ubuntuRecord(TARGET, PENDING), 'CVE-2026-50002', RELEASES)).toBeNull()
    expect(describeUbuntuStatus({ codename: 'noble', name: 'Ubuntu 24.04', status: 'needed', version: '' })).toBe('needed (no fix yet)')
  })

  it('sums up several CVEs per release, most common status first', () => {
    const s = (noble: [string, string?], jammy: [string, string?]) => parseUbuntuKernelStatus(ubuntuRecord('CVE-2026-90010', { noble, jammy }), 'CVE-2026-90010', RELEASES)!
    const many = [
      s(['pending', '6.8.0-101.101'], ['pending', '5.15.0-201.201']),
      s(['pending', '6.8.0-100.100'], ['released', '5.15.0-200.200']),
      s(['pending', '6.8.0-100.100'], ['not-affected']),
      s(['needed'], ['pending', '5.15.0-201.201']),
      s(['pending', '6.8.0-100.100'], ['pending', '5.15.0-201.201']),
    ]
    expect(ubuntuStatusLines(many)).toBe(
      'Ubuntu 24.04 (noble): 3 pending 6.8.0-100.100, 1 needed (no fix yet), 1 pending 6.8.0-101.101\n' +
        'Ubuntu 22.04 (jammy): 3 pending 5.15.0-201.201, 1 fixed in 5.15.0-200.200, 1 not affected',
    )
  })
})

describe('the kernel feed', () => {
  it('cards a new critical network bug once, with both pending versions, and pages', async () => {
    await finishBaseline()
    const report = await run()
    expect(report).toMatchObject({ feeds: 1, read: 1, emitted: 1, failed: [], baselined: [], deferred: 0, skipped: 1, belowThreshold: 4 })
    expect(ubuntuLookups().sort()).toEqual([TARGET, 'CVE-2026-50002'])
    expect(deps.sink.upserts).toEqual([
      {
        id: kernelCardKey([TARGET]),
        severity: 'critical',
        ping: true,
        title: `Critical kernel bug with no Ubuntu security fix yet: ${TARGET}`,
        url: `https://ubuntu.com/security/${TARGET}`,
        body: expect.stringMatching(new RegExp(`^net: fix ${TARGET}\\. Ubuntu has not released a security update`)),
      },
    ])
    const body = deps.sink.upserts[0].body
    expect(body).toContain('Pending means Ubuntu built the fix (in -proposed or -updates)')
    expect(body).toContain(
      '\n\nUbuntu 24.04 (noble): pending 6.8.0-101.101\nUbuntu 22.04 (jammy): pending 5.15.0-201.201\nRuns on: every server\nCVSS: 9.8 from the kernel CNA, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\nPublished: 2025-03-13',
    )
    expect(kstate()).toMatchObject({ seen: ['CVE-2026-50002'], queue: [], through: NOW })
    expect(kstate()?.open?.map((o) => [o.key, o.label, o.members.map((m) => m.cve.id)])).toEqual([[kernelCardKey([TARGET]), TARGET, [TARGET]]])

    // The same records again: no second card, and only the open one is looked up.
    deps.sink.clear()
    deps.requests.length = 0
    expect(await run(HOUR)).toMatchObject({ emitted: 0, deferred: 0 })
    expect(deps.sink.upserts).toEqual([])
    expect(ubuntuLookups()).toEqual([TARGET])
  })

  it('first read: reads the last 30 days and cards what is open without paging', async () => {
    expect(await run()).toMatchObject({ emitted: 1, baselined: ['linux-kernel'] })
    const [q] = nvdRequests()
    expect(q.get('sourceIdentifier')).toBe(KERNEL_CNA_SOURCE)
    expect(q.get('lastModStartDate')).toBe(new Date(NOW - 30 * DAY).toISOString())
    expect(q.get('lastModEndDate')).toBe(new Date(NOW).toISOString())
    expect(q.has('noRejected')).toBe(true)
    expect(deps.sink.upserts[0]).toMatchObject({ id: kernelFirstReadCardKey(), severity: 'warning', ping: false })
    expect(deps.sink.upserts[0].body).toContain('Already open when this feed first read the last 30 days, so this card does not page.')

    // The next window starts two hours before the last one ended.
    deps.requests.length = 0
    await run(HOUR)
    expect(nvdRequests()[0].get('lastModStartDate')).toBe(new Date(NOW - 2 * HOUR).toISOString())
  })

  it('closes the card once every listed release has the fix, and retries a close that did not go out', async () => {
    await finishBaseline()
    await run()
    deps.sink.clear()
    ubuntu.records[TARGET] = ubuntuRecord(TARGET, { noble: ['released', '6.8.0-101.101'], jammy: ['pending', '5.15.0-201.201'] })
    await run(HOUR)
    expect(deps.sink.closes).toEqual([])

    ubuntu.records[TARGET] = ubuntuRecord(TARGET, { noble: ['released', '6.8.0-101.101'], jammy: ['not-affected'] })
    deps.sink.accept = false
    await run(HOUR)
    expect(kstate()?.open?.map((o) => [o.key, o.members.length])).toEqual([[kernelCardKey([TARGET]), 0]])

    deps.sink.accept = true
    expect(await run(HOUR)).toMatchObject({ closed: 1 })
    expect(deps.sink.closes.map((c) => [c.id, c.wasOpen])).toEqual([[kernelCardKey([TARGET]), true]])
    expect(deps.sink.closes[0].note).toMatch(/^Ubuntu security fix out for CVE-2026-50001\./)
    expect(kstate()?.open).toEqual([])

    // Closed for good: no new card and no more lookups.
    deps.sink.clear()
    deps.requests.length = 0
    await run(HOUR)
    expect(deps.sink.upserts).toEqual([])
    expect(ubuntuLookups()).toEqual([])
  })

  it('a card a person resolved opens again, and pages again, while the fix is still missing', async () => {
    // The real hub cards with a fake Discord, so Resolve and the reopen are the hub's own.
    const hub = await makeHub()
    const hubDeps: FakeDeps = { ...deps, cards: hub.ops }
    const hubRun = (after = 0) => {
      if (after) advanceClock(after)
      return createAdvisoryWatch(CFG, hubDeps).run()
    }
    const key = `watch:${kernelCardKey([TARGET])}`
    await finishBaseline()
    expect(await hubRun()).toMatchObject({ emitted: 1 })
    expect(hub.discord.sent.map((s) => [s.channelId, s.payload.content])).toEqual([['crit', '<@&42>']])
    expect(hub.discord.sent[0].payload.embeds[0].description).toContain('If you resolve it before that, it opens again within about 6 hours.')
    const first = hub.ops.findOpen(key)!
    expect((await hub.ops.press('resolve', first.id, '7'.repeat(18))).ok).toBe(true)

    expect(await hubRun(5 * HOUR)).toMatchObject({ resent: 0 })
    expect(hub.ops.findOpen(key)).toBeUndefined()
    expect(await hubRun(HOUR)).toMatchObject({ resent: 1, emitted: 0 })
    expect(hub.discord.sent.map((s) => [s.channelId, s.payload.content])).toEqual([
      ['crit', '<@&42>'],
      ['crit', '<@&42>'],
    ])
    expect(hub.ops.findOpen(key)!.id).not.toBe(first.id)

    // Open and unchanged: the next send edits nothing and posts nothing.
    expect(await hubRun(6 * HOUR)).toMatchObject({ resent: 1 })
    expect(hub.discord.sent).toHaveLength(2)
    expect(hub.discord.edits).toHaveLength(0)

    // Ubuntu's status moved for one release: the next send edits the open card with it.
    ubuntu.records[TARGET] = ubuntuRecord(TARGET, { noble: ['released', '6.8.0-101.101'], jammy: ['pending', '5.15.0-201.201'] })
    await hubRun(HOUR)
    expect(hub.discord.edits).toHaveLength(0)
    expect(await hubRun(5 * HOUR)).toMatchObject({ resent: 1 })
    expect(hub.discord.edits).toHaveLength(1)
    expect(hub.discord.edits[0].payload.embeds[0].description).toContain('Ubuntu 24.04 (noble): fixed in 6.8.0-101.101')

    // The fix is out: it closes itself.
    ubuntu.records[TARGET] = ubuntuRecord(TARGET, { noble: ['released', '6.8.0-101.101'], jammy: ['not-affected'] })
    expect(await hubRun(HOUR)).toMatchObject({ closed: 1 })
    expect(hub.ops.findOpen(key)).toBeUndefined()
  })

  it('no Ubuntu record yet cards, and says so', async () => {
    await finishBaseline()
    delete ubuntu.records[TARGET]
    await run()
    expect(deps.sink.upserts[0].body).toContain('Ubuntu 24.04 (noble): no Ubuntu record yet\nUbuntu 22.04 (jammy): no Ubuntu record yet')
  })

  it('a lookup that fails leaves the CVE queued, and it pages once Ubuntu answers', async () => {
    await finishBaseline()
    ubuntu.status[TARGET] = 500
    expect(await run()).toMatchObject({ emitted: 0, deferred: 1, failed: [] })
    expect(kstate()?.queue?.map((q) => q.id)).toEqual([TARGET])
    delete ubuntu.status[TARGET]
    expect(await run(HOUR)).toMatchObject({ emitted: 1, deferred: 0 })
    expect(deps.sink.upserts[0]).toMatchObject({ id: kernelCardKey([TARGET]), ping: true })
  })

  it('a card the sink could not take puts its CVEs back, and they card next run', async () => {
    await finishBaseline()
    deps.sink.accept = false
    expect(await run()).toMatchObject({ emitted: 0, deferred: 1 })
    expect(kstate()?.queue?.map((q) => q.id)).toEqual([TARGET])
    deps.sink.accept = true
    expect(await run(HOUR)).toMatchObject({ emitted: 1, deferred: 0 })
  })

  it('Ubuntu unreadable is a failed read that changes nothing', async () => {
    await finishBaseline()
    const before = kstate()
    ubuntu.status['*'] = 503
    expect((await run()).failed).toEqual(['linux-kernel'])
    expect(deps.sink.upserts).toEqual([])
    expect(kstate()).toEqual({ ...before, fails: 1, failingSince: NOW, unreadableCarded: false })
  })

  it('NVD failing changes nothing, cards once after a day, and the next good read covers the outage', async () => {
    await finishBaseline()
    nvd.status = 503
    for (let i = 0; i < 24; i++) expect(await run(i ? HOUR : 0)).toMatchObject({ failed: ['linux-kernel'] })
    expect(deps.sink.upserts).toEqual([])
    await run(HOUR)
    expect(deps.sink.upserts.map((c) => [c.id, c.title])).toEqual([[feedUnreadableKey('linux-kernel'), "Can't read Linux kernel advisories"]])
    expect(kstate()?.through).toBe(NOW - HOUR)

    nvd.status = 200
    deps.sink.clear()
    deps.requests.length = 0
    expect(await run(HOUR)).toMatchObject({ emitted: 1, closed: 1 })
    expect(nvdRequests()[0].get('lastModStartDate')).toBe(new Date(NOW - 3 * HOUR).toISOString())
    expect(deps.sink.closes.map((c) => c.id)).toEqual([feedUnreadableKey('linux-kernel')])
  })

  it('reads a window bigger than a page from its newest records back, a few pages a run', async () => {
    await finishBaseline()
    const total = NVD_PAGE_SIZE * 4 + 100
    const ids = Array.from({ length: total }, (_, i) => `CVE-2026-${70000 + i}`)
    const boundary = NVD_PAGE_SIZE + 99
    const critical = new Set([total - 1, boundary])
    nvd.records = ids.map((id, i) => nvdRecord(id, critical.has(i) ? 9.8 : 7.8, critical.has(i) ? 'NETWORK' : 'LOCAL'))
    for (const i of critical) ubuntu.records[ids[i]] = ubuntuRecord(ids[i], { noble: ['needed'], jammy: ['needed'] })

    const first = await run()
    const pages = nvdRequests().map((q) => [Number(q.get('startIndex')), Number(q.get('resultsPerPage'))])
    expect(pages).toEqual([
      [0, NVD_PAGE_SIZE],
      [total - NVD_PAGE_SIZE, NVD_PAGE_SIZE],
      [total - 2 * NVD_PAGE_SIZE, NVD_PAGE_SIZE],
      [total - 3 * NVD_PAGE_SIZE, NVD_PAGE_SIZE],
    ])
    expect(pages).toHaveLength(NVD_PAGES_PER_RUN)
    expect(first.emitted).toBe(1)
    expect(deps.sink.upserts[0].id).toBe(kernelCardKey([ids[total - 1]]))
    expect(kstate()).toMatchObject({ through: NOW - HOUR, pass: { from: NOW - 3 * HOUR, to: NOW, next: total - 3 * NVD_PAGE_SIZE } })

    // A record already read changes again and leaves the window: the rest move up a place.
    nvd.records = nvd.records.filter((_, i) => i !== 50)
    deps.sink.clear()
    deps.requests.length = 0
    await run(HOUR)
    expect(nvdRequests().map((q) => [Number(q.get('startIndex')), Number(q.get('resultsPerPage'))])).toEqual([
      [total - 4 * NVD_PAGE_SIZE, NVD_PAGE_SIZE],
      [0, total - 4 * NVD_PAGE_SIZE],
    ])
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([kernelCardKey([ids[boundary]])])
    expect(kstate()?.through).toBe(NOW)
    expect(kstate()?.pass).toBeUndefined()
  })

  it("a run's new CVEs share one card that pages, and it closes once all of them are fixed", async () => {
    await finishBaseline()
    const ids = Array.from({ length: 8 }, (_, i) => `CVE-2026-${80000 + i}`)
    nvd.records = ids.map((id, i) => nvdRecord(id, i === 7 ? 9.1 : 9.8, 'NETWORK', `2025-03-${18 + (i % 3)}T10:00:00.000`))
    ids.forEach((id, i) => {
      ubuntu.records[id] = ubuntuRecord(id, i < 5 ? { noble: ['needed'], jammy: ['pending', '5.15.0-201.201'] } : PENDING)
    })
    expect(await run()).toMatchObject({ emitted: 1, deferred: 0 })
    const card = deps.sink.upserts[0]
    expect(card).toMatchObject({ id: kernelCardKey(ids), severity: 'critical', ping: true, title: '8 critical kernel bugs with no Ubuntu security fix yet' })
    expect(card.url).toBeUndefined()
    expect(card.body).toContain(`${ids[0]}, 9.8: net: fix ${ids[0]}`)
    expect(card.body).toContain("Ubuntu's page for each: https://ubuntu.com/security/<CVE id>")
    expect(card.body).toContain('Ubuntu 24.04 (noble): 5 needed (no fix yet), 3 pending 6.8.0-101.101\nUbuntu 22.04 (jammy): 8 pending 5.15.0-201.201')
    expect(card.body).toContain('CVSS: 9.1 to 9.8 from the kernel CNA, network\nPublished: 2025-03-18 to 2025-03-20')

    for (const id of ids.slice(0, 7)) ubuntu.records[id] = ubuntuRecord(id, { noble: ['released', '6.8.0-102.102'], jammy: ['released', '5.15.0-202.202'] })
    await run(HOUR)
    expect(deps.sink.closes).toEqual([])
    expect(kstate()?.open?.[0].members.map((m) => m.cve.id)).toEqual([ids[7]])

    ubuntu.records[ids[7]] = ubuntuRecord(ids[7], { noble: ['not-affected'], jammy: ['released', '5.15.0-202.202'] })
    await run(HOUR)
    expect(deps.sink.closes.map((c) => [c.id, c.note.slice(0, 51)])).toEqual([[card.id, 'Ubuntu security fix out for 8 critical kernel bugs.']])
  })

  it('looks up at most the cap of new CVEs per run, newest first', async () => {
    await finishBaseline()
    const n = UBUNTU_LOOKUP_CAP + 5
    const ids = Array.from({ length: n }, (_, i) => `CVE-2025-${60000 + i}`)
    nvd.records = ids.map((id, i) => nvdRecord(id, 9.8, 'NETWORK', new Date(Date.parse('2023-10-29T00:00:00Z') + i * DAY).toISOString().slice(0, -1)))
    for (const id of ids) ubuntu.records[id] = ubuntuRecord(id, { noble: ['released', '6.8.0-60.60'], jammy: ['not-affected'] })
    expect(await run()).toMatchObject({ emitted: 0, skipped: UBUNTU_LOOKUP_CAP, deferred: 5 })
    expect(ubuntuLookups()).toEqual(ids.slice(5).reverse())
    deps.requests.length = 0
    expect(await run(HOUR)).toMatchObject({ skipped: 5, deferred: 0 })
    expect(ubuntuLookups()).toEqual(ids.slice(0, 5).reverse())
  })

  it('sends no token to NVD or Ubuntu and follows no redirect', async () => {
    await run()
    expect(deps.requests.length).toBeGreaterThan(1)
    for (const r of deps.requests) {
      expect(r.headers.get('authorization')).toBeNull()
      expect(r.redirect).toBe('error')
    }
  })

  it('is off unless watch.json turns it on', async () => {
    const report = await createAdvisoryWatch(parseWatchConfig({}), deps).run()
    expect(report).toMatchObject({ feeds: 0, read: 0 })
    expect(deps.requests).toEqual([])
  })
})

describe('the kernel feed, longer reads', () => {
  it('the first read gathers what it finds on one quiet card that grows; later finds page on their own card', async () => {
    const total = NVD_PAGE_SIZE * 4 + 100
    const ids = Array.from({ length: total }, (_, i) => `CVE-2026-${70000 + i}`)
    // Run 1 reads indexes 0-249 and 350-1099; run 2 reads 100-349.
    const critical = [10, 1099, 349]
    nvd.records = ids.map((id, i) => nvdRecord(id, critical.includes(i) ? 9.8 : 7.8, critical.includes(i) ? 'NETWORK' : 'LOCAL'))
    for (const i of critical) ubuntu.records[ids[i]] = ubuntuRecord(ids[i], PENDING)

    expect(await run()).toMatchObject({ emitted: 1, baselined: ['linux-kernel'] })
    expect(await run(HOUR)).toMatchObject({ emitted: 1, baselined: ['linux-kernel'] })
    expect(deps.sink.upserts.map((c) => [c.id, c.severity, c.ping, c.title])).toEqual([
      [kernelFirstReadCardKey(), 'warning', false, '2 critical kernel bugs with no Ubuntu security fix yet'],
      [kernelFirstReadCardKey(), 'warning', false, '3 critical kernel bugs with no Ubuntu security fix yet'],
    ])
    expect(kstate()?.through).toBe(NOW)

    deps.sink.clear()
    nvd.records = [nvdRecord('CVE-2026-99999')]
    ubuntu.records['CVE-2026-99999'] = ubuntuRecord('CVE-2026-99999', { noble: ['needed'], jammy: ['needed'] })
    await run(HOUR)
    expect(deps.sink.upserts.map((c) => [c.id, c.ping])).toEqual([[kernelCardKey(['CVE-2026-99999']), true]])
    expect(kstate()?.open?.map((o) => [o.key, o.members.length])).toEqual([
      [kernelFirstReadCardKey(), 3],
      [kernelCardKey(['CVE-2026-99999']), 1],
    ])
  })

  it('re-reads the CVEs on open cards in turn, at most the cap a run', async () => {
    await finishBaseline()
    const range = (n: number, from: number) => Array.from({ length: n }, (_, i) => `CVE-2026-${from + i}`)
    const a = range(30, 81000)
    const b = range(30, 82000)
    for (const id of [...a, ...b]) ubuntu.records[id] = ubuntuRecord(id, { noble: ['needed'], jammy: ['needed'] })
    nvd.records = a.map((id) => nvdRecord(id))
    await run()
    nvd.records = b.map((id) => nvdRecord(id))
    await run(HOUR)
    expect(kstate()?.open?.map((o) => o.members.length)).toEqual([30, 30])

    nvd.records = []
    deps.requests.length = 0
    await run(HOUR)
    expect(ubuntuLookups()).toEqual([...a, ...b.slice(0, 10)])
    // The ones left out are the longest unchecked now, so they go first.
    deps.requests.length = 0
    await run(HOUR)
    expect(ubuntuLookups()).toHaveLength(40)
    expect(ubuntuLookups().slice(0, 20)).toEqual(b.slice(10))
  })
})

describe('NVD and Ubuntu text on a card', () => {
  /** A record whose description, after NVD's boilerplate line, tries to hide a link. */
  function hostile(id: string) {
    const r = nvdRecord(id, 9.8, 'NETWORK', '2025-03-20T10:00:00.000')
    r.cve.descriptions = [
      { lang: 'en', value: 'In the Linux kernel, the following vulnerability has been resolved:\n\n[Download the official patch](https://evil.example/patch.exe) **now**\n\nDetails.' },
    ]
    r.cve.metrics.cvssMetricV31[0].cvssData.vectorString = 'CVSS:3.1/AV:N/[x](https://evil.example)'
    return r
  }

  it('cannot hide a link or format a card for one CVE', async () => {
    await finishBaseline()
    nvd.records = [hostile(TARGET)]
    ubuntu.records[TARGET] = ubuntuRecord(TARGET, { noble: ['pending', '[6.8.0](https://evil.example)'], jammy: ['deferred', '**2026-01-01**'] })
    expect(await run()).toMatchObject({ emitted: 1 })
    const body = deps.sink.upserts[0].body
    expect(body).not.toMatch(MASKED_LINK)
    expect(body).toMatch(/^\\\[Download the official patch\\\]\(https:\/\/evil\.example\/patch\.exe\) \\\*\\\*now\\\*\\\*\. /)
    expect(body).toContain('Ubuntu 24.04 (noble): pending \\[6.8.0\\](https://evil.example)')
    expect(body).toContain('Ubuntu 22.04 (jammy): deferred (\\*\\*2026-01-01\\*\\*)')
    expect(body).toContain('CVSS: 9.8 from the kernel CNA, CVSS:3.1/AV:N/\\[x\\](https://evil.example)')
  })

  it('cannot hide a link or format a card for several CVEs', async () => {
    await finishBaseline()
    const ids = ['CVE-2026-50005', 'CVE-2026-50006']
    nvd.records = ids.map(hostile)
    for (const id of ids) ubuntu.records[id] = ubuntuRecord(id, PENDING)
    expect(await run()).toMatchObject({ emitted: 1 })
    const body = deps.sink.upserts[0].body
    expect(body).not.toMatch(MASKED_LINK)
    for (const id of ids) expect(body).toContain(`${id}, 9.8: \\[Download the official patch\\](https://evil.example/patch.exe) \\*\\*now\\*\\*`)
  })
})
