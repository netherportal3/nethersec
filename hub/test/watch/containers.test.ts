import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CONTAINER_STATE_NAME, CONTAINER_UNREADABLE_KEY, containerCacheName, createContainerCheck, DETAIL_FETCH_CAP } from '../../src/watch/containers.js'
import {
  CONTAINER_RESEND_CAP,
  containerCardKey,
  containerCardText,
  cvssV3BaseScore,
  DETAIL_MAX_AGE_MS,
  DETAIL_REFRESH_MS,
  detailSeverity,
  imageTag,
  isFloatingTag,
  needsFetch,
  normalizeImage,
  osvEcosystemFor,
  parseOsvDetail,
  severityOfScore,
} from '../../src/watch/containerVulns.js'
import { parseWatchConfig } from '../../src/watch/config.js'
import { OSV_BATCH_URL, OSV_VULN_URL } from '../../src/watch/osv.js'
import type { ContainerPackagesRecord } from '../../src/watch/types.js'
import { makeHub } from '../hubHelpers.js'
import { advanceClock, checkCardText, DAY, fakeDeps, HOUR, json, MASKED_LINK, pinClock, stateOf, text, type FakeDeps } from './helpers.js'

const NOW = Date.parse('2025-03-28T12:00:00Z')
const CFG = parseWatchConfig({})

const V = {
  critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // 9.8
  critical91: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H', // 9.1
  high: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', // 8.1
  medium: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N', // 4.3
}

interface Aff {
  eco: string
  pkg: string
  fixed?: string
  urgency?: string
  availability?: string
}

/** An OSV record in the shape the Debian, Ubuntu and Alpine feeds use. */
function osvRecord(id: string, cve: string | null, affected: Aff[], o: { vector?: string; ubuntu?: string; modified?: string } = {}) {
  return {
    id,
    modified: o.modified ?? '2025-02-27T00:00:00Z',
    ...(cve ? { upstream: [cve] } : {}),
    severity: [...(o.vector ? [{ type: 'CVSS_V3', score: o.vector }] : []), ...(o.ubuntu ? [{ type: 'Ubuntu', score: o.ubuntu }] : [])],
    affected: affected.map((a) => ({
      package: { ecosystem: a.eco, name: a.pkg },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, ...(a.fixed ? [{ fixed: a.fixed }] : [])] }],
      ecosystem_specific: { ...(a.urgency ? { urgency: a.urgency } : {}), ...(a.availability ? { availability: a.availability } : {}) },
    })),
  }
}

const RECORDS: Record<string, unknown> = {
  'DSA-5724-1': osvRecord('DSA-5724-1', 'CVE-2024-6387', [{ eco: 'Debian:12', pkg: 'openssh', fixed: '1:9.2p1-2+deb12u3' }]),
  'DEBIAN-CVE-2024-6387': osvRecord('DEBIAN-CVE-2024-6387', 'CVE-2024-6387', [{ eco: 'Debian:12', pkg: 'openssh', fixed: '1:9.2p1-2+deb12u3' }], { vector: V.high }),
  'DEBIAN-CVE-2023-45853': osvRecord(
    'DEBIAN-CVE-2023-45853',
    'CVE-2023-45853',
    [
      { eco: 'Debian:12', pkg: 'zlib', urgency: 'unimportant' },
      { eco: 'Debian:12', pkg: 'minizip', fixed: '1.1-8+deb12u1' },
    ],
    { vector: V.critical },
  ),
  'DEBIAN-CVE-2026-11111': osvRecord('DEBIAN-CVE-2026-11111', 'CVE-2026-11111', [{ eco: 'Debian:12', pkg: 'curl', fixed: '7.88.1-10+deb12u9' }], { vector: V.medium }),
  'ALPINE-CVE-2024-5535': osvRecord('ALPINE-CVE-2024-5535', 'CVE-2024-5535', [{ eco: 'Alpine:v3.19', pkg: 'openssl', fixed: '3.1.6-r0' }], { vector: V.critical91 }),
  'UBUNTU-CVE-2024-13176': osvRecord('UBUNTU-CVE-2024-13176', 'CVE-2024-13176', [{ eco: 'Ubuntu:24.04:LTS', pkg: 'openssl', fixed: '3.0.13-0ubuntu3.5' }], {
    vector: V.medium,
    ubuntu: 'medium',
  }),
}

/** What OSV matches per `ecosystem|package|version`. */
const MATCHES: Record<string, string[]> = {
  'Debian:12|openssh|1:9.2p1-2+deb12u2': ['DSA-5724-1', 'DEBIAN-CVE-2024-6387'],
  'Debian:12|zlib|1:1.2.13.dfsg-1': ['DEBIAN-CVE-2023-45853'],
  'Debian:12|curl|7.88.1-10+deb12u5': ['DEBIAN-CVE-2026-11111'],
  'Alpine:v3.19|openssl|3.1.4-r5': ['ALPINE-CVE-2024-5535'],
}

type RecordInput = Omit<Partial<ContainerPackagesRecord>, 'packages'> & { box: string; container: string; image: string; packages: Array<[string, string]> }
function container(o: RecordInput): ContainerPackagesRecord {
  return {
    imageId: '1111aaaa2222',
    builtAt: Date.parse('2024-11-27T00:00:00Z'),
    os: 'debian',
    osVersion: '12',
    pm: 'dpkg',
    more: 0,
    receivedAt: Date.now(),
    ...o,
    packages: o.packages.map(([name, version]) => ({ name, version })),
  }
}

const WEB_PKGS: Array<[string, string]> = [
  ['openssh', '1:9.2p1-2+deb12u2'],
  ['zlib', '1:1.2.13.dfsg-1'],
  ['curl', '7.88.1-10+deb12u5'],
]
const web = (box = 'web1', pkgs = WEB_PKGS, extra: Omit<Partial<ContainerPackagesRecord>, 'packages'> = {}) =>
  container({ box, container: 'web', image: 'ghcr.io/example/web:1.4.2@sha256:9999aaaa', packages: pkgs, ...extra })
const proxy = (extra: Omit<Partial<ContainerPackagesRecord>, 'packages'> = {}) =>
  container({ box: 'web1', container: 'proxy', image: 'example/proxy:3.2-alpine', os: 'alpine', osVersion: '3.19.1', pm: 'apk', packages: [['openssl', '3.1.4-r5']], ...extra })

const WEB_KEY = containerCardKey('ghcr.io/example/web:1.4.2')
const PROXY_KEY = containerCardKey('example/proxy:3.2-alpine')

const osv = { down: false, failIds: new Set<string>(), split: new Set<string>(), batches: 0, gets: [] as string[] }
let deps: FakeDeps

beforeEach(() => {
  pinClock(NOW)
  osv.down = false
  osv.failIds.clear()
  osv.split.clear()
  osv.batches = 0
  osv.gets = []
  deps = fakeDeps(async (url, init) => {
    if (url === OSV_BATCH_URL && init?.method === 'POST') {
      osv.batches++
      if (osv.down) return text('unavailable', undefined, 503)
      const body = JSON.parse(String(init.body)) as { queries: Array<{ package: { ecosystem: string; name: string }; version: string; page_token?: string }> }
      return json({
        results: body.queries.map((q) => {
          const key = `${q.package.ecosystem}|${q.package.name}|${q.version}`
          const ids = MATCHES[key] ?? []
          const vulns = (i: string[]) => i.map((id) => ({ id, modified: (RECORDS[id] as { modified: string })?.modified ?? '2025-02-27T00:00:00Z' }))
          // A split query answers in two pages.
          if (osv.split.has(key) && ids.length > 1) {
            return q.page_token ? { vulns: vulns(ids.slice(1)) } : { vulns: vulns(ids.slice(0, 1)), next_page_token: 'page-2' }
          }
          return ids.length ? { vulns: vulns(ids) } : {}
        }),
      })
    }
    if (url.startsWith(OSV_VULN_URL)) {
      const id = decodeURIComponent(url.slice(OSV_VULN_URL.length))
      osv.gets.push(id)
      if (osv.down || osv.failIds.has(id)) return text('error', undefined, 500)
      return id in RECORDS ? json(RECORDS[id]) : null
    }
    return null
  })
})
afterEach(() => {
  vi.useRealTimers()
})

async function run(after = 0) {
  if (after) advanceClock(after)
  const report = await createContainerCheck(CFG, deps).run()
  checkCardText(deps.sink.upserts)
  return report
}

describe('CVSS and OSV records', () => {
  it('scores CVSS v3 vectors like the reference calculator', () => {
    expect(cvssV3BaseScore(V.critical)).toBe(9.8)
    expect(cvssV3BaseScore(V.high)).toBe(8.1)
    expect(cvssV3BaseScore(V.critical91)).toBe(9.1)
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')).toBe(7.5)
    expect(cvssV3BaseScore(V.medium)).toBe(4.3)
    expect(cvssV3BaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(6.1)
    expect(cvssV3BaseScore('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N')).toBe(3.8)
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(0)
    expect(cvssV3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull()
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L')).toBeNull()
    expect([9.8, 7, 6.9, 0.1, 0, null].map(severityOfScore)).toEqual(['critical', 'high', 'medium', 'low', 'none', 'unknown'])
  })

  it('reads a fix per package; Debian "unimportant" and an Ubuntu Pro-only fix are no fix', () => {
    const zlib = parseOsvDetail(RECORDS['DEBIAN-CVE-2023-45853'], ['Debian:12|zlib', 'Debian:12|minizip'], NOW)!
    expect(zlib).toMatchObject({ c: 'CVE-2023-45853', s: 9.8, x: { 'Debian:12|zlib': [], 'Debian:12|minizip': ['1.1-8+deb12u1'] } })
    expect(parseOsvDetail(RECORDS['DSA-5724-1'], ['Debian:12|openssh'], NOW)).toMatchObject({ c: 'CVE-2024-6387', s: null, x: { 'Debian:12|openssh': ['1:9.2p1-2+deb12u3'] } })
    expect(parseOsvDetail(RECORDS['ALPINE-CVE-2024-5535'], ['Alpine:v3.19|openssl'], NOW)).toMatchObject({ s: 9.1, x: { 'Alpine:v3.19|openssl': ['3.1.6-r0'] } })
    const PAIR = 'Ubuntu:24.04:LTS|openssl'
    const pro = osvRecord('UBUNTU-CVE-2026-2', 'CVE-2026-2', [{ eco: 'Ubuntu:24.04:LTS', pkg: 'openssl', fixed: '3.0.13-0ubuntu3.6', availability: 'Available with Ubuntu Pro' }])
    expect(parseOsvDetail(pro, [PAIR], NOW)!.x[PAIR]).toEqual([])
    expect(parseOsvDetail({ nope: true }, [PAIR], NOW)).toBeNull()
  })

  it("takes the distro's rating when it is higher, and never guesses without one", () => {
    const PAIR = 'Ubuntu:24.04:LTS|openssl'
    const ubu = parseOsvDetail(RECORDS['UBUNTU-CVE-2024-13176'], [PAIR], NOW)!
    expect(detailSeverity(ubu, PAIR)).toBe('medium')
    const high = osvRecord('UBUNTU-CVE-2026-3', 'CVE-2026-3', [{ eco: 'Ubuntu:24.04:LTS', pkg: 'openssl', fixed: '1' }], { vector: V.medium, ubuntu: 'high' })
    expect(detailSeverity(parseOsvDetail(high, [PAIR], NOW)!, PAIR)).toBe('high')
    const dsa = parseOsvDetail(RECORDS['DSA-5724-1'], ['Debian:12|openssh'], NOW)!
    expect(detailSeverity(dsa, 'Debian:12|openssh')).toBe('unknown')
    const urgent = osvRecord('DSA-1', null, [{ eco: 'Debian:12', pkg: 'openssh', fixed: '1', urgency: 'high' }])
    expect(detailSeverity(parseOsvDetail(urgent, ['Debian:12|openssh'], NOW)!, 'Debian:12|openssh')).toBe('high')
  })

  it('fetches a cached record again only when it must', () => {
    const d = parseOsvDetail(RECORDS['DEBIAN-CVE-2024-6387'], ['Debian:12|openssh'], NOW)!
    const m = '2025-02-27T00:00:00Z'
    expect(needsFetch(undefined, m, ['Debian:12|openssh'], NOW)).toBe(true)
    expect(needsFetch(d, m, ['Debian:12|openssh'], NOW + DAY)).toBe(false)
    expect(needsFetch(d, m, ['Debian:13|openssh'], NOW)).toBe(true)
    expect(needsFetch(d, 'changed', ['Debian:12|openssh'], NOW + DETAIL_REFRESH_MS - 1)).toBe(false)
    expect(needsFetch(d, 'changed', ['Debian:12|openssh'], NOW + DETAIL_REFRESH_MS)).toBe(true)
    expect(needsFetch(d, m, ['Debian:12|openssh'], NOW + DETAIL_MAX_AGE_MS)).toBe(true)
  })

  it('maps the OS to its OSV ecosystem, Debian, Ubuntu and Alpine only', () => {
    const eco = (os: string, osVersion: string, pm: 'dpkg' | 'apk' | 'none') => osvEcosystemFor({ os, osVersion, pm })
    expect(eco('debian', '12', 'dpkg')).toBe('Debian:12')
    expect(eco('debian', '12.7', 'dpkg')).toBe('Debian:12')
    expect(eco('ubuntu', '24.04', 'dpkg')).toBe('Ubuntu:24.04:LTS')
    expect(eco('ubuntu', '25.10', 'dpkg')).toBe('Ubuntu:25.10')
    expect(eco('alpine', '3.19.1', 'apk')).toBe('Alpine:v3.19')
    expect(eco('fedora', '40', 'dpkg')).toBeNull()
    expect(eco('debian', '', 'dpkg')).toBeNull()
    expect(eco('debian', '12', 'none')).toBeNull()
  })

  it('normalizes an image and knows a floating tag', () => {
    expect(normalizeImage('ghcr.io/example/web:1.4@sha256:9999')).toBe('ghcr.io/example/web:1.4')
    expect(normalizeImage('localhost:5000/web')).toBe('localhost:5000/web:latest')
    expect(imageTag('localhost:5000/web:latest')).toBe('latest')
    expect(['latest', '16', '3.2-alpine', 'bookworm-slim', 'local'].map(isFloatingTag)).toEqual([true, true, true, true, true])
    expect(['1.2.3-alpine', 'v4.0.0', '7.0.1-alpine'].map(isFloatingTag)).toEqual([false, false, false])
  })
})

describe('the container check', () => {
  it('cards a fixable high and a fixable critical once per image, quietly, and only counts the rest', async () => {
    deps.containers = [web(), proxy()]
    const report = await run()
    expect(report).toMatchObject({
      kind: 'containers',
      ok: true,
      containers: 2,
      evaluated: 2,
      incomplete: 0,
      queries: 4,
      vulns: 5,
      detailsFetched: 5,
      emitted: 2,
      fixable: { critical: 1, high: 1, medium: 1, low: 0, unknown: 0, unfixed: 1 },
      errors: [],
    })
    expect(deps.sink.upserts.map((c) => [c.id, c.severity, c.ping, c.title])).toEqual([
      [PROXY_KEY, 'warning', false, 'Critical CVE in openssl in container image example/proxy:3.2-alpine'],
      [WEB_KEY, 'warning', false, 'High CVE in openssh in container image ghcr.io/example/web:1.4.2'],
    ])
    const card = deps.sink.upserts[1]
    expect(card.url).toBe('https://security-tracker.debian.org/tracker/CVE-2024-6387')
    expect(card.body).toMatch(/^ghcr\.io\/example\/web:1\.4\.2 has 1 high or critical CVE in 1 package that Debian 12 has fixed\. The worst: CVE-2024-6387 \(high 8\.1\) in openssh\./)
    expect(card.body).toContain('If the image comes from upstream and upstream has no newer release, build it yourself on the updated base.')
    expect(card.body).toContain('\n\nRuns on:\nweb1: web\n\nFix:\nopenssh 1:9.2p1-2+deb12u2, fixed in 1:9.2p1-2+deb12u3: CVE-2024-6387 (high 8.1)\n\nImage built: 2024-11-27 (121 days ago)')
    expect(deps.sink.upserts[0].body).toContain('The tag "3.2-alpine" moves, so pulling it again may already bring the fixes.')

    // Nothing changed: no edit, and the cached records are not fetched again.
    deps.sink.clear()
    osv.gets = []
    expect(await run(HOUR)).toMatchObject({ emitted: 0, updated: 0, closed: 0, detailsFetched: 0, cardsTracked: 2 })
    expect(deps.sink.upserts).toEqual([])
    expect(osv.gets).toEqual([])
  })

  it('never closes a card on what the box reports: the fix, another image or the container gone marks it, and it waits for a person', async () => {
    const cache = (pkgs: Array<[string, string]> = [['openssh', '1:9.2p1-2+deb12u2']]) => container({ box: 'db1', container: 'cache', image: 'example/cache:2.0.0', packages: pkgs })
    const CACHE_KEY = containerCardKey('example/cache:2.0.0')
    deps.containers = [web(), proxy(), cache()]
    expect(await run()).toMatchObject({ emitted: 3 })
    deps.sink.clear()
    // web1 installs the fix, the proxy runs a new image, and db1 reports its cache gone.
    deps.containers = [web('web1', [['openssh', '1:9.2p1-2+deb12u3'], ...WEB_PKGS.slice(1)]), container({ box: 'web1', container: 'proxy', image: 'example/proxy:3.3-alpine', os: 'alpine', osVersion: '3.19.1', pm: 'apk', packages: [['openssl', '3.1.6-r0']] })]
    expect(await run(HOUR)).toMatchObject({ closed: 0, reportedFixed: 3, emitted: 0, cardsTracked: 0 })
    expect(deps.sink.closes).toEqual([])
    expect([...deps.sink.fixedMarks].sort((a, b) => a.id.localeCompare(b.id))).toEqual(
      [
        { id: WEB_KEY, note: 'The box now reports that 1 container runs the fixed packages.', wasOpen: true },
        { id: PROXY_KEY, note: 'The box now reports that 1 container no longer runs example/proxy:3.2-alpine.', wasOpen: true },
        { id: CACHE_KEY, note: 'The box now reports that 1 container is gone.', wasOpen: true },
      ].sort((a, b) => a.id.localeCompare(b.id)),
    )
    expect([...deps.sink.open.keys()].sort()).toEqual([CACHE_KEY, PROXY_KEY, WEB_KEY].sort())

    // Not sent again and not marked again, however long it waits: only a person closes it.
    deps.sink.clear()
    for (let i = 0; i < 4; i++) expect(await run(6 * HOUR)).toMatchObject({ emitted: 0, updated: 0, resent: 0, reportedFixed: 0, closed: 0 })
    expect(deps.sink.upserts).toEqual([])
    expect(deps.sink.fixedMarks).toEqual([])
    expect([...deps.sink.reportedFixed.keys()].sort()).toEqual([CACHE_KEY, PROXY_KEY, WEB_KEY].sort())
  })

  it('a mark the sink could not take is tried again next run', async () => {
    deps.containers = [web()]
    await run()
    deps.containers = [web('web1', [['openssh', '1:9.2p1-2+deb12u3']])]
    deps.sink.accept = false
    expect(await run(HOUR)).toMatchObject({ reportedFixed: 0, closed: 0, cardsTracked: 1 })
    deps.sink.accept = true
    expect(await run(HOUR)).toMatchObject({ reportedFixed: 1, cardsTracked: 0 })
    expect(deps.sink.reportedFixed.get(WEB_KEY)).toBe('The box now reports that 1 container runs the fixed packages.')
  })

  it('on the hub cards: the card says the box reports the fix, a gap again edits it back, and only Resolve closes it', async () => {
    // The real hub cards with a fake Discord, so the mark, Resolve and the new card are the hub's own.
    const hub = await makeHub()
    const hubDeps: FakeDeps = { ...deps, cards: hub.ops }
    const hubRun = (after = 0) => {
      if (after) advanceClock(after)
      return createContainerCheck(CFG, hubDeps).run()
    }
    const key = `watch:${WEB_KEY}`
    const status = (i = -1) => hub.discord.edits.at(i)!.payload.embeds[0].fields!.find((f) => f.name === 'Status')?.value ?? ''
    const fixed: Array<[string, string]> = [['openssh', '1:9.2p1-2+deb12u3'], ...WEB_PKGS.slice(1)]

    deps.containers = [web()]
    expect(await hubRun()).toMatchObject({ emitted: 1 })
    expect(hub.discord.sent[0].payload.embeds[0].description).toContain(
      'When the boxes report that every container listed runs the fixes, this card says so and waits for you to press Resolve. If you resolve it before that, it opens again within about 6 hours.',
    )
    const first = hub.ops.findOpen(key)!

    // The box reports the fix: the card says so and stays open.
    deps.containers = [web('web1', fixed)]
    expect(await hubRun(HOUR)).toMatchObject({ reportedFixed: 1, closed: 0 })
    expect(hub.ops.findOpen(key)).toMatchObject({ id: first.id, reportedFixedNote: 'The box now reports that 1 container runs the fixed packages.' })
    expect(hub.ops.findOpen(key)!.reportedFixedAt).toBeDefined()
    expect(hub.discord.edits.at(-1)!.payload.embeds[0].title).toBe('Warning: High CVE in openssh in container image ghcr.io/example/web:1.4.2')
    expect(status()).toMatch(/^The box now reports that 1 container runs the fixed packages\. Reported <t:\d+:R>\. Press Resolve once you have checked it\.$/)

    // It is not sent again.
    const edits = hub.discord.edits.length
    for (let i = 0; i < 3; i++) await hubRun(6 * HOUR)
    expect(hub.discord.sent).toHaveLength(1)
    expect(hub.discord.edits).toHaveLength(edits)

    // The gap is back before anyone resolved it: the open card is edited back and the mark goes.
    deps.containers = [web()]
    expect(await hubRun(HOUR)).toMatchObject({ emitted: 1, cardsTracked: 1 })
    expect(hub.discord.sent).toHaveLength(1)
    expect(hub.ops.findOpen(key)).toMatchObject({ id: first.id, reportedFixedAt: undefined, reportedFixedNote: undefined })
    expect(status()).toBe('')
    // ...and it is tracked and sent again on the 6-hour timer, as before (open and unchanged: no edit).
    const before = hub.discord.edits.length
    expect(await hubRun(6 * HOUR)).toMatchObject({ resent: 1 })
    expect(hub.discord.edits).toHaveLength(before)
    const second = hub.ops.findOpen(key)!
    expect(second.id).toBe(first.id)

    // Fixed again, then a person presses Resolve: that closes it.
    deps.containers = [web('web1', fixed)]
    expect(await hubRun(HOUR)).toMatchObject({ reportedFixed: 1 })
    expect(hub.ops.findOpen(key)!.id).toBe(second.id)
    expect((await hub.ops.press('resolve', second.id, '7'.repeat(18))).ok).toBe(true)
    expect(hub.ops.findOpen(key)).toBeUndefined()
    await hubRun(6 * HOUR)
    expect(hub.ops.findOpen(key)).toBeUndefined()

    // A later gap in the image opens a new card.
    deps.containers = [web()]
    expect(await hubRun(HOUR)).toMatchObject({ emitted: 1 })
    expect(hub.discord.sent).toHaveLength(2)
    expect(hub.ops.findOpen(key)!.id).not.toBe(second.id)
  })

  it('a second box with the same gap joins the card, which is edited in place once and waits for both', async () => {
    deps.containers = [web()]
    await run()
    deps.sink.clear()
    deps.containers = [web(), web('web2')]
    expect(await run(HOUR)).toMatchObject({ emitted: 0, updated: 1 })
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([WEB_KEY])
    expect(deps.sink.upserts[0].body).toContain('Runs on:\nweb1: web\nweb2: web')
    expect(await run(HOUR)).toMatchObject({ updated: 0 })

    deps.containers = [web('web1', [['openssh', '1:9.2p1-2+deb12u3']]), web('web2')]
    expect(await run(HOUR)).toMatchObject({ closed: 0, reportedFixed: 0 })
    deps.containers = [web('web1', [['openssh', '1:9.2p1-2+deb12u3']]), web('web2', [['openssh', '1:9.2p1-2+deb12u3']])]
    expect(await run(HOUR)).toMatchObject({ closed: 0, reportedFixed: 1 })
    expect(deps.sink.fixedMarks).toEqual([{ id: WEB_KEY, note: 'The boxes now report that 2 containers run the fixed packages.', wasOpen: true }])
  })

  it('an edit the sink could not take is sent again next run', async () => {
    deps.containers = [web()]
    await run()
    deps.containers = [web(), web('web2')]
    deps.sink.accept = false
    expect(await run(HOUR)).toMatchObject({ updated: 0 })
    deps.sink.accept = true
    deps.sink.clear()
    expect(await run(HOUR)).toMatchObject({ updated: 1 })
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([WEB_KEY])
  })

  it('never closes on a stale box or a record it cannot read', async () => {
    deps.containers = [web()]
    await run()
    deps.sink.clear()
    // Fixed, but the report is four days old.
    deps.containers = [web('web1', [['openssh', '1:9.2p1-2+deb12u3']], { receivedAt: Date.now() - 4 * DAY })]
    expect(await run(HOUR)).toMatchObject({ closed: 0, stale: 1 })
    // Listed, but not a usable record.
    deps.containers = [{ box: 'web1', container: 'web', image: 'ghcr.io/example/web:1.4.2', packages: 'broken' } as unknown as ContainerPackagesRecord]
    const report = await run(HOUR)
    expect(report).toMatchObject({ closed: 0, reportedFixed: 0, unsupported: ['web1/web (record not readable)'] })
    expect(deps.sink.closes).toEqual([])
    expect(deps.sink.fixedMarks).toEqual([])
  })

  it('a stale box opens no new card', async () => {
    deps.containers = [web('web1', WEB_PKGS, { receivedAt: Date.now() - 4 * DAY })]
    expect(await run()).toMatchObject({ emitted: 0, stale: 1, evaluated: 1 })
  })

  it('an OSV outage changes nothing, and a day of them cards once until a run gets through', async () => {
    deps.containers = [web()]
    await run()
    deps.sink.clear()
    osv.down = true
    for (let i = 0; i < 24; i++) {
      const r = await run(HOUR)
      expect(r).toMatchObject({ ok: false, errors: ['OSV could not be read'] })
    }
    expect(deps.sink.upserts).toEqual([])
    expect(deps.sink.closes).toEqual([])
    await run(HOUR)
    expect(deps.sink.upserts.map((c) => [c.id, c.severity, c.title])).toEqual([[CONTAINER_UNREADABLE_KEY, 'warning', "Can't check container packages"]])
    expect(deps.sink.upserts[0].body).toMatch(/not got through since 2025-03-28 13:00 UTC \(25 runs\).*It is not a clean bill of health\./)
    expect(deps.logs).toContain('container check: OSV could not be read')
    await run(HOUR)
    expect(deps.sink.upserts).toHaveLength(1)

    // A person resolved it while OSV is still down: it is sent again 6 hours after it was.
    deps.sink.open.delete(CONTAINER_UNREADABLE_KEY)
    for (let i = 0; i < 4; i++) expect(await run(HOUR)).toMatchObject({ resent: 0 })
    expect(await run(HOUR)).toMatchObject({ resent: 1 })
    expect(deps.sink.upserts.map((c) => c.id)).toEqual([CONTAINER_UNREADABLE_KEY, CONTAINER_UNREADABLE_KEY])
    expect(deps.sink.upserts[1].body).toContain('(31 runs)')
    expect(deps.sink.upserts[1].body).toContain('If you resolve it before that, it opens again within about 6 hours.')

    osv.down = false
    expect(await run(HOUR)).toMatchObject({ ok: true, closed: 1, emitted: 0 })
    expect(deps.sink.closes.map((c) => c.id)).toEqual([CONTAINER_UNREADABLE_KEY])
    expect(stateOf<Record<string, unknown>>(deps, CONTAINER_STATE_NAME)).not.toHaveProperty('unreadableSentAt')
    expect(deps.sink.open.has(WEB_KEY)).toBe(true)
  })

  it('a package list the hub cannot read is a failed run, not an empty one', async () => {
    deps.containers = [web()]
    await run()
    deps.listContainerPackages = () => {
      throw new Error('store down')
    }
    expect(await run(HOUR)).toMatchObject({ ok: false, closed: 0, errors: ['the container package lists could not be read'] })
    expect(stateOf<{ fails: number; cards: unknown[] }>(deps, CONTAINER_STATE_NAME)).toMatchObject({ fails: 1, cards: [expect.anything()] })
  })

  it('a record that does not read stays unchecked and is fetched again next run', async () => {
    deps.containers = [web()]
    osv.failIds.add('DEBIAN-CVE-2024-6387')
    osv.failIds.add('DSA-5724-1')
    expect(await run()).toMatchObject({ emitted: 0, evaluated: 0, incomplete: 1, detailsFailed: 2 })
    osv.failIds.clear()
    expect(await run(HOUR)).toMatchObject({ emitted: 1, evaluated: 1, detailsFetched: 2 })
  })

  it('sends an unchanged open card again every 6 hours, so one a person resolved opens again', async () => {
    deps.containers = [web()]
    await run()
    deps.sink.clear()
    // A person resolved it in Discord: the hub has no open card with this id now.
    deps.sink.open.delete(WEB_KEY)
    expect(await run(5 * HOUR)).toMatchObject({ resent: 0, updated: 0 })
    expect(deps.sink.upserts).toEqual([])
    expect(await run(HOUR)).toMatchObject({ resent: 1, emitted: 0, updated: 0, cardsTracked: 1 })
    expect(deps.sink.upserts.map((c) => [c.id, c.severity, c.ping])).toEqual([[WEB_KEY, 'warning', false]])
    expect(deps.sink.upserts[0].body).toContain('If you resolve it before that, it opens again within about 6 hours.')
    expect(deps.sink.open.has(WEB_KEY)).toBe(true)
    // The next one waits another 6 hours.
    deps.sink.clear()
    expect(await run(5 * HOUR)).toMatchObject({ resent: 0 })
    expect(await run(HOUR)).toMatchObject({ resent: 1 })
    // A send that did not go out is tried again next run.
    deps.sink.accept = false
    expect(await run(6 * HOUR)).toMatchObject({ resent: 0 })
    deps.sink.accept = true
    expect(await run(HOUR)).toMatchObject({ resent: 1 })
  })

  it(`sends at most ${CONTAINER_RESEND_CAP} unchanged cards again per run, the longest unsent first`, async () => {
    const n = CONTAINER_RESEND_CAP + 5
    deps.containers = Array.from({ length: n }, (_, i) => container({ box: 'web1', container: `c${i}`, image: `example/app${i}:1.0.0`, packages: [['openssh', '1:9.2p1-2+deb12u2']] }))
    let emitted = (await run()).emitted
    while (emitted < n) emitted += (await run(HOUR)).emitted
    deps.sink.clear()
    expect(await run(6 * HOUR)).toMatchObject({ resent: CONTAINER_RESEND_CAP, emitted: 0 })
    expect(await run(HOUR)).toMatchObject({ resent: 5 })
    expect(new Set(deps.sink.upserts.map((c) => c.id)).size).toBe(n)
  })

  it('caps new cards per run and cards the rest next run', async () => {
    deps.containers = Array.from({ length: 8 }, (_, i) => container({ box: 'web1', container: `c${i}`, image: `example/app${i}:1.0.0`, packages: [['openssh', '1:9.2p1-2+deb12u2']] }))
    expect(await run()).toMatchObject({ emitted: 6, deferred: 2 })
    expect(await run(HOUR)).toMatchObject({ emitted: 2, deferred: 0 })
    expect(new Set(deps.sink.upserts.map((c) => c.id)).size).toBe(8)
  })

  it('names the containers it cannot check', async () => {
    deps.containers = [
      container({ box: 'db1', container: 'pg', image: 'example/pg:16', os: 'fedora', osVersion: '40', packages: [['glibc', '2.39']] }),
      container({ box: 'db1', container: 'static', image: 'example/static:1.0.0', os: '', osVersion: '', pm: 'none', packages: [] }),
    ]
    expect(await run()).toMatchObject({ ok: true, unsupported: ['db1/pg fedora 40 (not checked)', 'db1/static unknown OS (no package database)'], queries: 0 })
    expect(osv.batches).toBe(0)
  })

  it('reads every page of a query OSV pages', async () => {
    osv.split.add('Debian:12|openssh|1:9.2p1-2+deb12u2')
    deps.containers = [web()]
    expect(await run()).toMatchObject({ emitted: 1, vulns: 4 })
    expect(osv.batches).toBe(2)
  })

  it('keeps the OSV record cache across runs, split under the size cap', async () => {
    deps.containers = [web(), proxy()]
    await run()
    const cached = [0, 1, 2, 3].flatMap((n) => Object.keys(stateOf<{ e: Record<string, unknown> }>(deps, containerCacheName(n))?.e ?? {}))
    expect(cached.sort()).toEqual(Object.keys(RECORDS).filter((id) => !id.startsWith('UBUNTU')).sort())
    expect(DETAIL_FETCH_CAP).toBeGreaterThan(0)
  })

  it('a state that cannot be read skips the run and sends nothing', async () => {
    deps.containers = [web()]
    deps.failLoad.add(CONTAINER_STATE_NAME)
    expect(await run()).toMatchObject({ ok: false, emitted: 0, errors: ['the state could not be read; skipping this run'] })
    expect(osv.batches).toBe(0)
  })

  it('reads nothing when watch.json turns it off', async () => {
    deps.containers = [web()]
    const report = await createContainerCheck(parseWatchConfig({ containers: { enabled: false } }), deps).run()
    expect(report).toMatchObject({ ok: true, disabled: true, containers: 0 })
    expect(deps.requests).toEqual([])
  })
})

describe('the container check, edits', () => {
  it('a new fix on an open card edits it in place, once', async () => {
    deps.containers = [web()]
    await run()
    deps.sink.clear()
    MATCHES['Debian:12|curl|7.88.1-10+deb12u5'] = ['DEBIAN-CVE-2026-11111', 'DEBIAN-CVE-2026-22222']
    RECORDS['DEBIAN-CVE-2026-22222'] = osvRecord('DEBIAN-CVE-2026-22222', 'CVE-2026-22222', [{ eco: 'Debian:12', pkg: 'curl', fixed: '7.88.1-10+deb12u9' }], { vector: V.critical })
    try {
      expect(await run(HOUR)).toMatchObject({ emitted: 0, updated: 1 })
      expect(deps.sink.upserts.map((c) => [c.id, c.title])).toEqual([[WEB_KEY, 'Critical CVEs in 2 packages in container image ghcr.io/example/web:1.4.2']])
      expect(deps.sink.upserts[0].body).toContain('Fixes:\ncurl 7.88.1-10+deb12u5, fixed in 7.88.1-10+deb12u9: CVE-2026-22222 (critical 9.8)\nopenssh')
      expect(await run(HOUR)).toMatchObject({ updated: 0 })
    } finally {
      MATCHES['Debian:12|curl|7.88.1-10+deb12u5'] = ['DEBIAN-CVE-2026-11111']
      delete RECORDS['DEBIAN-CVE-2026-22222']
    }
  })
})

describe('box and OSV text on a card', () => {
  it('names a box reports cannot format the card, here or in the note when it moves', async () => {
    const odd = (image: string) => container({ box: 'web1', container: 'web__x__', image, packages: [['openssh', '1:9.2p1-2+deb12u2']] })
    deps.containers = [odd('ghcr.io/example/web__x__:1.4.2')]
    expect(await run()).toMatchObject({ emitted: 1 })
    const body = deps.sink.upserts[0].body
    expect(body).toMatch(/^ghcr\.io\/example\/web\\_\\_x\\_\\_:1\.4\.2 has 1 high/)
    expect(body).toContain('Runs on:\nweb1: web\\_\\_x\\_\\_\n')
    expect(body).not.toMatch(/(?<!\\)_/)
    // The box now runs another image: the note names the old one, escaped too.
    deps.containers = [odd('example/other:1.0.0')]
    await run(HOUR)
    expect(deps.sink.fixedMarks.map((m) => m.note)).toEqual(['The box now reports that 1 container no longer runs ghcr.io/example/web\\_\\_x\\_\\_:1.4.2.'])
  })

  it('escapes what a box cannot send today all the same, so the card never rests on the report rules', () => {
    const link = (s: string) => `[${s}](https://evil.example)`
    const t = containerCardText(
      [
        {
          field: 'web1/x',
          box: 'web1',
          container: link('a'),
          image: `${link('b')}:latest`,
          builtAt: null,
          ecosystem: 'Debian:12',
          pkg: link('c'),
          installed: link('d'),
          fixed: [link('e')],
          cves: [{ id: link('f'), osvId: 'X-1', score: 9.8, severity: 'critical' }],
          severity: 'critical',
        },
      ],
      NOW,
    )
    expect(t.body).not.toMatch(MASKED_LINK)
    for (const s of 'abcdef') expect(t.body).toContain(`\\[${s}\\]`)
  })
})
