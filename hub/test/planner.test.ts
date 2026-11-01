import { describe, expect, it } from 'vitest'
import { activeRepos, CARD_CAP, countOpen, DROPPED_TTL_MS, planScan, shouldPing } from '../src/planner.js'
import type { RepoState } from '../src/state.js'
import { finding, okRepo, scanOf, settings } from './helpers.js'

const NOW = '2025-02-27T00:00:00.000Z'

function baselined(...repos: Array<[string, ReturnType<typeof finding>[]]>): Record<string, RepoState> {
  const first = planScan({ scan: scanOf(repos.map(([r, f]) => okRepo(r, f))), repos: {}, settings: settings(), mutes: [], now: NOW })
  return first.nextRepos
}

describe('baseline', () => {
  it('records what is open on first read and alerts nothing', () => {
    const plan = planScan({
      scan: scanOf([okRepo('me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1', severity: 'critical' })]), okRepo('me/b', [])]),
      repos: {},
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(plan.alerts).toEqual([])
    expect(plan.baselined.map((b) => b.repo)).toEqual(['me/a', 'me/b'])
    expect(plan.nextRepos['me/a'].baselined).toEqual({ npm: true, PyPI: true })
    expect(Object.keys(plan.nextRepos['me/a'].findings)).toEqual(['GHSA-1:pkg'])
  })

  it('malware still gets a card during a baseline, unless muted', () => {
    const plan = planScan({
      scan: scanOf([
        okRepo('me/a', [
          finding({ repo: 'me/a', advisoryId: 'GHSA-old', severity: 'critical' }),
          finding({ repo: 'me/a', advisoryId: 'MAL-1', severity: 'low', malware: true }),
          finding({ repo: 'me/a', advisoryId: 'MAL-2', severity: 'low', malware: true }),
        ]),
      ]),
      repos: {},
      settings: settings(),
      mutes: [{ advisoryId: 'MAL-2', repo: null, by: 'u', at: NOW }],
      now: NOW,
    })
    expect(plan.alerts.map((g) => g.advisoryId)).toEqual(['MAL-1'])
    expect(plan.baselined[0].findings).toHaveLength(3)
  })

  it('an ecosystem whose source was down at the first read is baselined later, not flooded', () => {
    const py = (id: string) => finding({ repo: 'me/a', advisoryId: id, ecosystem: 'PyPI', severity: 'critical' })
    const one = planScan({ scan: scanOf([okRepo('me/a', [])], { npm: true, PyPI: false }), repos: {}, settings: settings(), mutes: [], now: NOW })
    expect(one.nextRepos['me/a'].baselined).toEqual({ npm: true })

    const two = planScan({ scan: scanOf([okRepo('me/a', [py('PY-old')])]), repos: one.nextRepos, settings: settings(), mutes: [], now: NOW })
    expect(two.alerts).toEqual([])
    expect(two.baselined).toEqual([{ repo: 'me/a', findings: [expect.objectContaining({ advisoryId: 'PY-old' })] }])
    expect(two.nextRepos['me/a'].baselined).toEqual({ npm: true, PyPI: true })

    const three = planScan({
      scan: scanOf([okRepo('me/a', [py('PY-old'), py('PY-new')])]),
      repos: two.nextRepos,
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(three.alerts.map((g) => g.advisoryId)).toEqual(['PY-new'])
    expect(three.baselined).toEqual([])
  })
})

describe('new advisories', () => {
  it('alerts a new advisory at or above the threshold; records one below it silently', () => {
    const repos = baselined(['me/a', []])
    const plan = planScan({
      scan: scanOf([
        okRepo('me/a', [
          finding({ repo: 'me/a', advisoryId: 'GHSA-high', severity: 'high' }),
          finding({ repo: 'me/a', advisoryId: 'GHSA-mod', severity: 'moderate' }),
        ]),
      ]),
      repos,
      settings: settings({ minSeverity: 'high' }),
      mutes: [],
      now: NOW,
    })
    expect(plan.alerts.map((g) => g.advisoryId)).toEqual(['GHSA-high'])
    expect(Object.keys(plan.nextRepos['me/a'].findings).sort()).toEqual(['GHSA-high:pkg', 'GHSA-mod:pkg'])
  })

  it('does not alert the same advisory twice', () => {
    const repos = baselined(['me/a', []])
    const f = finding({ repo: 'me/a', advisoryId: 'GHSA-1' })
    const one = planScan({ scan: scanOf([okRepo('me/a', [f])]), repos, settings: settings(), mutes: [], now: NOW })
    expect(one.alerts).toHaveLength(1)
    one.nextRepos['me/a'].findings['GHSA-1:pkg'].cardId = 'card1'
    const two = planScan({ scan: scanOf([okRepo('me/a', [f])]), repos: one.nextRepos, settings: settings(), mutes: [], now: NOW })
    expect(two.alerts).toEqual([])
    expect(two.nextRepos['me/a'].findings['GHSA-1:pkg'].cardId).toBe('card1')
  })

  it('alerts when a known advisory rises to the threshold', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1', severity: 'moderate' })]])
    const plan = planScan({
      scan: scanOf([okRepo('me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1', severity: 'critical' })])]),
      repos,
      settings: settings(),
      mutes: [],
      now: '2025-02-28T00:00:00.000Z',
    })
    expect(plan.alerts.map((g) => g.severity)).toEqual(['critical'])
    expect(plan.nextRepos['me/a'].findings['GHSA-1:pkg'].firstSeen).toBe(NOW)
  })

  it('lowering the threshold does not alert advisories already on record', () => {
    const repos = baselined(['me/a', []])
    const f = finding({ repo: 'me/a', advisoryId: 'GHSA-1', severity: 'moderate' })
    const one = planScan({ scan: scanOf([okRepo('me/a', [f])]), repos, settings: settings({ minSeverity: 'high' }), mutes: [], now: NOW })
    const two = planScan({ scan: scanOf([okRepo('me/a', [f])]), repos: one.nextRepos, settings: settings({ minSeverity: 'moderate' }), mutes: [], now: NOW })
    expect(two.alerts).toEqual([])
  })

  it('a muted advisory is recorded but not alerted; malware alerts below the threshold', () => {
    const repos = baselined(['me/a', []], ['me/b', []])
    const plan = planScan({
      scan: scanOf([
        okRepo('me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1' }), finding({ repo: 'me/a', advisoryId: 'GHSA-evil', severity: 'low', malware: true })]),
        okRepo('me/b', [finding({ repo: 'me/b', advisoryId: 'GHSA-1' })]),
      ]),
      repos,
      settings: settings({ minSeverity: 'critical' }),
      mutes: [{ advisoryId: 'GHSA-1', repo: 'ME/A', by: 'u', at: NOW }],
      now: NOW,
    })
    expect(plan.alerts.map((g) => g.advisoryId)).toEqual(['GHSA-evil'])
    expect(plan.nextRepos['me/a'].findings['GHSA-1:pkg']).toBeDefined()
  })

  it('a mute by CVE covers the advisory that carries it', () => {
    const repos = baselined(['me/a', []])
    const plan = planScan({
      scan: scanOf([
        okRepo('me/a', [
          finding({ repo: 'me/a', advisoryId: 'GHSA-1', cveId: 'CVE-2026-1111' }),
          finding({ repo: 'me/a', advisoryId: 'GHSA-2', cveId: 'CVE-2026-2222' }),
        ]),
      ]),
      repos,
      settings: settings(),
      mutes: [{ advisoryId: 'CVE-2026-1111', repo: null, by: 'u', at: NOW }],
      now: NOW,
    })
    expect(plan.alerts.map((g) => g.advisoryId)).toEqual(['GHSA-2'])
  })

  it('one card per advisory across repos, ordered malware, severity, reach', () => {
    const repos = baselined(['me/a', []], ['me/b', []], ['me/c', []])
    const plan = planScan({
      scan: scanOf([
        okRepo('me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-h', severity: 'high' }), finding({ repo: 'me/a', advisoryId: 'GHSA-c', severity: 'critical' })]),
        okRepo('me/b', [finding({ repo: 'me/b', advisoryId: 'GHSA-h', severity: 'high' })]),
        okRepo('me/c', [finding({ repo: 'me/c', advisoryId: 'GHSA-m', severity: 'low', malware: true })]),
      ]),
      repos,
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(plan.alerts.map((g) => [g.advisoryId, g.members.map((m) => m.repo), g.channel])).toEqual([
      ['GHSA-m', ['me/c'], 'critical'],
      ['GHSA-c', ['me/a'], 'critical'],
      ['GHSA-h', ['me/a', 'me/b'], 'alerts'],
    ])
  })

  it('caps cards per scan and lists the rest as overflow, still recorded', () => {
    const repos = baselined(['me/a', []])
    const many = Array.from({ length: CARD_CAP + 3 }, (_, i) => finding({ repo: 'me/a', advisoryId: `GHSA-${i}` }))
    const plan = planScan({ scan: scanOf([okRepo('me/a', many)]), repos, settings: settings(), mutes: [], now: NOW })
    expect(plan.alerts).toHaveLength(CARD_CAP)
    expect(plan.overflow).toHaveLength(3)
    expect(Object.keys(plan.nextRepos['me/a'].findings)).toHaveLength(CARD_CAP + 3)
  })
})

describe('fixed, unreadable and failed sources', () => {
  it('an advisory gone from a readable repo is fixed', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1' })]])
    const plan = planScan({ scan: scanOf([okRepo('me/a', [])]), repos, settings: settings(), mutes: [], now: NOW })
    expect(plan.fixed.map((f) => [f.repo, f.key])).toEqual([['me/a', 'GHSA-1:pkg']])
    expect(plan.nextRepos['me/a'].findings).toEqual({})
  })

  it('an unreadable repo keeps what it had, and is reported once after two scans in a row', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1' })]])
    const bad = scanOf([{ repo: 'me/a', status: 'unreadable', reason: 'GitHub returned 404.', lockfiles: [], skipped: [], treeTruncated: false, findings: [] }])
    const one = planScan({ scan: bad, repos, settings: settings(), mutes: [], now: NOW })
    expect(one.fixed).toEqual([])
    expect(one.unreadableNotices).toEqual([])
    expect(one.nextRepos['me/a'].findings['GHSA-1:pkg']).toBeDefined()
    const two = planScan({ scan: bad, repos: one.nextRepos, settings: settings(), mutes: [], now: NOW })
    expect(two.unreadableNotices).toEqual([{ repo: 'me/a', reason: 'GitHub returned 404.' }])
    const three = planScan({ scan: bad, repos: two.nextRepos, settings: settings(), mutes: [], now: NOW })
    expect(three.unreadableNotices).toEqual([])
    const back = planScan({ scan: scanOf([okRepo('me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1' })])]), repos: three.nextRepos, settings: settings(), mutes: [], now: NOW })
    expect(back.recovered).toEqual(['me/a'])
    expect(back.alerts).toEqual([])
  })

  it('a repo the scan did not reach keeps its state untouched', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1' })]])
    const plan = planScan({
      scan: scanOf([{ repo: 'me/a', status: 'not-reached', lockfiles: [], skipped: [], treeTruncated: false, findings: [] }]),
      repos,
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(plan.nextRepos['me/a']).toBe(repos['me/a'])
    expect(plan.fixed).toEqual([])
  })

  it('a failed advisory source keeps that ecosystem as it was: nothing new, nothing fixed', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-py', ecosystem: 'PyPI' })]])
    const plan = planScan({
      scan: scanOf([okRepo('me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-npm' })])], { npm: true, PyPI: false }),
      repos,
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(plan.fixed).toEqual([])
    expect(Object.keys(plan.nextRepos['me/a'].findings).sort()).toEqual(['GHSA-npm:pkg', 'GHSA-py:pkg'])
  })

  it('a finding in a lockfile that was skipped this scan is kept, not fixed', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1' })]])
    const skipped = { ...okRepo('me/a', []), lockfiles: [], skipped: [{ path: 'package-lock.json', reason: 'too big' }] }
    const plan = planScan({ scan: scanOf([skipped]), repos, settings: settings(), mutes: [], now: NOW })
    expect(plan.fixed).toEqual([])
    expect(plan.nextRepos['me/a'].findings['GHSA-1:pkg']).toBeDefined()
  })

  it('a finding is kept, not fixed, when the repo tree came back truncated', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1' })]])
    const plan = planScan({ scan: scanOf([{ ...okRepo('me/a', []), treeTruncated: true }]), repos, settings: settings(), mutes: [], now: NOW })
    expect(plan.fixed).toEqual([])
    expect(plan.nextRepos['me/a'].findings['GHSA-1:pkg']).toBeDefined()
  })

  it('a repo no longer scanned is reported once, kept for a while, then forgotten', () => {
    const repos = baselined(['me/a', []], ['me/gone', [finding({ repo: 'me/gone', advisoryId: 'GHSA-1', severity: 'critical' })]])
    const one = planScan({ scan: scanOf([okRepo('me/a', [])]), repos, settings: settings(), mutes: [], now: NOW })
    expect(one.dropped).toEqual(['me/gone'])
    expect(one.fixed).toEqual([])
    expect(one.nextRepos['me/gone']).toMatchObject({ droppedAt: NOW })
    expect(countOpen(one.nextRepos).critical).toBe(0)
    expect(activeRepos(one.nextRepos).map((r) => r.name)).toEqual(['me/a'])

    const two = planScan({ scan: scanOf([okRepo('me/a', [])]), repos: one.nextRepos, settings: settings(), mutes: [], now: '2025-03-18T00:00:00.000Z' })
    expect(two.dropped).toEqual([])
    expect(two.nextRepos['me/gone']).toMatchObject({ droppedAt: NOW })

    const later = new Date(Date.parse(NOW) + DROPPED_TTL_MS + 1000).toISOString()
    const three = planScan({ scan: scanOf([okRepo('me/a', [])]), repos: two.nextRepos, settings: settings(), mutes: [], now: later })
    expect(three.nextRepos['me/gone']).toBeUndefined()
  })

  it('a dropped repo that comes back alerts new advisories instead of baselining again', () => {
    const repos = baselined(['me/a', []], ['me/gone', []])
    const one = planScan({ scan: scanOf([okRepo('me/a', [])]), repos, settings: settings(), mutes: [], now: NOW })
    const back = planScan({
      scan: scanOf([okRepo('me/a', []), okRepo('me/gone', [finding({ repo: 'me/gone', advisoryId: 'GHSA-new' })])]),
      repos: one.nextRepos,
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(back.alerts.map((g) => g.advisoryId)).toEqual(['GHSA-new'])
    expect(back.baselined).toEqual([])
    expect(back.nextRepos['me/gone'].droppedAt).toBeUndefined()
  })

  it('a dropped repo that comes back but is not reached keeps what it had', () => {
    const repos = baselined(['me/gone', [finding({ repo: 'me/gone', advisoryId: 'GHSA-1' })]])
    const one = planScan({ scan: scanOf([]), repos, settings: settings(), mutes: [], now: NOW })
    expect(one.nextRepos['me/gone'].droppedAt).toBe(NOW)
    const two = planScan({
      scan: scanOf([{ repo: 'me/gone', status: 'not-reached', lockfiles: [], skipped: [], treeTruncated: false, findings: [] }]),
      repos: one.nextRepos,
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(two.nextRepos['me/gone'].droppedAt).toBeUndefined()
    expect(two.nextRepos['me/gone'].findings['GHSA-1:pkg']).toBeDefined()
  })
})

describe('pings and counts', () => {
  it('pings for critical runtime findings and malware only, as configured', () => {
    const runtime = [finding({ repo: 'r', advisoryId: 'A', devOnly: false })]
    const devOnly = [finding({ repo: 'r', advisoryId: 'A', devOnly: true })]
    const s = settings()
    expect(shouldPing(s, { malware: false, severity: 'critical', members: runtime })).toBe(true)
    expect(shouldPing(s, { malware: false, severity: 'critical', members: devOnly })).toBe(false)
    expect(shouldPing({ ...s, pingDevOnly: true }, { malware: false, severity: 'critical', members: devOnly })).toBe(true)
    expect(shouldPing(s, { malware: false, severity: 'high', members: runtime })).toBe(false)
    expect(shouldPing(s, { malware: true, severity: 'critical', members: devOnly })).toBe(true)
    expect(shouldPing({ ...s, pingRole: false }, { malware: true, severity: 'critical', members: runtime })).toBe(false)
  })

  it('counts open findings by severity', () => {
    const repos = baselined(['me/a', [finding({ repo: 'me/a', advisoryId: '1', severity: 'critical' }), finding({ repo: 'me/a', advisoryId: '2', severity: 'low' })]])
    expect(countOpen(repos)).toEqual({ critical: 1, high: 0, moderate: 0, low: 1 })
  })
})
