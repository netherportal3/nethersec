import { describe, expect, it } from 'vitest'
import { CARD_CAP, countOpen, planScan, shouldPing } from '../src/planner.js'
import type { RepoState } from '../src/state.js'
import { finding, okRepo, scanOf, settings } from './helpers.js'

const NOW = '2026-10-01T00:00:00.000Z'

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
    expect(plan.nextRepos['me/a'].baselined).toBe(true)
    expect(Object.keys(plan.nextRepos['me/a'].findings)).toEqual(['GHSA-1:pkg'])
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
      now: '2026-10-02T00:00:00.000Z',
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

  it('a repo no longer scanned is dropped and reported', () => {
    const repos = baselined(['me/a', []], ['me/gone', []])
    const plan = planScan({ scan: scanOf([okRepo('me/a', [])]), repos, settings: settings(), mutes: [], now: NOW })
    expect(plan.dropped).toEqual(['me/gone'])
    expect(plan.nextRepos['me/gone']).toBeUndefined()
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
