import { describe, expect, it } from 'vitest'
import {
  alertCard,
  baselineMessage,
  dashboardEmbed,
  findingsEmbed,
  fixText,
  joinLines,
  updatedCardButtons,
  updatedCardEmbed,
} from '../src/discord/cards.js'
import { planScan, type AlertGroup } from '../src/planner.js'
import { emptyState, type CardState } from '../src/state.js'
import { finding, okRepo, scanOf, settings } from './helpers.js'

const NOW = '2026-10-01T00:00:00.000Z'

function group(over: Partial<AlertGroup> = {}): AlertGroup {
  const members = over.members ?? [finding({ repo: 'me/app', advisoryId: 'GHSA-aaaa-bbbb-cccc', packageName: 'lodash' })]
  return {
    groupKey: 'npm:GHSA-aaaa-bbbb-cccc:lodash',
    advisoryId: 'GHSA-aaaa-bbbb-cccc',
    packageName: 'lodash',
    ecosystem: 'npm',
    severity: 'critical',
    malware: false,
    channel: 'critical',
    ping: true,
    ...over,
    members,
  }
}

describe('joinLines', () => {
  it('fits within the limit and says how many were left out', () => {
    const lines = Array.from({ length: 50 }, (_, i) => `line number ${i}`)
    const out = joinLines(lines, 100)
    expect(out.length).toBeLessThanOrEqual(100)
    expect(out).toMatch(/and \d+ more$/)
    expect(joinLines(['a', 'b'], 100)).toBe('a\nb')
    expect(joinLines([], 100)).toBe('-')
    expect(joinLines(['x'.repeat(500)], 100).length).toBeLessThanOrEqual(100)
  })
})

describe('alertCard', () => {
  it('pings only the watcher role, and only when asked', () => {
    const p = alertCard(group(), { cardId: 'abc', roleId: '42', now: NOW })
    expect(p.content).toBe('<@&42>')
    expect(p.allowedMentions).toEqual({ parse: [], roles: ['42'] })
    const quiet = alertCard(group({ ping: false }), { cardId: 'abc', roleId: '42', now: NOW })
    expect(quiet.content).toBeUndefined()
    expect(quiet.allowedMentions).toEqual({ parse: [] })
  })

  it('escapes outside text so it cannot format or ping', () => {
    const members = [finding({ repo: 'me/app', advisoryId: 'GHSA-aaaa-bbbb-cccc', title: '@everyone **click** [here](https://evil.example)' })]
    const p = alertCard(group({ members, ping: false }), { cardId: 'abc', roleId: null, now: NOW })
    expect(p.embeds[0].description).not.toContain('**click**')
    expect(p.allowedMentions.parse).toEqual([])
  })

  it('lists every affected repo with its fix, within Discord limits', () => {
    const members = Array.from({ length: 80 }, (_, i) => finding({ repo: `me/repo-${i}`, advisoryId: 'GHSA-aaaa-bbbb-cccc' }))
    const p = alertCard(group({ members }), { cardId: 'abc', roleId: null, now: NOW })
    const field = p.embeds[0].fields![0]
    expect(field.name).toBe('Affected repos (80)')
    expect(field.value.length).toBeLessThanOrEqual(1024)
    expect(field.value).toContain('`1.0.0` to `1.0.1`')
    expect(p.embeds[0].title!.length).toBeLessThanOrEqual(256)
    const ids = p.components![0].components.map((c) => ('custom_id' in c ? c.custom_id : c.style))
    expect(ids).toContain('cve:ack:abc')
    expect(ids).toContain('cve:mute:abc')
  })

  it('malware gets the remediation caveat', () => {
    const p = alertCard(group({ malware: true }), { cardId: 'abc', roleId: null, now: NOW })
    expect(p.embeds[0].title).toMatch(/^Malware: /)
    expect(p.embeds[0].description).toContain('rotate any secrets')
  })
})

describe('card updates', () => {
  const card: CardState = {
    id: 'abc',
    channelId: '1',
    messageId: '2',
    advisoryId: 'GHSA-aaaa-bbbb-cccc',
    packageName: 'lodash',
    severity: 'critical',
    repos: { 'me/a': 'fixed', 'me/b': 'open' },
    createdAt: NOW,
  }
  const embed = alertCard(group(), { cardId: 'abc', roleId: null, now: NOW }).embeds[0]

  it('shows partial fixes and acknowledgement, and drops the Acknowledge button', () => {
    const e = updatedCardEmbed(embed, { ...card, ackedBy: '7', ackedAt: NOW })
    const status = e.fields!.find((f) => f.name === 'Status')!.value
    expect(status).toContain('Fixed in me/a.')
    expect(status).toContain('Acknowledged by <@7>')
    const labels = updatedCardButtons(embed.url, { ...card, ackedBy: '7' })[0].components.map((c) => ('label' in c ? c.label : undefined))
    expect(labels).toEqual(['View advisory', 'Mute advisory'])
  })

  it('turns green with no action buttons once fixed everywhere', () => {
    const done = { ...card, repos: { 'me/a': 'fixed' as const, 'me/b': 'fixed' as const }, resolvedAt: NOW }
    const e = updatedCardEmbed(embed, done)
    expect(e.title).toMatch(/^Fixed: /)
    expect(updatedCardEmbed(e, done).title).toBe(e.title)
    expect(updatedCardEmbed(e, done).fields!.filter((f) => f.name === 'Status')).toHaveLength(1)
    expect(updatedCardButtons(embed.url, done)[0].components.map((c) => ('label' in c ? c.label : undefined))).toEqual(['View advisory'])
  })
})

describe('fix text', () => {
  it('reads plainly', () => {
    expect(fixText({ from: '1.0.0', to: '2.0.0', crossesLine: true })).toBe('`1.0.0` to `2.0.0` (major update)')
    expect(fixText({ from: '1.0.0', to: null, crossesLine: false, unfixed: true })).toBe('`1.0.0`, no fix released yet')
    expect(fixText({ from: '1.0.0', to: null, crossesLine: false })).toBe('`1.0.0`, fixed version not listed')
  })
})

describe('summaries', () => {
  it('the baseline message counts everything and lists only alert-level findings', () => {
    const p = baselineMessage(
      [
        { repo: 'me/a', findings: [finding({ repo: 'me/a', advisoryId: 'GHSA-1', severity: 'critical' }), finding({ repo: 'me/a', advisoryId: 'GHSA-2', severity: 'low' })] },
        { repo: 'me/b', findings: [] },
      ],
      'high',
    )
    const d = p.embeds[0].description!
    expect(d).toContain('Started watching 2 repos. 1 of them have open advisories.')
    expect(d).toContain('Critical 1 · High 0 · Moderate 0 · Low 1')
    expect(d).toContain('GHSA-1')
    expect(d).not.toContain('GHSA-2')
  })

  it('findings and the status board read from state', () => {
    const plan = planScan({
      scan: scanOf([okRepo('me/a', [finding({ repo: 'me/a', advisoryId: 'GHSA-1', severity: 'high' }), finding({ repo: 'me/a', advisoryId: 'GHSA-2', severity: 'low' })])]),
      repos: {},
      settings: settings(),
      mutes: [],
      now: NOW,
    })
    expect(findingsEmbed(plan.nextRepos, {}).title).toBe('Open advisories (2)')
    expect(findingsEmbed(plan.nextRepos, { minSeverity: 'high' }).title).toBe('Open advisories (1)')
    expect(findingsEmbed(plan.nextRepos, { repo: 'ME/A' }).title).toBe('Open advisories in ME/A (2)')
    expect(findingsEmbed(plan.nextRepos, { repo: 'me/other' }).description).toBe('Nothing open.')

    const state = { ...emptyState(60), repos: plan.nextRepos }
    const board = dashboardEmbed(state, { nextRunAt: NOW, running: false })
    expect(board.fields![0]).toEqual({ name: 'Open advisories', value: 'Critical 0 · High 1 · Moderate 0 · Low 1' })
    expect(board.fields!.find((f) => f.name === 'Next scan')!.value).toMatch(/^<t:\d+:R>$/)
  })
})
