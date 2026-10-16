/**
 * Message builders. PURE: they return plain Discord API objects, so they can be
 * tested without a client.
 *
 * Every message sets allowedMentions explicitly. Advisory titles and package
 * names come from outside sources; with `parse: []` a stray "@everyone" in one
 * is just text. The only mention ever allowed is the watcher role, on purpose.
 */
import { ButtonStyle, ComponentType, escapeMarkdown, type APIEmbed, type APIActionRowComponent, type APIButtonComponent } from 'discord.js'
import { SEVERITIES, SOURCE_LABEL, type Severity } from '../scanner/advisories.js'
import type { FixLine } from '../scanner/fix.js'
import type { Finding } from '../scanner/match.js'
import { activeRepos, type AlertGroup, type FixedItem } from '../planner.js'
import type { CardState, FindingState, RepoState, State } from '../state.js'

export const COLORS: Record<Severity | 'fixed' | 'info' | 'warn', number> = {
  critical: 0xd32f2f,
  high: 0xf57c00,
  moderate: 0xfbc02d,
  low: 0x9e9e9e,
  fixed: 0x2e7d32,
  info: 0x1976d2,
  warn: 0x8e24aa,
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  moderate: 'Moderate',
  low: 'Low',
}

export const ACK_PREFIX = 'cve:ack:'
export const MUTE_PREFIX = 'cve:mute:'

export interface Payload {
  content?: string
  embeds: APIEmbed[]
  components?: APIActionRowComponent<APIButtonComponent>[]
  allowedMentions: { parse: []; roles?: string[] }
}

const NO_MENTIONS = { parse: [] as [] }

/** Cut to `max` characters with a trailing ellipsis. */
export function clip(s: string, max: number): string {
  return s.length > max ? s.slice(0, Math.max(0, max - 1)) + String.fromCharCode(0x2026) : s
}

/** Join lines up to `max` characters; the rest becomes "and N more". */
export function joinLines(lines: string[], max: number): string {
  if (lines.length === 0) return '-'
  let out = ''
  for (let i = 0; i < lines.length; i++) {
    // Each line must leave room for the "and N more" note the next line may need.
    const remaining = lines.length - i - 1
    const tail = remaining > 0 ? `\nand ${remaining} more` : ''
    const candidate = out ? `${out}\n${lines[i]}` : lines[i]
    if (candidate.length + tail.length <= max) {
      out = candidate
      continue
    }
    if (!out) return clip(lines[i], Math.max(1, max - tail.length)) + tail
    return `${out}\nand ${lines.length - i} more`
  }
  return out
}

/**
 * Outside text, shown as typed: no formatting, headings, lists or masked links.
 * Clipped first, since escapeMarkdown slows down on very long hostile input and
 * nothing shown is this long. Brackets are escaped here because the library's
 * own masked-link check is slow on hostile input too.
 */
export function esc(s: string): string {
  return escapeMarkdown(clip(s, 1000), { heading: true, bulletedList: true, numberedList: true }).replace(/[[\]]/g, '\\$&')
}

/** An https URL with nothing that could end a markdown link early. */
export function isSafeUrl(url: string | undefined): url is string {
  return !!url && /^https:\/\/[^\s()<>[\]]+$/.test(url) && url.length <= 512
}

/** The advisory id, linked when its URL is safe to link. */
function advLink(id: string, url: string): string {
  return isSafeUrl(url) ? `[${esc(id)}](${url})` : esc(id)
}

function unix(iso: string): number {
  return Math.floor(new Date(iso).getTime() / 1000)
}

/** One fix line as text: "`1.2.3` to `1.2.5`", or why there is none. */
export function fixText(l: FixLine): string {
  if (l.to) {
    let s = `\`${l.from}\` to \`${l.to}\``
    if (l.crossesLine) s += ' (major update)'
    if (l.prereleaseOnly) s += ' (prerelease only)'
    return s
  }
  return `\`${l.from}\`, ${l.unfixed ? 'no fix released yet' : 'fixed version not listed'}`
}

function findingLine(f: Pick<Finding, 'repo' | 'fixes' | 'installed' | 'lockfiles' | 'devOnly'>): string {
  const fixes = f.fixes.length ? f.fixes.map(fixText).join(', ') : f.installed.map((v) => `\`${v}\``).join(', ')
  const where = f.lockfiles.length === 1 ? esc(f.lockfiles[0]) : `${f.lockfiles.length} lockfiles`
  return `**${esc(f.repo)}** ${fixes} in ${where}${f.devOnly ? ' (dev only)' : ''}`
}

function advisoryButtons(url: string, cardId: string): APIActionRowComponent<APIButtonComponent>[] {
  const row: APIButtonComponent[] = []
  if (isSafeUrl(url)) row.push({ type: ComponentType.Button, style: ButtonStyle.Link, label: 'View advisory', url })
  row.push({ type: ComponentType.Button, style: ButtonStyle.Secondary, label: 'Acknowledge', custom_id: ACK_PREFIX + cardId })
  row.push({ type: ComponentType.Button, style: ButtonStyle.Secondary, label: 'Mute advisory', custom_id: MUTE_PREFIX + cardId })
  return [{ type: ComponentType.ActionRow, components: row }]
}

/** The alert card for one advisory that is new in one or more repos. */
export function alertCard(g: AlertGroup, opts: { cardId: string; roleId: string | null; now: string }): Payload {
  const lead = g.members[0]
  const label = g.malware ? 'Malware' : SEVERITY_LABEL[g.severity]
  const title = clip(`${label}: ${g.packageName} (${g.advisoryId})`, 256)
  let description = esc(lead.title)
  if (g.malware) {
    description +=
      '\n\nThis release was reported as malicious. Remove it, and rotate any secrets the machines that installed it could reach.'
  }
  const fields = [
    {
      name: g.members.length === 1 ? 'Affected repo' : `Affected repos (${g.members.length})`,
      value: joinLines(g.members.map(findingLine), 1024),
    },
    { name: 'Severity', value: SEVERITY_LABEL[g.severity], inline: true },
    { name: 'Ecosystem', value: g.ecosystem, inline: true },
  ]
  if (lead.cveId) fields.push({ name: 'CVE', value: esc(lead.cveId), inline: true })
  const sources = [...new Set(g.members.flatMap((m) => m.sources))].map((s) => SOURCE_LABEL[s]).join(', ')
  const embed: APIEmbed = {
    title,
    url: isSafeUrl(lead.url) ? lead.url : undefined,
    description: clip(description, 4096),
    color: g.malware ? COLORS.critical : COLORS[g.severity],
    fields,
    footer: { text: clip(`Source: ${sources}`, 2048) },
    timestamp: opts.now,
  }
  const payload: Payload = { embeds: [embed], components: advisoryButtons(lead.url, opts.cardId), allowedMentions: NO_MENTIONS }
  if (g.ping && opts.roleId) {
    payload.content = `<@&${opts.roleId}>`
    payload.allowedMentions = { parse: [], roles: [opts.roleId] }
  }
  return payload
}

/** The card's embed after a change: who acknowledged it, and which repos are fixed. */
export function updatedCardEmbed(embed: APIEmbed, card: CardState): APIEmbed {
  const next: APIEmbed = { ...embed, fields: (embed.fields ?? []).filter((f) => f.name !== 'Status') }
  const repos = Object.entries(card.repos)
  const fixedRepos = repos.filter(([, s]) => s === 'fixed').map(([r]) => r)
  const status: string[] = []
  if (card.resolvedAt) {
    status.push(`Fixed in every repo <t:${unix(card.resolvedAt)}:R>.`)
    next.color = COLORS.fixed
    if (next.title && !next.title.startsWith('Fixed: ')) next.title = clip(`Fixed: ${next.title}`, 256)
  } else if (fixedRepos.length) {
    status.push(`Fixed in ${fixedRepos.map(esc).join(', ')}.`)
  }
  if (card.ackedBy && card.ackedAt) status.push(`Acknowledged by <@${card.ackedBy}> <t:${unix(card.ackedAt)}:R>.`)
  if (card.mutedBy && card.mutedAt) status.push(`Muted by <@${card.mutedBy}> <t:${unix(card.mutedAt)}:R>. No new alerts for it.`)
  if (status.length) next.fields = [...(next.fields ?? []), { name: 'Status', value: clip(status.join('\n'), 1024) }]
  return next
}

/** Buttons after a change: none once fixed; Acknowledge and Mute go once used. */
export function updatedCardButtons(url: string | undefined, card: CardState): APIActionRowComponent<APIButtonComponent>[] {
  const row: APIButtonComponent[] = []
  if (isSafeUrl(url)) row.push({ type: ComponentType.Button, style: ButtonStyle.Link, label: 'View advisory', url })
  if (!card.resolvedAt) {
    if (!card.ackedBy) row.push({ type: ComponentType.Button, style: ButtonStyle.Secondary, label: 'Acknowledge', custom_id: ACK_PREFIX + card.id })
    if (!card.mutedBy) row.push({ type: ComponentType.Button, style: ButtonStyle.Secondary, label: 'Mute advisory', custom_id: MUTE_PREFIX + card.id })
  }
  return row.length ? [{ type: ComponentType.ActionRow, components: row }] : []
}

function countsText(counts: Record<Severity, number>): string {
  return SEVERITIES.map((s) => `${SEVERITY_LABEL[s]} ${counts[s]}`).join(' · ')
}

function countBySeverity(findings: Array<{ severity: Severity }>): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, moderate: 0, low: 0 }
  for (const f of findings) out[f.severity]++
  return out
}

function severityOrder(a: { severity: Severity }, b: { severity: Severity }): number {
  return SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
}

/**
 * One message for every repo (or ecosystem of a repo) read for the first time
 * this scan. An ecosystem whose source was down at a repo's first read lands
 * here later, so the wording fits a repo already watched too.
 */
export function baselineMessage(baselined: Array<{ repo: string; findings: Finding[] }>, minSeverity: Severity): Payload {
  const all = baselined.flatMap((b) => b.findings)
  const top = all
    .filter((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(minSeverity) || f.malware)
    .sort(severityOrder)
    .map((f) => `**${SEVERITY_LABEL[f.severity]}** ${esc(f.packageName)} ${f.fixes.map(fixText).join(', ')} in **${esc(f.repo)}** (${advLink(f.advisoryId, f.url)})`)
  const n = baselined.length
  const withFindings = baselined.filter((b) => b.findings.length > 0).length
  const which =
    n === 1
      ? withFindings ? 'It has open advisories.' : 'Nothing is open there.'
      : `${withFindings} of them ${withFindings === 1 ? 'has' : 'have'} open advisories.`
  const lines = [
    `Recorded what is already open in ${n} ${n === 1 ? 'repo' : 'repos'}. ${which}`,
    '',
    `**Open now:** ${countsText(countBySeverity(all))}`,
  ]
  if (top.length) lines.push('', joinLines(top, 3000))
  lines.push('', 'These are recorded, not alerted one by one. New advisories from now on get their own alert. Use `/cve findings` for the full list.')
  return {
    embeds: [{ title: 'Now watching', description: clip(lines.join('\n'), 4096), color: COLORS.info }],
    allowedMentions: NO_MENTIONS,
  }
}

/** The advisories past the per-scan card limit. */
export function overflowMessage(groups: AlertGroup[]): Payload {
  const lines = groups.map(
    (g) => `**${g.malware ? 'Malware' : SEVERITY_LABEL[g.severity]}** ${esc(g.packageName)} (${advLink(g.advisoryId, g.members[0].url)}) in ${g.members.map((m) => esc(m.repo)).join(', ')}`,
  )
  return {
    embeds: [
      {
        title: `${groups.length} more new ${groups.length === 1 ? 'advisory' : 'advisories'}`,
        description: clip(`${joinLines(lines, 3800)}\n\nThese did not get their own card this scan. Use \`/cve findings\` for details.`, 4096),
        color: COLORS[groups.some((g) => g.malware) ? 'critical' : groups[0].severity],
      },
    ],
    allowedMentions: NO_MENTIONS,
  }
}

/** Advisories that are gone since the last scan. */
export function fixedMessage(items: FixedItem[]): Payload {
  const lines = [...items]
    .sort((a, b) => severityOrder(a.finding, b.finding))
    .map((i) => `**${SEVERITY_LABEL[i.finding.severity]}** ${esc(i.finding.packageName)} (${esc(i.finding.advisoryId)}) in **${esc(i.repo)}**`)
  return {
    embeds: [{ title: 'Fixed since the last scan', description: joinLines(lines, 4000), color: COLORS.fixed }],
    allowedMentions: NO_MENTIONS,
  }
}

export function noticeMessage(title: string, lines: string[], color: number = COLORS.warn): Payload {
  return { embeds: [{ title, description: joinLines(lines, 4000), color }], allowedMentions: NO_MENTIONS }
}

export function unreadableMessage(notices: Array<{ repo: string; reason: string }>): Payload {
  return noticeMessage(
    `Can't read ${notices.length === 1 ? 'a repo' : `${notices.length} repos`}`,
    [
      ...notices.map((n) => `**${esc(n.repo)}**: ${esc(n.reason)}`),
      '',
      'What was open there stays on record until it can be read again.',
    ],
  )
}

export function scanFailedMessage(reason: string): Payload {
  return noticeMessage('Scans are failing', [esc(reason), '', 'Nothing is marked fixed while scans fail. You will see a message here when they work again.'])
}

/** Fix lines as text for a finding stored in state. */
function storedLine(repo: string, f: FindingState): string {
  const fixes = f.fixes.length ? f.fixes.map(fixText).join(', ') : f.installed.map((v) => `\`${v}\``).join(', ')
  return `**${f.malware ? 'Malware' : SEVERITY_LABEL[f.severity]}** ${esc(f.packageName)} ${fixes} in **${esc(repo)}** (${advLink(f.advisoryId, f.url)})${f.devOnly ? ' (dev only)' : ''}`
}

/** The open findings, filtered, as one embed. */
export function findingsEmbed(repos: Record<string, RepoState>, filter: { repo?: string; minSeverity?: Severity }): APIEmbed {
  const want = filter.repo?.toLowerCase()
  const min = filter.minSeverity ? SEVERITIES.indexOf(filter.minSeverity) : SEVERITIES.length - 1
  const rows: Array<{ severity: Severity; line: string }> = []
  for (const r of activeRepos(repos)) {
    if (want && r.name.toLowerCase() !== want) continue
    for (const f of Object.values(r.findings)) {
      if (SEVERITIES.indexOf(f.severity) > min && !f.malware) continue
      rows.push({ severity: f.malware ? 'critical' : f.severity, line: storedLine(r.name, f) })
    }
  }
  rows.sort((a, b) => severityOrder(a, b) || a.line.localeCompare(b.line))
  const scope = filter.repo ? ` in ${clip(esc(filter.repo), 200)}` : ''
  if (rows.length === 0) {
    return { title: `Open advisories${scope}`, description: 'Nothing open.', color: COLORS.fixed }
  }
  return {
    title: clip(`Open advisories${scope} (${rows.length})`, 256),
    description: joinLines(rows.map((r) => r.line), 4000),
    color: COLORS[rows[0].severity],
  }
}

/** The status board in the status channel, edited after every scan. */
export function dashboardEmbed(state: State, opts: { nextRunAt: string | null; running: boolean; githubLogin?: string }): APIEmbed {
  const repos = activeRepos(state.repos)
  const counts: Record<Severity, number> = { critical: 0, high: 0, moderate: 0, low: 0 }
  for (const r of repos) for (const f of Object.values(r.findings)) counts[f.severity]++
  const s = state.settings
  const watched =
    s.repoMode === 'all' ? 'every repo the GitHub token can read' : `${s.repos.length} chosen ${s.repos.length === 1 ? 'repo' : 'repos'}`
  const fields: NonNullable<APIEmbed['fields']> = [
    { name: 'Open advisories', value: countsText(counts) },
    {
      name: 'Watching',
      value: `${repos.length} ${repos.length === 1 ? 'repo' : 'repos'} (${watched}), ${repos.filter((r) => r.lockfiles > 0).length} with lockfiles`,
    },
  ]
  const run = state.lastRun
  if (run) {
    const extra = run.unreadable.length ? `, ${run.unreadable.length} could not be read` : ''
    fields.push({ name: 'Last scan', value: `<t:${unix(run.finishedAt)}:R>: ${run.readable} of ${run.repos} read${extra}` })
  }
  fields.push({
    name: 'Next scan',
    value: s.paused ? 'Paused. Use `/cve resume` to start again.' : opts.running ? 'Running now' : opts.nextRunAt ? `<t:${unix(opts.nextRunAt)}:R>` : 'Soon',
  })
  if (run?.unreadable.length) {
    fields.push({ name: 'Could not read', value: joinLines(run.unreadable.map((u) => `**${esc(u.repo)}**: ${esc(u.reason)}`), 1024) })
  }
  if (run?.errors.length) fields.push({ name: 'Problems', value: joinLines(run.errors.map(esc), 1024) })
  const footer = `Alerts for ${SEVERITY_LABEL[s.minSeverity]} and above${opts.githubLogin ? ` · GitHub: ${opts.githubLogin}` : ''}`
  return {
    title: 'CVE Monitor',
    color: counts.critical ? COLORS.critical : counts.high ? COLORS.high : COLORS.fixed,
    fields,
    footer: { text: footer },
    timestamp: run?.finishedAt,
  }
}

export function dashboardPayload(embed: APIEmbed): Payload {
  return { embeds: [embed], allowedMentions: NO_MENTIONS }
}
