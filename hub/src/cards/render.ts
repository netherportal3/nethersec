/**
 * Message builders for host and watch cards, notes, direct messages and the
 * weekly pending-reboot summary. PURE: plain Discord API objects, tested
 * without a client.
 *
 * Box text (title, detail, group) is untrusted. It is shown as plain text: no
 * formatting, no masked links, and `<@...>` or `@everyone` show as text. Every
 * message sets allowedMentions; the only mention ever allowed is the watcher
 * role, added here on purpose and never taken from a report.
 */
import { createHash } from 'node:crypto'
import { ButtonStyle, ComponentType, escapeMarkdown, type APIActionRowComponent, type APIButtonComponent, type APIEmbed } from 'discord.js'
import { clip, COLORS, isSafeUrl, joinLines, type Payload } from '../discord/cards.js'
import type { Report } from '../reports/protocol.js'
import { REBOOT_STALE_MS } from '../reports/data.js'
import type { OpsCardState, OpsSeverity, RebootPendingRecord } from '../state.js'

export const OPS_ACK_PREFIX = 'ns:ack:'
export const OPS_MUTE_PREFIX = 'ns:mute:'
export const OPS_RESOLVE_PREFIX = 'ns:resolve:'

export const OPS_SEVERITY_LABEL: Record<OpsSeverity, string> = { critical: 'Critical', warning: 'Warning', info: 'Info' }
export const OPS_COLORS: Record<OpsSeverity, number> = { critical: COLORS.critical, warning: COLORS.high, info: COLORS.info }

const NO_MENTIONS = { parse: [] as [] }

/** Box text as typed: no formatting, links or mentions. */
export function plain(s: string, max: number): string {
  return escapeMarkdown(clip(s, max), { heading: true, bulletedList: true, numberedList: true }).replace(/[[\]<@]/g, '\\$&')
}

/** Box text in a title: formatting escaped. */
function titleText(s: string): string {
  return escapeMarkdown(clip(s, 200))
}

function unix(iso: string | number): number {
  return Math.floor(new Date(iso).getTime() / 1000)
}

function kindLabel(kind: OpsCardState['kind'] | Report['kind']): string {
  return kind === 'security' ? 'Security' : kind === 'uptime' ? 'Uptime' : 'Watch'
}

function cardTitle(card: OpsCardState): string {
  const label = card.closedAt ? (card.kind === 'watch' && !card.closedBy ? 'Closed' : 'Resolved') : OPS_SEVERITY_LABEL[card.severity]
  const what = card.kind === 'watch' ? titleText(card.title) : `${titleText(card.title || card.event || '')} (${card.source})`
  return clip(`${label}: ${what}`, 256)
}

function statusLines(card: OpsCardState): string[] {
  const out: string[] = []
  if (card.closedAt) {
    const at = `<t:${unix(card.closedAt)}:R>`
    if (card.closedBy) out.push(`Resolved by <@${card.closedBy}> ${at}.`)
    else if (card.kind === 'uptime') out.push(`Back up ${at}.`)
    else out.push(card.closeNote ? `Closed ${at}: ${clip(card.closeNote, 300)}` : `Closed ${at}.`)
  } else if (card.reportedFixedAt) {
    const at = `<t:${unix(card.reportedFixedAt)}:R>`
    if (card.kind !== 'watch') out.push(`The box reports this is fixed ${at}. Press Resolve once you have checked it.`)
    else if (card.reportedFixedNote) out.push(`${clip(card.reportedFixedNote, 300)} Reported ${at}. Press Resolve once you have checked it.`)
    else out.push(`Reported fixed ${at}. Press Resolve once you have checked it.`)
  }
  if (card.ackedBy && card.ackedAt) out.push(`Acknowledged by <@${card.ackedBy}> <t:${unix(card.ackedAt)}:R>.`)
  if (card.mutedBy && card.mutedAt) {
    out.push(`Muted by <@${card.mutedBy}> <t:${unix(card.mutedAt)}:R>. No new card or ping for this check until \`/nethersec host-unmute\`.`)
  }
  return out
}

function cardEmbed(card: OpsCardState): APIEmbed {
  const fields: NonNullable<APIEmbed['fields']> = []
  if (card.kind !== 'watch') {
    fields.push({ name: 'Box', value: card.group ? `${card.source} · ${plain(card.group, 40)}` : card.source ?? '-', inline: true })
    fields.push({ name: 'Check', value: `\`${card.event}\``, inline: true })
    fields.push({ name: 'Kind', value: kindLabel(card.kind), inline: true })
  }
  const status = statusLines(card)
  if (status.length) fields.push({ name: 'Status', value: clip(status.join('\n'), 1024) })
  const body = card.kind === 'watch' ? clip(card.body, 4000) : clip(plain(card.body, 3000), 4096)
  return {
    title: cardTitle(card),
    url: card.url && isSafeUrl(card.url) ? card.url : undefined,
    description: body || undefined,
    color: card.closedAt ? COLORS.fixed : OPS_COLORS[card.severity],
    fields,
    footer: { text: card.kind === 'watch' ? 'Watch' : `${kindLabel(card.kind)} report` },
    timestamp: card.updatedAt,
  }
}

function cardButtons(card: OpsCardState): APIActionRowComponent<APIButtonComponent>[] {
  const row: APIButtonComponent[] = []
  if (card.url && isSafeUrl(card.url)) row.push({ type: ComponentType.Button, style: ButtonStyle.Link, label: 'Open', url: card.url })
  if (!card.closedAt) {
    if (!card.ackedBy) row.push({ type: ComponentType.Button, style: ButtonStyle.Secondary, label: 'Acknowledge', custom_id: OPS_ACK_PREFIX + card.id })
    // Watch cards cannot be muted: a module's card is not one check on one box.
    if (card.kind !== 'watch' && !card.mutedBy) row.push({ type: ComponentType.Button, style: ButtonStyle.Secondary, label: 'Mute', custom_id: OPS_MUTE_PREFIX + card.id })
    row.push({ type: ComponentType.Button, style: ButtonStyle.Success, label: 'Resolve', custom_id: OPS_RESOLVE_PREFIX + card.id })
  }
  return row.length ? [{ type: ComponentType.ActionRow, components: row }] : []
}

/** A new card. `pingRoleId` adds the one allowed mention. */
export function opsCardMessage(card: OpsCardState, pingRoleId: string | null): Payload {
  const payload: Payload = { embeds: [cardEmbed(card)], components: cardButtons(card), allowedMentions: NO_MENTIONS }
  if (pingRoleId) {
    payload.content = `<@&${pingRoleId}>`
    payload.allowedMentions = { parse: [], roles: [pingRoleId] }
  }
  return payload
}

/** The card after a change. An edit never pings, so it carries no mention. */
export function opsCardEdit(card: OpsCardState): Payload {
  return { embeds: [cardEmbed(card)], components: cardButtons(card), allowedMentions: NO_MENTIONS }
}

/** What the message shows, without its timestamp. Equal hashes: nothing to edit. */
export function opsContentHash(card: OpsCardState): string {
  const { timestamp: _t, ...embed } = cardEmbed(card)
  return createHash('sha256').update(JSON.stringify([embed, cardButtons(card)])).digest('hex').slice(0, 24)
}

/** An open card rose to critical: a short note in the critical channel, since an edit never pings. */
export function riseMessage(card: OpsCardState, link: string, pingRoleId: string | null): Payload {
  const what = card.kind === 'watch' ? titleText(card.title) : `${titleText(card.title || card.event || '')} (${card.source})`
  const payload: Payload = {
    embeds: [{ title: clip(`Now critical: ${what}`, 256), description: `[Open the card](${link})`, color: COLORS.critical }],
    allowedMentions: NO_MENTIONS,
  }
  if (pingRoleId) {
    payload.content = `<@&${pingRoleId}>`
    payload.allowedMentions = { parse: [], roles: [pingRoleId] }
  }
  return payload
}

function reportFields(r: Report): NonNullable<APIEmbed['fields']> {
  return [
    { name: 'Box', value: r.group ? `${r.source} · ${plain(r.group, 40)}` : r.source, inline: true },
    { name: 'Check', value: `\`${r.event}\``, inline: true },
    { name: 'Kind', value: kindLabel(r.kind), inline: true },
  ]
}

/** An `info` report with no open card: a note in the status channel, no card. */
export function infoNote(r: Report, now: string): Payload {
  return {
    embeds: [
      {
        title: clip(`Info: ${titleText(r.title || r.event)} (${r.source})`, 256),
        description: r.detail ? clip(plain(r.detail, 3000), 4096) : undefined,
        color: COLORS.info,
        fields: reportFields(r),
        footer: { text: `${kindLabel(r.kind)} report` },
        timestamp: now,
      },
    ],
    allowedMentions: NO_MENTIONS,
  }
}

/** A report from a `dm=` key: one direct message, no buttons, no mention. */
export function dmMessage(r: Report, now: string): Payload {
  const resolved = r.state === 'resolved'
  const label = resolved ? (r.kind === 'uptime' ? 'Back up' : 'Reported fixed') : OPS_SEVERITY_LABEL[r.severity]
  return {
    embeds: [
      {
        title: clip(`${label}: ${titleText(r.title || r.event)} (${r.source})`, 256),
        description: r.detail ? clip(plain(r.detail, 3000), 4096) : undefined,
        color: resolved ? COLORS.fixed : OPS_COLORS[r.severity],
        fields: reportFields(r),
        footer: { text: 'Sent only to you' },
        timestamp: now,
      },
    ],
    allowedMentions: NO_MENTIONS,
  }
}

function days(ms: number): string {
  const d = Math.floor(Math.max(0, ms) / 864e5)
  if (d === 0) return 'under a day'
  return d === 1 ? '1 day' : `${d} days`
}

/** One line per box with a pending reboot, oldest first. */
export function rebootLines(records: RebootPendingRecord[], now: number): string[] {
  const age = (r: RebootPendingRecord) => now - (r.since ?? r.receivedAt)
  return [...records]
    .sort((a, b) => age(b) - age(a) || a.source.localeCompare(b.source))
    .map((r) => {
      let line = `**${r.source}**: pending for ${days(age(r))}.`
      if (now - r.receivedAt > REBOOT_STALE_MS) {
        line += ` No report for ${days(now - r.receivedAt)}, so this may be out of date.`
      } else if (!r.checked) {
        line += ' Not checked (the CVE lookup did not finish).'
      } else if (r.uncovered) {
        line += ` ${r.uncovered} High or Critical ${r.uncovered === 1 ? 'CVE waits' : 'CVEs wait'} for the reboot.`
      } else {
        line += ' Nothing High or Critical waits for it.'
      }
      if (r.livepatch) line += ' Livepatch is on.'
      if (r.pkgs.length) line += ` Staged: ${r.pkgs.map((p) => plain(p, 64)).join(', ')}${r.more ? ` and ${r.more} more` : ''}.`
      return line
    })
}

/** The weekly summary, or null when no box has a reboot pending. */
export function rebootDigestMessage(records: RebootPendingRecord[], now: number): Payload | null {
  if (!records.length) return null
  return {
    embeds: [
      {
        title: records.length === 1 ? 'Pending reboot' : `Pending reboots (${records.length})`,
        description: joinLines(rebootLines(records, now), 4000),
        color: COLORS.info,
        footer: { text: 'Posted once a week' },
        timestamp: new Date(now).toISOString(),
      },
    ],
    allowedMentions: NO_MENTIONS,
  }
}
