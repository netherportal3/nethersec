/**
 * The report protocol, version 1 (docs/report-protocol.md): the body rules.
 * PURE. The body is untrusted: a key proves who sent it, not what is in it.
 */
import type { OpsSeverity } from '../state.js'

export const SOURCE_RE = /^[a-z0-9][a-z0-9-]{0,39}$/
export const EVENT_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/
export const MAX_BODY_BYTES = 100_000
export const TITLE_MAX = 120
export const DETAIL_MAX = 1_500
export const DATA_DETAIL_MAX = 64_000
export const GROUP_MAX = 40

export const REBOOT_PENDING_EVENT = 'reboot-pending'
export const CONTAINER_PACKAGES_EVENT = 'container-packages'
const DATA_EVENTS = new Set([REBOOT_PENDING_EVENT, CONTAINER_PACKAGES_EVENT])

export interface Report {
  kind: 'security' | 'uptime'
  source: string
  event: string
  state: 'triggered' | 'resolved'
  /** The default is already applied: warning for security, critical for uptime. */
  severity: OpsSeverity
  title: string
  detail: string
  group: string
  /** One of the two data events: stored, never a card. */
  data: boolean
}

export type Validation = { ok: true; report: Report } | { ok: false; field: string; error: string }

/**
 * Control characters and bidirectional overrides go. Tabs and line breaks
 * become one space each, so words on either side stay apart.
 */
export function stripControls(s: string): string {
  return s.replace(/[\t\n\r]/g, ' ').replace(/[\p{Cc}\p{Bidi_Control}]/gu, '')
}

/** Length in characters (code points), as a person counts them. */
function length(s: string): number {
  let n = 0
  for (const _ of s) n++
  return n
}

function bad(field: string, error: string): Validation {
  return { ok: false, field, error }
}

/** Check one parsed body against the protocol. Unknown fields are ignored. */
export function validateReport(raw: unknown): Validation {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return bad('body', 'The body must be one JSON object.')
  const b = raw as Record<string, unknown>

  if (b.v !== undefined && b.v !== 1) return bad('v', 'v must be 1.')

  for (const f of ['kind', 'source', 'event', 'state', 'severity', 'title', 'detail', 'group']) {
    if (b[f] !== undefined && typeof b[f] !== 'string') return bad(f, `${f} must be a string.`)
  }
  const str = (f: string) => (b[f] as string | undefined) ?? ''

  const kind = str('kind')
  if (kind !== 'security' && kind !== 'uptime') return bad('kind', 'kind must be security or uptime.')
  const source = str('source')
  if (!SOURCE_RE.test(source)) return bad('source', 'source must be 1 to 40 lowercase letters, digits or dashes, starting with a letter or digit.')
  const event = str('event')
  if (!EVENT_RE.test(event)) return bad('event', 'event must be 1 to 64 lowercase letters, digits, dots, dashes or underscores, starting with a letter or digit.')

  const stateRaw = str('state')
  if (stateRaw !== '' && stateRaw !== 'triggered' && stateRaw !== 'resolved') return bad('state', 'state must be triggered or resolved.')
  const state = stateRaw === 'resolved' ? 'resolved' : 'triggered'

  const sevRaw = str('severity')
  if (sevRaw !== '' && sevRaw !== 'critical' && sevRaw !== 'warning' && sevRaw !== 'info') {
    return bad('severity', 'severity must be critical, warning, info or empty.')
  }
  const severity: OpsSeverity = sevRaw === '' ? (kind === 'security' ? 'warning' : 'critical') : sevRaw

  const data = kind === 'security' && DATA_EVENTS.has(event)
  const title = stripControls(str('title')).trim()
  if (length(title) > TITLE_MAX) return bad('title', `title must be at most ${TITLE_MAX} characters.`)
  const detail = stripControls(str('detail')).trim()
  const detailMax = data ? DATA_DETAIL_MAX : DETAIL_MAX
  if (length(detail) > detailMax) return bad('detail', `detail must be at most ${detailMax} characters for this event.`)
  const group = stripControls(str('group')).trim()
  if (length(group) > GROUP_MAX) return bad('group', `group must be at most ${GROUP_MAX} characters.`)

  return { ok: true, report: { kind, source, event, state, severity, title, detail, group, data } }
}

/** A report's identity: one open card at most per identity. */
export function reportKey(r: Pick<Report, 'kind' | 'source' | 'event'>): string {
  return `${r.kind}:${r.source}:${r.event}`
}
