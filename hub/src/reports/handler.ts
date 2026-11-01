/**
 * POST /v1/report, after the HTTP layer: the order of checks and what each
 * answer means (docs/report-protocol.md, "Responses").
 *
 *   401 missing or unknown key        (checked first, before the body is read)
 *   400 the body broke a rule          (says which field, never echoes it)
 *   403 another source, or a data event from a dm= key
 *   429 rate limited                   (Retry-After)
 *   202 the card was posted or edited, the note or DM sent, or the data stored
 *   503 not delivered                  (Discord unreachable, hub not set up)
 */
import type { Store } from '../store.js'
import { accepted, notDelivered, type OpsCards, type Reply } from '../cards/ops.js'
import type { DiscordPort } from '../cards/port.js'
import { dmMessage } from '../cards/render.js'
import {
  CONTAINERS_MAX,
  CONTAINERS_MAX_PER_BOX,
  REBOOT_PENDING_MAX,
  containerKey,
  containerName,
  parseContainerPackages,
  parseRebootPending,
} from './data.js'
import type { Key, KeyRing } from './keys.js'
import { CONTAINER_PACKAGES_EVENT, validateReport, type Report } from './protocol.js'
import { HOUR_MS, MINUTE_MS, RateLimiter, windowsFor } from './ratelimit.js'

/** Sources kept in the host list at most. Only key holders can report, so this is a backstop. */
export const MAX_HOSTS = 500
const SAVED_WITH_CARD = new Set(['posted', 'edited', 'closed', 'reported-fixed'])

export interface ReportDeps {
  store: Store
  keys: KeyRing
  ops: OpsCards
  port: DiscordPort
  limiter?: RateLimiter
  now?: () => number
  log?: (msg: string) => void
  /** Called when the status board should change (to refresh it). */
  onChange?: () => void
}

export class ReportHandler {
  private readonly limiter: RateLimiter
  private readonly now: () => number
  private readonly log: (msg: string) => void
  /** The total-limit log line: when it was last written, and the refusals since then not written. */
  private refusedLoggedAt = -Infinity
  private refusedQuiet = 0

  constructor(private readonly deps: ReportDeps) {
    this.now = deps.now ?? Date.now
    this.limiter = deps.limiter ?? new RateLimiter(this.now)
    this.log = deps.log ?? (() => {})
  }

  authenticate(header: string | undefined): Promise<Key | null> {
    return this.deps.keys.match(header)
  }

  /** One report from a key that already matched. `text` is the raw body. */
  async handle(key: Key, text: string): Promise<Reply> {
    let raw: unknown
    try {
      raw = JSON.parse(text)
    } catch {
      return { status: 400, body: { error: 'The body is not valid JSON.', field: 'body' } }
    }
    const v = validateReport(raw)
    if (!v.ok) return { status: 400, body: { error: v.error, field: v.field } }
    const r = v.report
    if (r.source !== key.source) return { status: 403, body: { error: 'This key belongs to another source.' } }
    if (r.data && key.dmUserId) return { status: 403, body: { error: 'A dm= key cannot send data events.' } }

    const limit = this.limiter.hit(windowsFor(r.source, { data: r.data, dm: key.dmUserId !== null }))
    if (!limit.ok) {
      if (limit.shared) await this.noteRefusedAtTotal(r.source, r.data ? 'data' : 'alert')
      return { status: 429, body: { error: 'Too many reports. Try again later.' }, retryAfterSec: limit.retryAfterSec }
    }
    this.clearRefusedAtTotal()

    this.recordHost(r.source)
    if (r.data) return this.storeData(r)
    if (key.dmUserId) return this.sendDm(r, key.dmUserId)
    const reply = await this.deps.ops.hostReport(r, { page: key.page })
    // The host list is saved with a changed card; save it here when nothing else did.
    if (!SAVED_WITH_CARD.has(String(reply.body.result))) await this.deps.store.save().catch(() => {})
    return reply
  }

  /**
   * The total limit refused a source that was under its own: some key may be
   * sending far more than its box should. One log line a minute at most, with
   * the busiest sources (never a key), and a line on the status board.
   */
  private async noteRefusedAtTotal(source: string, what: 'alert' | 'data'): Promise<void> {
    const now = this.now()
    if (now - this.refusedLoggedAt >= MINUTE_MS) {
      const busiest = this.limiter.busiest(`${what}:`, 3).map((b) => `${b.name} (${b.count})`)
      const quiet = this.refusedQuiet ? ` ${this.refusedQuiet} more ${this.refusedQuiet === 1 ? 'was' : 'were'} refused since the last line like this.` : ''
      this.log(
        `${what === 'alert' ? 'An alert' : 'A data'} report from ${source} was refused: the total limit for ${what} reports is full, although ${source} is under its own.${quiet} ` +
          `Busiest sources this minute: ${busiest.join(', ') || 'none'}. If one sends far more than its box should, its key may be stolen: revoke it with \`node dist/cli.js key revoke <source>\`.`,
      )
      this.refusedLoggedAt = now
      this.refusedQuiet = 0
    } else {
      this.refusedQuiet++
    }
    const at = new Date(now).toISOString()
    const state = this.deps.store.state
    if (state.reportsRefused) {
      // Saved with the next change; the first refusal is what matters.
      state.reportsRefused.lastAt = at
    } else {
      state.reportsRefused = { since: at, lastAt: at }
      await this.deps.store.save().catch(() => {})
    }
    this.deps.onChange?.()
  }

  /** A report got through: the refusal line on the board goes an hour after the last refusal. Saved with the next change. */
  private clearRefusedAtTotal(): void {
    const refused = this.deps.store.state.reportsRefused
    if (!refused || this.now() - Date.parse(refused.lastAt) < HOUR_MS) return
    this.deps.store.state.reportsRefused = null
    this.deps.onChange?.()
  }

  private recordHost(source: string): void {
    const hosts = this.deps.store.state.hosts
    const at = new Date(this.now()).toISOString()
    const h = hosts[source]
    if (h) {
      h.lastReportAt = at
      h.reports++
      return
    }
    if (Object.keys(hosts).length >= MAX_HOSTS) return
    hosts[source] = { source, firstReportAt: at, lastReportAt: at, reports: 1 }
  }

  private async sendDm(r: Report, userId: string): Promise<Reply> {
    if (!this.deps.port.isReady()) return notDelivered('Discord is not reachable.')
    try {
      await this.deps.port.dm(userId, dmMessage(r, new Date(this.now()).toISOString()))
    } catch {
      // Never the user id in a log.
      this.log(`A direct message for ${r.source} was not delivered.`)
      return notDelivered('The direct message could not be delivered.')
    } finally {
      await this.deps.store.save().catch(() => {})
    }
    return accepted('dm')
  }

  private async storeData(r: Report): Promise<Reply> {
    const state = this.deps.store.state
    const now = this.now()
    let reply: Reply
    if (r.event === CONTAINER_PACKAGES_EVENT) {
      if (r.state === 'resolved') {
        const ctr = containerName(r.detail)
        if (!ctr) return { status: 400, body: { error: 'A resolved container-packages report needs ctr=<container name>.', field: 'detail' } }
        delete state.containers[containerKey(r.source, ctr)]
        reply = accepted('cleared')
      } else {
        const rec = parseContainerPackages(r.detail, r.source, now)
        if (!rec) return { status: 400, body: { error: 'container-packages needs ctr=<container name> and img=<image ref>.', field: 'detail' } }
        const k = containerKey(r.source, rec.container)
        if (!state.containers[k]) {
          const all = Object.values(state.containers)
          if (all.length >= CONTAINERS_MAX) return { status: 429, body: { error: 'The hub keeps no more containers.' }, retryAfterSec: 3600 }
          if (all.filter((c) => c.box === r.source).length >= CONTAINERS_MAX_PER_BOX) {
            return { status: 429, body: { error: 'The hub keeps no more containers for this source.' }, retryAfterSec: 3600 }
          }
        }
        state.containers[k] = rec
        reply = accepted('stored')
      }
    } else {
      if (r.state === 'resolved') {
        delete state.rebootPending[r.source]
        reply = accepted('cleared')
      } else {
        if (!state.rebootPending[r.source] && Object.keys(state.rebootPending).length >= REBOOT_PENDING_MAX) {
          return { status: 429, body: { error: 'The hub keeps no more pending reboots.' }, retryAfterSec: 3600 }
        }
        state.rebootPending[r.source] = parseRebootPending(r.detail, r.source, now)
        reply = accepted('stored')
      }
    }
    try {
      await this.deps.store.save()
    } catch {
      return { status: 503, body: { error: 'The data could not be saved.' } }
    }
    return reply
  }
}
