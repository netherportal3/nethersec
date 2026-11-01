/**
 * The weekly pending-reboot summary: one message in the status channel, on
 * Mondays from 09:00 UTC, listing every box with a reboot pending.
 *
 * A check runs every 15 minutes. The ISO week it posted for is saved, so a
 * restart does not post it twice; a post that fails is tried again on the next
 * check; a week with no pending reboot posts nothing. Records with no report
 * for 30 days are dropped (the box is gone, or rebooted unheard).
 */
import type { DiscordPort } from './cards/port.js'
import { rebootDigestMessage } from './cards/render.js'
import { DATA_PRUNE_MS } from './reports/data.js'
import type { Store } from './store.js'

export const DIGEST_CHECK_MS = 15 * 60_000
/** Monday (getUTCDay), from this hour UTC. */
export const DIGEST_DAY_UTC = 1
export const DIGEST_HOUR_UTC = 9

/** ISO 8601 week of a time, like `2026-W44` (weeks start on Monday; week 1 holds the first Thursday). */
export function isoWeekKey(now: number): string {
  const d = new Date(now)
  const day = d.getUTCDay() || 7
  // The Thursday of this week decides the ISO year.
  const thursday = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 4 - day)
  const year = new Date(thursday).getUTCFullYear()
  const week = Math.floor((thursday - Date.UTC(year, 0, 1)) / 864e5 / 7) + 1
  return `${year}-W${String(week).padStart(2, '0')}`
}

export function inDigestWindow(now: number): boolean {
  const d = new Date(now)
  return d.getUTCDay() === DIGEST_DAY_UTC && d.getUTCHours() >= DIGEST_HOUR_UTC
}

/** Drop data records with no report for DATA_PRUNE_MS. True when something was dropped. */
export function pruneData(store: Store, now: number): boolean {
  let changed = false
  const s = store.state
  for (const [k, r] of Object.entries(s.rebootPending)) {
    if (now - r.receivedAt > DATA_PRUNE_MS) {
      delete s.rebootPending[k]
      changed = true
    }
  }
  for (const [k, c] of Object.entries(s.containers)) {
    if (now - c.receivedAt > DATA_PRUNE_MS) {
      delete s.containers[k]
      changed = true
    }
  }
  return changed
}

export type DigestOutcome = 'outside' | 'done' | 'not-set-up' | 'empty' | 'posted' | 'failed'

export class RebootDigest {
  private timer: NodeJS.Timeout | null = null
  private readonly now: () => number

  constructor(private readonly deps: { store: Store; port: DiscordPort; now?: () => number; log?: (msg: string) => void }) {
    this.now = deps.now ?? Date.now
  }

  start(): void {
    if (this.timer) return
    this.timer = setInterval(() => void this.check(), DIGEST_CHECK_MS)
    this.timer.unref()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
    this.timer = null
  }

  /** One check. Never throws. */
  async check(): Promise<DigestOutcome> {
    try {
      const now = this.now()
      const store = this.deps.store
      if (pruneData(store, now)) await store.save().catch(() => {})
      if (!inDigestWindow(now)) return 'outside'
      const week = isoWeekKey(now)
      if (store.state.rebootDigestWeek === week) return 'done'
      const setup = store.state.setup
      if (!setup || !this.deps.port.isReady()) return 'not-set-up'
      const payload = rebootDigestMessage(Object.values(store.state.rebootPending), now)
      if (!payload) return 'empty'
      try {
        await this.deps.port.send(setup.statusChannelId, payload)
      } catch {
        this.deps.log?.('The pending-reboot summary could not be posted; trying again at the next check.')
        return 'failed'
      }
      store.state.rebootDigestWeek = week
      await store.save().catch(() => {})
      return 'posted'
    } catch (err) {
      this.deps.log?.(`The pending-reboot summary failed: ${err instanceof Error ? err.name : 'unknown error'}`)
      return 'failed'
    }
  }
}
