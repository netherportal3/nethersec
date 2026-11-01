/**
 * Fixed-window counters, kept in memory. A report is admitted only when every
 * window it counts in has room, and it is counted only when admitted: a report
 * that one window refuses counts in none. So a source over its own window
 * cannot keep filling a total that every other source shares.
 *
 * The limits are the protocol's (docs/report-protocol.md). The total windows
 * bound a set of keys that each stay under their own source's window, and the
 * data events count on windows of their own, so a box listing its containers
 * never crowds out its alerts.
 */

export const MINUTE_MS = 60_000
export const HOUR_MS = 3_600_000

export const LIMITS = {
  alertPerSource: 25,
  alertTotal: 100,
  dataPerSource: 30,
  dataTotal: 150,
  dmPerHour: 15,
} as const

export interface Window {
  key: string
  max: number
  ms: number
  /** A total that every source shares, not one source's own window. */
  shared?: boolean
}

/**
 * Refused: `retryAfterSec` says when to try again. `shared` is true when only
 * shared windows were full, so the source itself was under its own limits.
 */
export type HitResult = { ok: true } | { ok: false; retryAfterSec: number; shared: boolean }

/** Keys whose name starts with this are never dropped to make room. */
const PINNED = '_'
const MAX_KEYS = 1_000

export class RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>()

  constructor(private readonly now: () => number = Date.now) {}

  /** Admit one report and count it in every window, or refuse it and count it in none. */
  hit(windows: Window[]): HitResult {
    const now = this.now()
    let retryAt = 0
    let own = false
    for (const w of windows) {
      const live = this.windows.get(w.key)
      if (!live || now >= live.resetAt || live.count < w.max) continue
      retryAt = Math.max(retryAt, live.resetAt)
      if (!w.shared) own = true
    }
    if (retryAt) return { ok: false, retryAfterSec: Math.max(1, Math.ceil((retryAt - now) / 1000)), shared: !own }
    for (const w of windows) this.count(w, now)
    return { ok: true }
  }

  /** The live counts of the windows whose key starts with `prefix`, highest first, the prefix cut off. */
  busiest(prefix: string, n: number): Array<{ name: string; count: number }> {
    const now = this.now()
    const out: Array<{ name: string; count: number }> = []
    for (const [k, w] of this.windows) if (k.startsWith(prefix) && now < w.resetAt) out.push({ name: k.slice(prefix.length), count: w.count })
    return out.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)).slice(0, n)
  }

  private count(w: Window, now: number): void {
    const live = this.windows.get(w.key)
    if (live && now < live.resetAt) {
      live.count++
      return
    }
    if (!live && this.windows.size >= MAX_KEYS) this.makeRoom(now)
    this.windows.set(w.key, { count: 1, resetAt: now + w.ms })
  }

  /** Drop expired windows, then the oldest unpinned ones. A flood of made-up keys cannot grow the map. */
  private makeRoom(now: number): void {
    for (const [k, w] of this.windows) if (now >= w.resetAt) this.windows.delete(k)
    for (const k of this.windows.keys()) {
      if (this.windows.size < MAX_KEYS) break
      if (!k.startsWith(PINNED)) this.windows.delete(k)
    }
  }
}

/** The windows one report counts in. The totals are marked shared. */
export function windowsFor(source: string, opts: { data: boolean; dm: boolean }): Window[] {
  if (opts.data) {
    return [
      { key: `data:${source}`, max: LIMITS.dataPerSource, ms: MINUTE_MS },
      { key: '_data', max: LIMITS.dataTotal, ms: MINUTE_MS, shared: true },
    ]
  }
  const out: Window[] = [{ key: `alert:${source}`, max: LIMITS.alertPerSource, ms: MINUTE_MS }]
  // A DM source's hourly window is pinned too: dropping it would reopen that person's DMs.
  if (opts.dm) out.push({ key: `_dm:${source}`, max: LIMITS.dmPerHour, ms: HOUR_MS })
  out.push({ key: '_alert', max: LIMITS.alertTotal, ms: MINUTE_MS, shared: true })
  return out
}
