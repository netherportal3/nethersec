/** Small helpers shared by the watch modules. PURE. */
import { createHash } from 'node:crypto'
import type { CardSink, WatchCard } from './types.js'

/**
 * A card body is shown as Discord markdown. esc() makes outside text (a feed's
 * title or summary, a version, a name a box reports) show as typed: no
 * formatting, headings, lists or masked links. isSafeUrl() says whether a URL
 * can be shown as is. The modules' own text, links included, needs neither.
 */
export { esc, isSafeUrl } from '../discord/cards.js'

export const HOUR_MS = 3_600_000
export const DAY_MS = 86_400_000
/**
 * A card for a problem that is still there (a kernel bug, a container image, a
 * feed that cannot be read) is sent again this often. The hub edits nothing
 * when the card is open and unchanged; when a person resolved it, the problem
 * comes back as a new card.
 */
export const RESURFACE_MS = 6 * HOUR_MS
export const TITLE_MAX = 120
export const BODY_MAX = 3_500
/** Card ids stay short enough for any store or button id the hub keys them by. */
const CARD_ID_MAX = 100
/** The ids the card sink accepts (WATCH_ID_RE in cards/ops.ts). */
const CARD_ID_RE = /^[A-Za-z0-9][A-Za-z0-9:._/@+-]{0,199}$/

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 3).trimEnd()}...`
}

export function joinAnd(items: string[]): string {
  return items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
}

export function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

export function isoDay(ms: number | null): string {
  return ms === null || !Number.isFinite(ms) ? 'not given' : new Date(ms).toISOString().slice(0, 10)
}

export function dayRange(days: string[]): string {
  const sorted = [...new Set(days.filter(Boolean))].sort()
  return sorted.length <= 1 ? sorted[0] || 'not given' : `${sorted[0]} to ${sorted[sorted.length - 1]}`
}

export function asRecord(x: unknown): Record<string, unknown> | null {
  return x && typeof x === 'object' && !Array.isArray(x) ? (x as Record<string, unknown>) : null
}

export function asArray(x: unknown): unknown[] {
  return Array.isArray(x) ? x : []
}

/** No control characters (a card is plain text), newlines kept. */
export function plain(s: string): string {
  return s.replace(/[\x00-\x09\x0b-\x1f\x7f]/g, ' ')
}

/** A stable card id. A long one keeps its start and ends in a hash of the whole. */
export function cardId(...parts: string[]): string {
  const id = parts.join(':')
  if (id.length <= CARD_ID_MAX && CARD_ID_RE.test(id)) return id
  // An id from a feed can hold characters the card sink refuses (`#`, `?`, `=`, spaces),
  // and a refused id would never post. Keep a readable part and add a hash of the whole.
  const hash = createHash('sha256').update(id).digest('hex').slice(0, 16)
  return `${id.replace(/[^A-Za-z0-9:._/@+-]/g, '_').slice(0, CARD_ID_MAX - 18)}-h${hash}`
}

/** A card body: the text, then one `Name: value` line per field, cut to fit. */
export function cardBody(text: string, fields: Array<[string, string | null | undefined]> = []): string {
  const lines = fields.filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`)
  const body = lines.length ? `${text.trim()}\n\n${lines.join('\n')}` : text.trim()
  return truncate(plain(body), BODY_MAX)
}

/** Sends a card. False when the sink threw: the caller keeps it to send again next run. */
export async function sendCard(sink: CardSink, card: WatchCard): Promise<boolean> {
  try {
    await sink.upsert({
      ...card,
      title: truncate(plain(card.title).replace(/\s+/g, ' ').trim(), TITLE_MAX),
      body: truncate(plain(card.body), BODY_MAX),
      ping: card.severity === 'critical' && card.ping,
      ...(card.url ? { url: card.url } : {}),
    })
    return true
  } catch {
    return false
  }
}

/** Closes a card. False when the sink threw: the caller tries again next run. */
export async function closeCard(sink: CardSink, id: string, note: string): Promise<boolean> {
  try {
    await sink.close(id, truncate(plain(note), BODY_MAX))
    return true
  } catch {
    return false
  }
}

/** Marks a card reported fixed (it stays open for a person). False when the sink threw: the caller tries again next run. */
export async function reportFixedCard(sink: CardSink, id: string, note: string): Promise<boolean> {
  try {
    await sink.reportFixed(id, truncate(plain(note), BODY_MAX))
    return true
  } catch {
    return false
  }
}

/** Runs `fn` over `items` with at most `limit` at a time, results in order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await fn(items[i])
    }
  })
  await Promise.all(workers)
  return out
}

/** The JSON size of a value, in characters. */
export function jsonSize(value: unknown): number {
  return JSON.stringify(value)?.length ?? 0
}

/** What a state save may use: under the hub's 512 kB cap per name, with room to spare. */
export const STATE_BUDGET = 480_000
