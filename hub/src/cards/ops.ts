/**
 * Host and watch cards: one open card per identity, edited in place.
 *
 * Host reports (docs/report-protocol.md, "What the hub does with a report"):
 *   - triggered, no open card: a new card (critical to the critical channel,
 *     warning to the alerts channel), or a note in the status channel for info.
 *     An info note the same as one posted in the last hour is not posted again;
 *   - triggered, card open: edited in place. It pings again only when it rose to
 *     critical, and only with a `page` key;
 *   - resolved, security: the card says the box reports it fixed and stays open
 *     until a person presses Resolve. A box cannot close its own security alert;
 *   - resolved, uptime: the card closes.
 *
 * Nothing is recorded unless Discord took the post or edit, so a report that
 * was not delivered (503) changes nothing and the box sends it again. Work on
 * one identity runs one at a time, so two reports at once never post two cards.
 *
 * Watch cards (a watch module's upsert and close) work the same way, and a
 * person can Resolve one too. A later upsert of the same id opens a new card,
 * so a module that sends a still-current problem again brings it back. A
 * module whose only sign of a fix comes from the boxes calls reportFixed
 * instead of close: like a host security card, the card says so and stays open
 * until a person presses Resolve, and a later upsert clears the mark. When the
 * open watch cards are at their cap, a new one is refused (the module tries
 * again next run) and the status board says so until there is room.
 */
import { createHash, randomBytes } from 'node:crypto'
import type { Store } from '../store.js'
import { MAX_OPEN_WATCH_CARDS, type OpsCardState, type OpsKind, type OpsSeverity, type State } from '../state.js'
import { reportKey, type Report } from '../reports/protocol.js'
import { MessageGone, type DiscordPort } from './port.js'
import { infoNote, opsCardEdit, opsCardMessage, opsContentHash, riseMessage } from './render.js'

/** Open cards at most, per kind group (host, watch). */
export const MAX_OPEN_HOST_CARDS = 300
/** Open host cards at most for one source, so one key cannot fill the cap for every box. */
export const MAX_OPEN_HOST_CARDS_PER_SOURCE = 30
export { MAX_OPEN_WATCH_CARDS }
/** How far past MAX_OPEN_WATCH_CARDS a critical watch card may still open. */
export const WATCH_CRITICAL_RESERVE = 50
/** An info note the same as one posted this recently (same check, title, detail and group) is not posted again. */
export const INFO_NOTE_REPEAT_MS = 3_600_000
/** Info notes remembered at most for that, in memory. */
const MAX_NOTES_KEPT = 500
/** Cards kept at most, open and closed. */
export const MAX_CARDS = 1_000
/** A closed card is forgotten after this. Its message stays in Discord. */
export const CLOSED_CARD_TTL_MS = 30 * 864e5
export const MAX_MUTES = 200

/** The shapes a watch module codes against. */
export interface WatchCard {
  id: string
  severity: 'critical' | 'warning' | 'info'
  ping: boolean
  title: string
  body: string
  url?: string
}

export interface CardSink {
  upsert(card: WatchCard): Promise<void>
  close(id: string, note: string): Promise<void>
  reportFixed(id: string, note: string): Promise<void>
}

export interface Reply {
  status: number
  body: Record<string, unknown>
  retryAfterSec?: number
}

export function accepted(result: string): Reply {
  return { status: 202, body: { accepted: true, result } }
}

export function notDelivered(error: string): Reply {
  return { status: 503, body: { error } }
}

export const WATCH_ID_RE = /^[A-Za-z0-9][A-Za-z0-9:._/@+-]{0,199}$/
const SEVERITIES: OpsSeverity[] = ['critical', 'warning', 'info']

export class NotDelivered extends Error {
  override name = 'NotDelivered'
}

/** The open watch cards are at their cap. The module keeps the card and tries again next run. */
export class WatchCardsFullError extends Error {
  override name = 'WatchCardsFullError'
}

/** Watch cards one closeAcknowledged() call closes at most. */
export const MAX_AUTO_CLOSE_PER_RUN = 25

export interface OpsDeps {
  store: Store
  port: DiscordPort
  guildId: string
  now?: () => Date
  log?: (msg: string) => void
  /** Called after a card changed (to refresh the status board). */
  onChange?: () => void
}

export class OpsCards implements CardSink {
  private readonly locks = new Map<string, Promise<unknown>>()
  /** Info notes posted lately: a hash of the note, and when (ms). */
  private readonly notes = new Map<string, number>()
  private readonly now: () => Date
  private readonly log: (msg: string) => void

  constructor(private readonly deps: OpsDeps) {
    this.now = deps.now ?? (() => new Date())
    this.log = deps.log ?? (() => {})
  }

  private get state(): State {
    return this.deps.store.state
  }

  /** Run `fn` after every earlier call for the same identity has finished. */
  lock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(key) ?? Promise.resolve()
    const next = prev.then(fn, fn)
    const tail = next.catch(() => {})
    this.locks.set(key, tail)
    void tail.then(() => {
      if (this.locks.get(key) === tail) this.locks.delete(key)
    })
    return next
  }

  findOpen(key: string): OpsCardState | undefined {
    for (const c of Object.values(this.state.opsCards)) if (c.key === key && !c.closedAt) return c
    return undefined
  }

  openCards(): OpsCardState[] {
    return Object.values(this.state.opsCards).filter((c) => !c.closedAt)
  }

  isMuted(key: string): boolean {
    return this.state.opsMutes.some((m) => m.key === key)
  }

  link(card: Pick<OpsCardState, 'channelId' | 'messageId'>): string {
    return `https://discord.com/channels/${this.deps.guildId}/${card.channelId}/${card.messageId}`
  }

  /** Why nothing can be posted now, or null when it can. */
  private blocked(): string | null {
    if (!this.state.setup) return 'The hub is not set up yet (run /nethersec setup).'
    if (!this.deps.port.isReady()) return 'Discord is not reachable.'
    return null
  }

  private channelFor(severity: OpsSeverity): string {
    const s = this.state.setup!
    return severity === 'critical' ? s.criticalChannelId : severity === 'warning' ? s.alertsChannelId : s.statusChannelId
  }

  private pingRole(allowed: boolean): string | null {
    if (!allowed || !this.state.settings.pingRole) return null
    return this.state.setup?.roleId ?? null
  }

  private newId(): string {
    let id = randomBytes(5).toString('hex')
    while (this.state.opsCards[id]) id = randomBytes(5).toString('hex')
    return id
  }

  private async commit(card: OpsCardState): Promise<void> {
    card.contentHash = opsContentHash(card)
    this.state.opsCards[card.id] = card
    this.prune()
    if (this.state.watchCardsFull && this.openWatchCount() < MAX_OPEN_WATCH_CARDS) {
      this.state.watchCardsFull = null
      this.log('Watch cards have room again.')
    }
    await this.deps.store.save()
    this.deps.onChange?.()
  }

  private openWatchCount(): number {
    let n = 0
    for (const c of Object.values(this.state.opsCards)) if (c.kind === 'watch' && !c.closedAt) n++
    return n
  }

  /** A new watch card was refused at the cap: say so on the status board, not only in the log. */
  private async noteWatchCardsFull(now: string): Promise<void> {
    const full = this.state.watchCardsFull
    if (full) {
      // Saved with the next change; the first refusal is what matters.
      full.lastAt = now
      this.deps.onChange?.()
      return
    }
    this.state.watchCardsFull = { since: now, lastAt: now }
    this.log(`New watch cards are refused: ${MAX_OPEN_WATCH_CARDS} are open, the most allowed. Resolve the ones that are handled to make room.`)
    await this.deps.store.save().catch(() => {})
    this.deps.onChange?.()
  }

  /** Closed cards past their time go first, then the oldest closed ones over the cap. */
  prune(): void {
    const now = this.now().getTime()
    const cards = this.state.opsCards
    for (const [id, c] of Object.entries(cards)) {
      if (c.closedAt && now - new Date(c.closedAt).getTime() > CLOSED_CARD_TTL_MS) delete cards[id]
    }
    const ids = Object.keys(cards)
    if (ids.length <= MAX_CARDS) return
    const closed = Object.values(cards)
      .filter((c) => c.closedAt)
      .sort((a, b) => a.closedAt!.localeCompare(b.closedAt!))
    for (const c of closed.slice(0, ids.length - MAX_CARDS)) delete cards[c.id]
  }

  /**
   * Post a new card, or edit the open one in place (posting it again when its
   * message was deleted). Throws NotDelivered when Discord did not take it.
   */
  private async deliver(next: OpsCardState, prev: OpsCardState | undefined, opts: { pingRoleId: string | null; riseRoleId: string | null | false }): Promise<void> {
    const port = this.deps.port
    if (!prev) {
      try {
        next.messageId = await port.send(next.channelId, opsCardMessage(next, opts.pingRoleId))
      } catch {
        throw new NotDelivered('The card could not be posted.')
      }
      return
    }
    try {
      await port.edit(next.channelId, next.messageId, opsCardEdit(next))
    } catch (err) {
      if (!(err instanceof MessageGone)) throw new NotDelivered('The card could not be edited.')
      // Deleted: post it again where its severity goes now.
      next.channelId = this.channelFor(next.severity)
      try {
        next.messageId = await port.send(next.channelId, opsCardMessage(next, null))
      } catch {
        throw new NotDelivered('The card could not be posted again.')
      }
      // Keep where the message now is, even if the note below fails.
      prev.channelId = next.channelId
      prev.messageId = next.messageId
      prev.contentHash = ''
    }
    if (opts.riseRoleId !== false) {
      try {
        await port.send(this.state.setup!.criticalChannelId, riseMessage(next, this.link(next), opts.riseRoleId))
      } catch {
        throw new NotDelivered('The card was edited, but the critical note could not be posted.')
      }
    }
  }

  // ---- host reports ------------------------------------------------------------

  /** One validated, non-data host report from a key that may post cards. */
  hostReport(r: Report, key: { page: boolean }): Promise<Reply> {
    const id = reportKey(r)
    return this.lock(id, async () => {
      const open = this.findOpen(id)
      const now = this.now().toISOString()

      if (r.state === 'resolved') {
        if (!open) return accepted('nothing-open')
        if (r.kind === 'security' && open.reportedFixedAt) return accepted('unchanged')
        const why = this.blocked()
        if (why) return notDelivered(why)
        const next: OpsCardState = { ...open, updatedAt: now }
        if (r.kind === 'uptime') next.closedAt = now
        else next.reportedFixedAt = now
        try {
          await this.deliver(next, open, { pingRoleId: null, riseRoleId: false })
        } catch (err) {
          return notDelivered((err as Error).message)
        }
        await this.commit(next)
        return accepted(r.kind === 'uptime' ? 'closed' : 'reported-fixed')
      }

      const muted = this.isMuted(id)
      if (open) {
        const next: OpsCardState = { ...open, severity: r.severity, title: r.title, body: r.detail, group: r.group || undefined, reportedFixedAt: undefined }
        if (opsContentHash(next) === open.contentHash) return accepted('unchanged')
        const why = this.blocked()
        if (why) return notDelivered(why)
        next.updatedAt = now
        const rose = open.severity !== 'critical' && r.severity === 'critical'
        try {
          await this.deliver(next, open, { pingRoleId: null, riseRoleId: rose ? this.pingRole(key.page && !muted) : false })
        } catch (err) {
          if (open.contentHash === '') await this.deps.store.save()
          return notDelivered((err as Error).message)
        }
        await this.commit(next)
        return accepted('edited')
      }

      if (muted) return accepted('muted')
      const why = this.blocked()
      if (why) return notDelivered(why)
      if (r.severity === 'info') {
        const note = createHash('sha256').update(JSON.stringify([id, r.title, r.detail, r.group])).digest('base64url').slice(0, 22)
        const at = this.now().getTime()
        const last = this.notes.get(note)
        if (last !== undefined && at - last < INFO_NOTE_REPEAT_MS) return accepted('already-noted')
        try {
          await this.deps.port.send(this.state.setup!.statusChannelId, infoNote(r, now))
        } catch {
          return notDelivered('The note could not be posted.')
        }
        this.rememberNote(note, at)
        return accepted('noted')
      }
      const hostOpen = this.openCards().filter((c) => c.kind !== 'watch')
      if (hostOpen.length >= MAX_OPEN_HOST_CARDS) return { status: 429, body: { error: 'Too many open host alerts. Resolve some first.' }, retryAfterSec: 3600 }
      if (hostOpen.filter((c) => c.source === r.source).length >= MAX_OPEN_HOST_CARDS_PER_SOURCE) {
        return { status: 429, body: { error: 'Too many open alerts for this source. Resolve some first.' }, retryAfterSec: 3600 }
      }
      const card: OpsCardState = {
        id: this.newId(),
        key: id,
        kind: r.kind,
        source: r.source,
        event: r.event,
        group: r.group || undefined,
        severity: r.severity,
        title: r.title,
        body: r.detail,
        channelId: this.channelFor(r.severity),
        messageId: '',
        createdAt: now,
        updatedAt: now,
        contentHash: '',
      }
      try {
        await this.deliver(card, undefined, { pingRoleId: r.severity === 'critical' ? this.pingRole(key.page) : null, riseRoleId: false })
      } catch (err) {
        return notDelivered((err as Error).message)
      }
      await this.commit(card)
      return accepted('posted')
    })
  }

  /** Remember a posted note. Past the cap, the expired ones go first, then the oldest. */
  private rememberNote(note: string, at: number): void {
    this.notes.delete(note)
    if (this.notes.size >= MAX_NOTES_KEPT) {
      for (const [k, t] of this.notes) if (at - t >= INFO_NOTE_REPEAT_MS) this.notes.delete(k)
      for (const k of this.notes.keys()) {
        if (this.notes.size < MAX_NOTES_KEPT) break
        this.notes.delete(k)
      }
    }
    this.notes.set(note, at)
  }

  // ---- watch cards -------------------------------------------------------------

  /**
   * Create a watch card, or edit the open one in place. An unchanged card is
   * not touched. `ping` is honored only for critical, and on an open card only
   * when it rose to critical. Rejects when the card could not be posted (not
   * set up, Discord unreachable); the module should try again on its next run.
   */
  upsert(card: WatchCard): Promise<void> {
    let c: WatchCard
    try {
      c = checkWatchCard(card)
    } catch (err) {
      return Promise.reject(err)
    }
    const key = `watch:${c.id}`
    return this.lock(key, async () => {
      const open = this.findOpen(key)
      const now = this.now().toISOString()
      if (open) {
        // The module sends the problem again, so any "reported fixed" mark goes.
        const next: OpsCardState = { ...open, severity: c.severity, title: c.title, body: c.body, url: c.url, reportedFixedAt: undefined, reportedFixedNote: undefined }
        if (opsContentHash(next) === open.contentHash) return
        const why = this.blocked()
        if (why) throw new NotDelivered(why)
        next.updatedAt = now
        const rose = open.severity !== 'critical' && c.severity === 'critical'
        try {
          await this.deliver(next, open, { pingRoleId: null, riseRoleId: rose ? this.pingRole(c.ping) : false })
        } catch (err) {
          if (open.contentHash === '') await this.deps.store.save()
          throw err
        }
        await this.commit(next)
        return
      }
      const why = this.blocked()
      if (why) throw new NotDelivered(why)
      // A critical card (an exploited bug, a kernel bug with no fix) may use a small reserve past
      // the cap, so a board full of old notices never blocks a page.
      const limit = c.severity === 'critical' ? MAX_OPEN_WATCH_CARDS + WATCH_CRITICAL_RESERVE : MAX_OPEN_WATCH_CARDS
      if (this.openWatchCount() >= limit) {
        await this.noteWatchCardsFull(now)
        throw new WatchCardsFullError(`Too many open watch cards (${limit}). Resolve some first.`)
      }
      const fresh: OpsCardState = {
        id: this.newId(),
        key,
        kind: 'watch',
        severity: c.severity,
        title: c.title,
        body: c.body,
        url: c.url,
        channelId: this.channelFor(c.severity),
        messageId: '',
        createdAt: now,
        updatedAt: now,
        contentHash: '',
      }
      await this.deliver(fresh, undefined, { pingRoleId: c.severity === 'critical' ? this.pingRole(c.ping) : null, riseRoleId: false })
      await this.commit(fresh)
    })
  }

  /** Close a watch card with a short note. A no-op when it is not open. */
  close(id: string, note: string): Promise<void> {
    if (typeof id !== 'string' || !WATCH_ID_RE.test(id)) {
      return Promise.reject(new TypeError('A watch card id is 1 to 200 characters with no spaces.'))
    }
    const key = `watch:${id}`
    return this.lock(key, async () => {
      const open = this.findOpen(key)
      if (!open) return
      const why = this.blocked()
      if (why) throw new NotDelivered(why)
      const now = this.now().toISOString()
      const next: OpsCardState = { ...open, closedAt: now, updatedAt: now, closeNote: typeof note === 'string' && note.trim() ? note.trim().slice(0, 300) : undefined }
      await this.deliver(next, open, { pingRoleId: null, riseRoleId: false })
      await this.commit(next)
    })
  }

  /**
   * Mark an open watch card as reported fixed, with a short note saying who
   * reports it. The card stays open until a person presses Resolve, like a host
   * security card a box reports fixed. A no-op when it is not open, or already
   * marked with the same note. The next upsert of the id clears the mark.
   */
  reportFixed(id: string, note: string): Promise<void> {
    if (typeof id !== 'string' || !WATCH_ID_RE.test(id)) {
      return Promise.reject(new TypeError('A watch card id is 1 to 200 characters with no spaces.'))
    }
    const key = `watch:${id}`
    return this.lock(key, async () => {
      const open = this.findOpen(key)
      if (!open) return
      const text = typeof note === 'string' && note.trim() ? note.trim().slice(0, 300) : undefined
      if (open.reportedFixedAt && open.reportedFixedNote === text) return
      const why = this.blocked()
      if (why) throw new NotDelivered(why)
      const now = this.now().toISOString()
      const next: OpsCardState = { ...open, reportedFixedAt: open.reportedFixedAt ?? now, reportedFixedNote: text, updatedAt: now }
      try {
        await this.deliver(next, open, { pingRoleId: null, riseRoleId: false })
      } catch (err) {
        if (open.contentHash === '') await this.deps.store.save()
        throw err
      }
      await this.commit(next)
    })
  }

  // ---- buttons and commands ------------------------------------------------------

  /**
   * A person pressed a button. Changes the state only; the caller edits the
   * message from the returned card (the interaction edits it directly).
   */
  press(action: 'ack' | 'mute' | 'resolve', cardId: string, userId: string): Promise<{ ok: true; card: OpsCardState } | { ok: false; reason: string }> {
    const found = this.state.opsCards[cardId]
    if (!found) return Promise.resolve({ ok: false, reason: 'This alert is no longer tracked.' })
    return this.lock(found.key, async () => {
      const card = this.state.opsCards[cardId]
      if (!card) return { ok: false as const, reason: 'This alert is no longer tracked.' }
      if (card.closedAt) return { ok: false as const, reason: 'This alert is already closed.' }
      const now = this.now().toISOString()
      const next: OpsCardState = { ...card }
      if (action === 'ack') {
        if (card.ackedBy) return { ok: false as const, reason: `Already acknowledged by <@${card.ackedBy}>.` }
        next.ackedBy = userId
        next.ackedAt = now
      } else if (action === 'mute') {
        if (card.kind === 'watch') return { ok: false as const, reason: 'Watch cards cannot be muted.' }
        if (!this.isMuted(card.key)) {
          if (this.state.opsMutes.length >= MAX_MUTES) return { ok: false as const, reason: `At most ${MAX_MUTES} checks can be muted. Unmute some first.` }
          this.state.opsMutes.push({ key: card.key, by: userId, at: now })
        }
        next.mutedBy = userId
        next.mutedAt = now
      } else {
        next.closedAt = now
        next.closedBy = userId
      }
      next.updatedAt = now
      await this.commit(next)
      return { ok: true as const, card: next }
    })
  }

  /**
   * Close the open watch cards a person acknowledged at least `olderThanMs`
   * ago and whose id `match` accepts, oldest acknowledgment first, at most
   * MAX_AUTO_CLOSE_PER_RUN. A card nobody acknowledged is never closed here.
   * Stops at the first card Discord does not take. Resolves to the number closed.
   */
  async closeAcknowledged(match: (id: string) => boolean, olderThanMs: number, note: string): Promise<number> {
    if (!(olderThanMs > 0)) return 0
    const now = this.now()
    const due = this.openCards()
      .filter((c) => c.kind === 'watch' && c.ackedAt && match(c.key.slice('watch:'.length)) && now.getTime() - new Date(c.ackedAt).getTime() >= olderThanMs)
      .sort((a, b) => a.ackedAt!.localeCompare(b.ackedAt!))
      .slice(0, MAX_AUTO_CLOSE_PER_RUN)
    let closed = 0
    for (const c of due) {
      const done = await this.lock(c.key, async () => {
        const open = this.state.opsCards[c.id]
        if (!open || open.closedAt || open.ackedAt !== c.ackedAt) return true
        if (this.blocked()) return false
        const at = this.now().toISOString()
        const next: OpsCardState = { ...open, closedAt: at, updatedAt: at, closeNote: note.trim().slice(0, 300) || undefined }
        try {
          await this.deliver(next, open, { pingRoleId: null, riseRoleId: false })
        } catch {
          if (open.contentHash === '') await this.deps.store.save()
          return false
        }
        await this.commit(next)
        closed++
        return true
      })
      if (!done) break
    }
    return closed
  }

  /** Unmute a host check. The open card, if any, loses its muted line (best effort). */
  async unmute(kind: 'security' | 'uptime', source: string, event: string): Promise<boolean> {
    const key = `${kind}:${source}:${event}`
    const before = this.state.opsMutes.length
    this.state.opsMutes = this.state.opsMutes.filter((m) => m.key !== key)
    if (this.state.opsMutes.length === before) return false
    await this.deps.store.save()
    await this.lock(key, async () => {
      const open = this.findOpen(key)
      if (!open || !open.mutedBy) return
      const next: OpsCardState = { ...open, mutedBy: undefined, mutedAt: undefined }
      if (this.blocked()) {
        // The line goes at the next edit.
        open.mutedBy = undefined
        open.mutedAt = undefined
        await this.deps.store.save()
        return
      }
      try {
        await this.deliver(next, open, { pingRoleId: null, riseRoleId: false })
      } catch {
        // Best effort: the state is right, the message catches up at the next edit.
      }
      await this.commit(next)
    })
    return true
  }
}

/** A checked copy of a watch card. Throws a TypeError naming the bad field. */
export function checkWatchCard(card: WatchCard): WatchCard {
  if (!card || typeof card !== 'object') throw new TypeError('A watch card must be an object.')
  if (typeof card.id !== 'string' || !WATCH_ID_RE.test(card.id)) throw new TypeError('A watch card id is 1 to 200 characters with no spaces.')
  if (!SEVERITIES.includes(card.severity)) throw new TypeError('A watch card severity is critical, warning or info.')
  if (typeof card.title !== 'string' || !card.title.trim()) throw new TypeError('A watch card needs a title.')
  if (typeof card.body !== 'string') throw new TypeError('A watch card body must be a string.')
  if (card.url !== undefined && typeof card.url !== 'string') throw new TypeError('A watch card url must be a string.')
  return {
    id: card.id,
    severity: card.severity,
    ping: card.ping === true,
    title: card.title.trim().slice(0, 240),
    body: card.body.slice(0, 4000),
    url: card.url || undefined,
  }
}

export function opsKindOf(key: string): OpsKind | null {
  const k = key.split(':', 1)[0]
  return k === 'security' || k === 'uptime' || k === 'watch' ? k : null
}
