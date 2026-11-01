/**
 * The advisory watch: security advisories for software no lockfile names (servers,
 * daemons, agents), read from each component's own feed, plus CISA's catalog of
 * bugs exploited in the wild and, when turned on, the kernel feed (kernel.ts).
 *
 * Only what watch.json lists is watched. Each run reads every feed and opens one
 * card per new fix: advisories of one component that one update closes share a
 * card. Critical pages, high is a quiet card, a bulletin with no severity is a
 * quiet card, medium and low are only counted. A KEV entry for a listed component
 * pages, one card per CVE, whether or not a fix is out.
 *
 * The first read of a feed records what is there and cards only what was published
 * in the last BASELINE_LOOKBACK_DAYS (the KEV catalog's first read cards nothing:
 * every entry would page, and the recent ones were known when the watch started).
 * A feed that cannot be read changes nothing. One that has failed every read for
 * a day gets one "can't read" card, which closes when a read gets through. While
 * the feed still fails, that card is sent again every RESURFACE_MS, so one a
 * person resolved too early comes back. An advisory or KEV card is a notice: it
 * is sent once, and a person resolves it.
 *
 * Whether an advisory applies (a feature you do not use, a platform you do not run)
 * is the reader's call: the card says where the component runs, from watch.json.
 */
import type { WatchComponent, WatchConfig } from './config.js'
import { KERNEL_FEED_ID } from './config.js'
import {
  cardsAdvisory,
  groupAdvisoriesByFix,
  kevInventory,
  parseGithubAdvisories,
  parseKevCatalog,
  parseRssAdvisories,
  type Advisory,
  type KevProduct,
} from './feeds.js'
import { fetchText, GITHUB_API, type HttpOptions } from './http.js'
import { applyKernelRead, readKernelFeed, type KernelState } from './kernel.js'
import type { AdvisoryRunReport, WatchCard, WatchDeps } from './types.js'
import { asArray, asRecord, cardBody, cardId, closeCard, DAY_MS, esc, isoDay, isSafeUrl, joinAnd, mapLimit, RESURFACE_MS, sendCard, truncate } from './util.js'

/** CISA's Known Exploited Vulnerabilities catalog, the whole of it in one document. */
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
/** On a feed's first read, advisories newer than this are carded; older ones are only recorded. */
export const BASELINE_LOOKBACK_DAYS = 30
/** Most cards per run. The rest stay unseen and card on a later run. */
export const ADVISORY_CARD_CAP = 6
/** A feed that has failed every read for this long gets a "can't read" card. */
export const FEED_UNREADABLE_AFTER_MS = DAY_MS
/** Seen ids kept per feed beyond the ones it still lists. */
const SEEN_CAP = 300
const GITHUB_PAGE = 20
/** Items read from one RSS feed, from the top. */
const RSS_ITEM_CAP = 500
const MAX_FEED_BYTES = 2 * 1024 * 1024
const MAX_KEV_BYTES = 8 * 1024 * 1024
const READ_CONCURRENCY = 8
const GROUP_LIST_MAX = 1600

interface FeedState {
  seen?: string[]
  etag?: string
  fails?: number
  failingSince?: number
  unreadableCarded?: boolean
  /** When the "can't read" card was last sent (epoch ms). */
  unreadableSentAt?: number
  /** The first read left advisories for a later run, so that run still cards only recent ones. */
  baselining?: boolean
}

type FeedRead = { status: 'ok'; advisories: Advisory[]; etag?: string } | { status: 'not-modified' } | { status: 'failed'; code?: number }

/** The state name of a component's feed. */
export function feedStateName(componentId: string): string {
  return `watch-advisories-${componentId}`
}

export function advisoryCardKey(componentId: string, advisoryId: string): string {
  return cardId('advisory', componentId, advisoryId)
}

/** A lone advisory keeps its own key; a group's key names every advisory in it, so a later one with the same fix gets its own card. */
export function advisoryGroupCardKey(componentId: string, group: Advisory[]): string {
  return advisoryCardKey(componentId, group.length === 1 ? group[0].id : group.map((a) => a.id).sort().join('+'))
}

export function feedUnreadableKey(feedId: string): string {
  return cardId('advisory-unreadable', feedId)
}

/**
 * An advisory or KEV card: a notice, sent once, that nothing here closes. The
 * hub closes an acknowledged one after advisoryCards.closeAcknowledgedAfterDays.
 * Kernel cards share the prefix but track a live problem, so they are left out.
 */
export function isAdvisoryNoticeId(id: string): boolean {
  return id.startsWith('advisory:') && !id.startsWith(`advisory:${KERNEL_FEED_ID}:`)
}

function emptyReport(): AdvisoryRunReport {
  return {
    kind: 'advisories',
    ok: true,
    feeds: 0,
    read: 0,
    notModified: 0,
    failed: [],
    baselined: [],
    emitted: 0,
    closed: 0,
    resent: 0,
    belowThreshold: 0,
    skipped: 0,
    deferred: 0,
    errors: [],
  }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

async function readFeed(http: HttpOptions, c: WatchComponent, prev: FeedState, inventory: KevProduct[]): Promise<FeedRead> {
  const etag = Array.isArray(prev.seen) && typeof prev.etag === 'string' ? prev.etag : undefined
  const f = c.feed
  if (!f) return { status: 'failed' }
  try {
    if (f.kind === 'kev') {
      const res = await fetchText(http, KEV_URL, 'json', { etag, cap: MAX_KEV_BYTES })
      if (res.status !== 'ok') return res
      const advisories = parseKevCatalog(JSON.parse(res.text), inventory)
      return advisories ? { status: 'ok', advisories, etag: res.etag } : { status: 'failed' }
    }
    if (f.kind === 'rss') {
      const res = await fetchText(http, f.url, 'rss', { etag, cap: MAX_FEED_BYTES })
      if (res.status !== 'ok') return res
      const advisories = parseRssAdvisories(res.text, c.name, f.match)
      return advisories ? { status: 'ok', advisories: advisories.slice(0, RSS_ITEM_CAP), etag: res.etag } : { status: 'failed' }
    }
    const url = `${GITHUB_API}/repos/${f.repo}/security-advisories?state=published&sort=published&direction=desc&per_page=${GITHUB_PAGE}`
    const res = await fetchText(http, url, 'github', { etag, cap: MAX_FEED_BYTES })
    if (res.status !== 'ok') return res
    const advisories = parseGithubAdvisories(JSON.parse(res.text))
    return advisories ? { status: 'ok', advisories, etag: res.etag } : { status: 'failed' }
  } catch {
    return { status: 'failed' }
  }
}

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

/** One line per advisory, the feed's text escaped. Lines that do not fit become "And N more." */
function groupList(items: Advisory[]): string {
  const lines: string[] = []
  let used = 0
  for (const [i, a] of items.entries()) {
    const line = `${esc(a.title)}: ${esc(a.summary)}${isSafeUrl(a.url) ? ` ${a.url}` : ''}`
    if (used + line.length > GROUP_LIST_MAX) {
      lines.push(`And ${items.length - i} more.`)
      break
    }
    lines.push(line)
    used += line.length + 1
  }
  return lines.join('\n')
}

function publishedRange(items: Advisory[]): string {
  const days = [...new Set(items.flatMap((a) => (a.published === null ? [] : [isoDay(a.published)])))].sort()
  return days.length <= 1 ? days[0] || 'not given' : `${days[0]} to ${days[days.length - 1]}`
}

/** The page for a KEV entry of a listed component. The catalog's text is escaped. */
export function kevCard(componentId: string, a: Advisory): WatchCard {
  const m = a.kev!
  const names = joinAnd(m.products.map((p) => p.name))
  const where = m.products.filter((p) => p.runsOn)
  const runsOn = where.length === 0 ? null : m.products.length === 1 ? where[0].runsOn : where.map((p) => `${p.name}: ${p.runsOn}`).join('; ')
  return {
    id: advisoryCardKey(componentId, a.id),
    severity: 'critical',
    ping: true,
    title: `Exploited in the wild: ${a.id} in ${names}`,
    body: cardBody(
      `${esc(a.summary)} CISA lists it as exploited in the wild. Check whether it applies where it runs, then patch or mitigate it by the due date. A fix may not be out yet.`,
      [
        ['Runs on', runsOn],
        ['Listed as', esc(m.listedAs)],
        ['Added to KEV', m.dateAdded ? esc(m.dateAdded) : 'not given'],
        ['CISA due date', m.dueDate ? esc(m.dueDate) : 'not given'],
        ['Ransomware', m.ransomware ? 'known to be used in ransomware campaigns' : null],
      ],
    ),
    url: a.url,
  }
}

/** The card for one fix: a lone advisory, or every advisory of the component that the same update closes. The feed's text is escaped. */
export function advisoryCard(c: WatchComponent, group: Advisory[]): WatchCard {
  const items = [...group].sort((a, b) => a.title.localeCompare(b.title, 'en', { numeric: true }))
  const lone = items.length === 1 ? items[0] : null
  const severity = items.some((a) => a.severity === 'critical') ? 'critical' : items.some((a) => a.severity === 'high') ? 'high' : null
  const pages = severity === 'critical'
  const label = severity === 'critical' ? 'Critical' : severity === 'high' ? 'High' : 'Security'
  const advice = `Check whether it applies where ${c.name} runs, and compare the fixed version with what is installed there.`
  const fixedIn = items[0].fixedIn
  return {
    id: advisoryGroupCardKey(c.id, items),
    severity: pages ? 'critical' : 'warning',
    ping: pages,
    title: lone ? `${label} advisory for ${c.name}: ${lone.title}` : `${label} advisories for ${c.name}: ${joinAnd(items.map((a) => a.title))}`,
    body: cardBody(lone ? `${esc(lone.summary)} ${advice}` : `${groupList(items)}\n\nAll ${items.length} are fixed in ${esc(fixedIn ?? '')}. ${advice}`, [
      ['Runs on', c.runsOn],
      ['Fixed in', fixedIn ? esc(fixedIn) : 'not listed'],
      ['Published', publishedRange(items)],
    ]),
    ...(items.find((a) => a.url) ? { url: items.find((a) => a.url)!.url } : {}),
  }
}

function unreadableCard(feedId: string, name: string, fails: number, since: number): WatchCard {
  return {
    id: feedUnreadableKey(feedId),
    severity: 'warning',
    ping: false,
    title: `Can't read ${name} advisories`,
    body: `The ${name} advisory feed has failed every read since ${new Date(since).toISOString().slice(0, 16).replace('T', ' ')} UTC (${fails} reads), so new ${name} advisories are not being checked. This card closes itself when a read gets through. If you resolve it before that, it opens again within about 6 hours. It is not a clean bill of health.`,
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

interface Ctx {
  deps: WatchDeps
  report: AdvisoryRunReport
  budget: { left: number }
  now: number
}

function readState(ctx: Ctx, name: string): Record<string, unknown> | null {
  try {
    const raw = ctx.deps.loadState(name)
    return asRecord(raw) ?? {}
  } catch {
    return null
  }
}

async function writeState(ctx: Ctx, name: string, value: unknown): Promise<void> {
  try {
    await ctx.deps.saveState(name, value)
  } catch {
    ctx.report.ok = false
    const msg = `advisory watch: could not save ${name}; the next run reads this feed as if this run had not happened`
    ctx.report.errors.push(msg)
    ctx.deps.log(msg)
  }
}

/** A failed read: count it, card once after a day (and again every RESURFACE_MS while it lasts), change nothing else. */
async function onFailure(ctx: Ctx, feedId: string, name: string, prev: FeedState, code: number | undefined): Promise<FeedState> {
  ctx.report.failed.push(feedId)
  ctx.deps.log(`advisory watch: could not read the ${feedId} feed${code ? ` (HTTP ${code})` : ''}`)
  const fails = (typeof prev.fails === 'number' ? prev.fails : 0) + 1
  const since = typeof prev.failingSince === 'number' ? prev.failingSince : ctx.now
  let carded = prev.unreadableCarded === true
  let sentAt = carded && typeof prev.unreadableSentAt === 'number' ? prev.unreadableSentAt : undefined
  if (!carded && ctx.now - since >= FEED_UNREADABLE_AFTER_MS) {
    carded = await sendCard(ctx.deps.cards, unreadableCard(feedId, name, fails, since))
    if (carded) {
      ctx.report.emitted++
      sentAt = ctx.now
    }
  } else if (carded && ctx.now - (sentAt ?? 0) >= RESURFACE_MS) {
    if (await sendCard(ctx.deps.cards, unreadableCard(feedId, name, fails, since))) {
      ctx.report.resent++
      sentAt = ctx.now
    }
  }
  const next: FeedState = { ...prev, fails, failingSince: since, unreadableCarded: carded }
  if (sentAt !== undefined) next.unreadableSentAt = sentAt
  else delete next.unreadableSentAt
  return next
}

/** A good read: close an open "can't read" card and clear the streak. */
async function onReadable(ctx: Ctx, feedId: string, name: string, prev: FeedState): Promise<FeedState> {
  const next: FeedState = { ...prev }
  delete next.fails
  delete next.failingSince
  if (prev.unreadableCarded) {
    if (await closeCard(ctx.deps.cards, feedUnreadableKey(feedId), `The ${name} advisory feed reads again, and this run checked it.`)) {
      ctx.report.closed++
      delete next.unreadableCarded
      delete next.unreadableSentAt
    }
    // Not closed: keep the flag so the next readable run closes it.
  } else {
    delete next.unreadableCarded
    delete next.unreadableSentAt
  }
  return next
}

function isBaseline(prev: FeedState): boolean {
  return !Array.isArray(prev.seen) || prev.baselining === true
}

/** Applies one feed's good read: cards what is new, and returns the next state. */
async function applyRead(ctx: Ctx, c: WatchComponent, prev: FeedState, r: Extract<FeedRead, { status: 'ok' }>): Promise<FeedState> {
  const { report, now } = ctx
  const isKev = c.feed?.kind === 'kev'
  const baseline = isBaseline(prev)
  if (baseline) report.baselined.push(c.id)
  const seen = new Set(asArray(prev.seen).filter((s): s is string => typeof s === 'string'))
  let complete = true
  const toCard: Advisory[] = []
  for (const a of r.advisories) {
    if (seen.has(a.id)) continue
    const recent = !isKev && a.published !== null && now - a.published <= BASELINE_LOOKBACK_DAYS * DAY_MS
    if (!cardsAdvisory(a) || (baseline && !recent)) {
      if (!baseline && a.noCard) report.skipped++
      else if (!baseline && !cardsAdvisory(a)) report.belowThreshold++
      seen.add(a.id)
      continue
    }
    toCard.push(a)
  }
  // KEV entries are one card per CVE; a feed's advisories share a card per fix.
  const groups = isKev ? toCard.map((a) => [a]) : groupAdvisoriesByFix(toCard)
  for (const group of groups) {
    const card = isKev ? kevCard(c.id, group[0]) : advisoryCard(c, group)
    if (ctx.budget.left <= 0 || !(await sendCard(ctx.deps.cards, card))) {
      report.deferred += group.length
      complete = false
      continue
    }
    ctx.budget.left--
    report.emitted++
    for (const a of group) seen.add(a.id)
  }
  // Every id the feed still lists is kept; past that, the newest SEEN_CAP.
  const listed = new Set(r.advisories.map((a) => a.id))
  const all = [...seen]
  const next: FeedState = { ...prev, seen: [...all.filter((id) => !listed.has(id)).slice(-SEEN_CAP), ...all.filter((id) => listed.has(id))] }
  // A deferred advisory must be read again next run, so its feed keeps no ETag.
  if (complete && r.etag) next.etag = truncate(r.etag, 200)
  else delete next.etag
  if (baseline && !complete) next.baselining = true
  else delete next.baselining
  return next
}

async function runAdvisoryWatch(cfg: WatchConfig, deps: WatchDeps): Promise<AdvisoryRunReport> {
  const report = emptyReport()
  const ctx: Ctx = { deps, report, budget: { left: ADVISORY_CARD_CAP }, now: 0 }
  try {
    ctx.now = deps.now()
    const http: HttpOptions = { fetch: deps.fetch, githubToken: deps.githubToken }
    const inventory = kevInventory(cfg.components)
    // The KEV feed first, then the kernel's, so the card cap never holds a page back behind a quiet card.
    const withFeed = cfg.components.filter((c) => c.feed)
    const ordered = [...withFeed.filter((c) => c.feed?.kind === 'kev'), ...withFeed.filter((c) => c.feed?.kind !== 'kev')]
    report.feeds = ordered.length + (cfg.kernel ? 1 : 0)

    const states = new Map<string, Record<string, unknown> | null>()
    for (const c of ordered) states.set(c.id, readState(ctx, feedStateName(c.id)))
    const kernelPrev = cfg.kernel ? readState(ctx, feedStateName(KERNEL_FEED_ID)) : null

    // A state that cannot be read would re-baseline its feed, so that feed sits this run out.
    const skip = (id: string, state: unknown) => {
      if (state !== null) return false
      report.ok = false
      const msg = `advisory watch: could not load ${feedStateName(id)}; skipping that feed this run`
      report.errors.push(msg)
      deps.log(msg)
      return true
    }
    const readable = ordered.filter((c) => !skip(c.id, states.get(c.id)))
    const kernelOn = cfg.kernel !== null && !skip(KERNEL_FEED_ID, kernelPrev)

    const [reads, kernelRead] = await Promise.all([
      mapLimit(readable, READ_CONCURRENCY, (c) => readFeed(http, c, (states.get(c.id) ?? {}) as FeedState, inventory)),
      kernelOn && cfg.kernel ? readKernelFeed(http, cfg.kernel, (kernelPrev ?? {}) as KernelState, ctx.now).catch(() => null) : Promise.resolve(null),
    ])

    const apply = async (c: WatchComponent, r: FeedRead) => {
      let state = (states.get(c.id) ?? {}) as FeedState
      if (r.status === 'failed') {
        state = await onFailure(ctx, c.id, c.name, state, r.code)
      } else {
        state = await onReadable(ctx, c.id, c.name, state)
        if (r.status === 'not-modified') report.notModified++
        else {
          report.read++
          state = await applyRead(ctx, c, state, r)
        }
      }
      await writeState(ctx, feedStateName(c.id), state)
    }

    const kevFirst = readable.filter((c) => c.feed?.kind === 'kev')
    for (const c of kevFirst) await apply(c, reads[readable.indexOf(c)])

    if (kernelOn && cfg.kernel) {
      let state = (kernelPrev ?? {}) as KernelState
      const name = 'Linux kernel'
      if (!kernelRead) {
        state = (await onFailure(ctx, KERNEL_FEED_ID, name, state as FeedState, undefined)) as KernelState
      } else {
        state = (await onReadable(ctx, KERNEL_FEED_ID, name, state as FeedState)) as KernelState
        report.read++
        if (kernelRead.baseline) report.baselined.push(KERNEL_FEED_ID)
        state = await applyKernelRead({ cards: deps.cards, kernel: cfg.kernel, report, budget: ctx.budget }, state, kernelRead)
      }
      await writeState(ctx, feedStateName(KERNEL_FEED_ID), state)
    }

    for (const c of readable) if (c.feed?.kind !== 'kev') await apply(c, reads[readable.indexOf(c)])
  } catch {
    report.ok = false
    const msg = 'advisory watch: the run stopped unexpectedly; the next run tries again'
    report.errors.push(msg)
    deps.log(msg)
  }
  return report
}

/** The advisory watch. `run()` never throws: errors are log lines and report fields. */
export function createAdvisoryWatch(cfg: WatchConfig, deps: WatchDeps): { run(): Promise<AdvisoryRunReport> } {
  return { run: () => runAdvisoryWatch(cfg, deps) }
}
