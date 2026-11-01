/**
 * The container check: the OS packages of each published container, as its box
 * reported them (the `container-packages` data event), against OSV. Everything that
 * decides a card is in containerVulns.ts; this is the I/O around it.
 *
 * Each run:
 *  1. reads the package lists the hub holds,
 *  2. asks OSV which vulnerabilities affect each (ecosystem, package, version),
 *  3. reads each matched record's details, from a cache in the hub's state: a record
 *     is fetched when it is new, when OSV says it changed (at most every 6 hours), or
 *     a week after the last fetch, at most DETAIL_FETCH_CAP per run (the rest wait,
 *     and the containers they touch count as not checked in full),
 *  4. cards a fixable critical or high, one quiet card per image, edits an open card
 *     when its fixes or containers change, sends an unchanged one again every
 *     RESURFACE_MS (so a card a person resolved too early comes back), and marks a
 *     card reported fixed once every container on it is settled. That rests on the
 *     boxes' own reports, so the card stays open for a person to Resolve and is no
 *     longer tracked or sent again. If the image needs a fix again later, it is
 *     carded anew: the open card is edited back, or a new one opens if a person
 *     resolved it.
 *
 * A read that fails changes nothing: the package lists or OSV unreadable skips the
 * run (no card, no close), and after a day of such runs one "Can't check container
 * packages" card opens, which closes when a run gets through (and is sent again every
 * RESURFACE_MS while it lasts). A cache that cannot be read is treated as empty for
 * this run and not written back.
 */
import type { WatchConfig } from './config.js'
import {
  CONTAINER_CARD_CAP,
  MAX_TRACKED_CONTAINER_CARDS,
  STALE_MS,
  containerField,
  findContainerFindings,
  idsToPairs,
  inventoryQueries,
  needsFetch,
  osvEcosystemFor,
  parseOsvDetail,
  planContainerCards,
  readCachedDetail,
  readTrackedContainerCards,
  type InventoryEntry,
  type OsvDetail,
  type PlannedContainerCard,
  type TrackedContainerCard,
} from './containerVulns.js'
import type { HttpOptions } from './http.js'
import { osvGetVuln, osvQueryBatch, type OsvHit } from './osv.js'
import type { ContainerPackagesRecord, ContainerRunReport, WatchDeps } from './types.js'
import { asRecord, closeCard, DAY_MS, jsonSize, mapLimit, reportFixedCard, RESURFACE_MS, sendCard, STATE_BUDGET } from './util.js'

export const CONTAINER_STATE_NAME = 'watch-containers'
/** The OSV record cache is split over this many state names, each under the size cap. */
export const CONTAINER_CACHE_SHARDS = 4
/** The "can't check container packages" card. */
export const CONTAINER_UNREADABLE_KEY = 'container-unreadable'
/** Runs that could not read for this long open the "can't check" card. */
export const CONTAINER_UNREADABLE_AFTER_MS = DAY_MS
/** OSV records fetched per run at most. */
export const DETAIL_FETCH_CAP = 250
/** The run stops asking OSV for more after this long. */
export const CONTAINER_BUDGET_MS = 240_000
const DETAIL_CONCURRENCY = 8

interface ContainerState {
  v: 1
  cards?: TrackedContainerCard[]
  fails?: number
  failingSince?: number
  unreadableCarded?: boolean
  /** When the "can't check" card was last sent (epoch ms). */
  unreadableSentAt?: number
}

export function containerCacheName(shard: number): string {
  return `watch-containers-osv-${shard}`
}

/** Which cache shard holds an OSV id. */
export function cacheShard(id: string): number {
  let h = 0
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0
  return h % CONTAINER_CACHE_SHARDS
}

function emptyReport(): ContainerRunReport {
  return {
    kind: 'containers',
    ok: false,
    disabled: false,
    containers: 0,
    evaluated: 0,
    incomplete: 0,
    stale: 0,
    unsupported: [],
    queries: 0,
    vulns: 0,
    detailsFetched: 0,
    detailsFailed: 0,
    detailsDeferred: 0,
    fixable: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, unfixed: 0 },
    emitted: 0,
    updated: 0,
    resent: 0,
    closed: 0,
    reportedFixed: 0,
    deferred: 0,
    cardsTracked: 0,
    errors: [],
  }
}

/** A record the hub handed over, checked. Null when it cannot be used. */
function checkRecord(raw: unknown): ContainerPackagesRecord | null {
  const r = asRecord(raw)
  if (!r || typeof r.box !== 'string' || !r.box || typeof r.container !== 'string' || !r.container) return null
  if (typeof r.image !== 'string' || !r.image || typeof r.receivedAt !== 'number' || !Number.isFinite(r.receivedAt)) return null
  if (!Array.isArray(r.packages)) return null
  const packages = r.packages.filter(
    (p): p is { name: string; version: string } => !!p && typeof p.name === 'string' && typeof p.version === 'string' && !!p.name && !!p.version,
  )
  return {
    box: r.box,
    container: r.container,
    image: r.image,
    imageId: typeof r.imageId === 'string' ? r.imageId : null,
    builtAt: typeof r.builtAt === 'number' && Number.isFinite(r.builtAt) ? r.builtAt : null,
    os: typeof r.os === 'string' ? r.os : '',
    osVersion: typeof r.osVersion === 'string' ? r.osVersion : '',
    pm: r.pm === 'dpkg' || r.pm === 'apk' ? r.pm : 'none',
    packages,
    more: typeof r.more === 'number' ? r.more : 0,
    receivedAt: r.receivedAt,
  }
}

function fail(report: ContainerRunReport, deps: WatchDeps, msg: string): void {
  report.errors.push(msg)
  deps.log(`container check: ${msg}`)
}

async function saveState(deps: WatchDeps, report: ContainerRunReport, state: ContainerState): Promise<boolean> {
  try {
    await deps.saveState(CONTAINER_STATE_NAME, state)
    return true
  } catch {
    fail(report, deps, 'the state could not be saved; the next run may send the same cards again')
    return false
  }
}

/** A run that could not read: count it, card once after a day (and again every RESURFACE_MS while it lasts), change nothing else. */
async function failRun(report: ContainerRunReport, deps: WatchDeps, state: ContainerState, now: number, msg: string): Promise<ContainerRunReport> {
  fail(report, deps, msg)
  const fails = (typeof state.fails === 'number' ? state.fails : 0) + 1
  const since = typeof state.failingSince === 'number' ? state.failingSince : now
  let carded = state.unreadableCarded === true
  let sentAt = carded && typeof state.unreadableSentAt === 'number' ? state.unreadableSentAt : undefined
  const card = () =>
    sendCard(deps.cards, {
      id: CONTAINER_UNREADABLE_KEY,
      severity: 'warning',
      ping: false,
      title: "Can't check container packages",
      body: `The container check has not got through since ${new Date(since).toISOString().slice(0, 16).replace('T', ' ')} UTC (${fails} runs): it could not read the package lists or OSV, so the OS packages in your containers are not being checked. This card closes itself when a run gets through. If you resolve it before that, it opens again within about 6 hours. It is not a clean bill of health.`,
    })
  if (!carded && now - since >= CONTAINER_UNREADABLE_AFTER_MS) {
    carded = await card()
    if (carded) {
      report.emitted++
      sentAt = now
    }
  } else if (carded && now - (sentAt ?? 0) >= RESURFACE_MS && (await card())) {
    report.resent++
    sentAt = now
  }
  const next: ContainerState = { ...state, v: 1, fails, failingSince: since, unreadableCarded: carded }
  if (sentAt !== undefined) next.unreadableSentAt = sentAt
  else delete next.unreadableSentAt
  await saveState(deps, report, next)
  report.cardsTracked = state.cards?.length ?? 0
  return report
}

function loadCache(deps: WatchDeps): { cache: Record<string, OsvDetail>; writable: boolean[] } {
  const cache: Record<string, OsvDetail> = {}
  const writable: boolean[] = []
  for (let shard = 0; shard < CONTAINER_CACHE_SHARDS; shard++) {
    try {
      const stored = asRecord(asRecord(deps.loadState(containerCacheName(shard)))?.e) ?? {}
      for (const [id, entry] of Object.entries(stored)) {
        const d = readCachedDetail(entry)
        if (d && cacheShard(id) === shard) cache[id] = d
      }
      writable.push(true)
    } catch {
      // Unreadable: start this shard empty and do not write it back, so what it held is not lost.
      writable.push(false)
    }
  }
  return { cache, writable }
}

/** Only what this run's answers named (the cache follows what is installed), newest fetch first, each shard under the budget. */
async function saveCache(deps: WatchDeps, report: ContainerRunReport, cache: Record<string, OsvDetail>, keep: string[], writable: boolean[]): Promise<void> {
  const shards: Array<Record<string, OsvDetail>> = Array.from({ length: CONTAINER_CACHE_SHARDS }, () => ({}))
  const used = new Array<number>(CONTAINER_CACHE_SHARDS).fill(20)
  for (const id of [...keep].sort((a, b) => cache[b].f - cache[a].f)) {
    const shard = cacheShard(id)
    const size = jsonSize(cache[id]) + id.length + 4
    if (used[shard] + size > STATE_BUDGET) continue
    used[shard] += size
    shards[shard][id] = cache[id]
  }
  for (let shard = 0; shard < CONTAINER_CACHE_SHARDS; shard++) {
    if (!writable[shard]) continue
    try {
      await deps.saveState(containerCacheName(shard), { v: 1, e: shards[shard] })
    } catch {
      fail(report, deps, `the OSV record cache (part ${shard + 1}) could not be saved; its records are fetched again`)
    }
  }
}

async function runContainerCheck(cfg: WatchConfig, deps: WatchDeps): Promise<ContainerRunReport> {
  const report = emptyReport()
  if (!cfg.containers.enabled) {
    report.disabled = true
    report.ok = true
    return report
  }
  try {
    const now = () => deps.now()
    const started = now()
    const deadline = started + CONTAINER_BUDGET_MS
    const http: HttpOptions = { fetch: deps.fetch }

    // Without the state a close could repeat or a card could be lost: skip the run.
    let state: ContainerState
    try {
      state = { ...(asRecord(deps.loadState(CONTAINER_STATE_NAME)) ?? {}), v: 1 } as ContainerState
    } catch {
      fail(report, deps, 'the state could not be read; skipping this run')
      return report
    }
    const tracked = readTrackedContainerCards(state.cards)

    let list: unknown
    try {
      list = deps.listContainerPackages()
      if (!Array.isArray(list)) throw new Error('not a list')
    } catch {
      return await failRun(report, deps, state, started, 'the container package lists could not be read')
    }

    const records = new Map<string, ContainerPackagesRecord>()
    const entries: InventoryEntry[] = []
    const unreadable = new Set<string>()
    for (const raw of list as unknown[]) {
      const rec = checkRecord(raw)
      if (!rec) {
        const r = asRecord(raw)
        if (r && typeof r.box === 'string' && typeof r.container === 'string') unreadable.add(`${r.box}/${r.container}`)
        continue
      }
      const field = containerField(rec)
      records.set(field, rec)
      entries.push({ field, record: rec })
      if (started - rec.receivedAt > STALE_MS) report.stale++
    }
    report.containers = records.size

    const queries = inventoryQueries(entries)
    report.queries = queries.length
    let hits: OsvHit[][]
    try {
      hits = queries.length ? await osvQueryBatch(http, queries, { deadline, now }) : []
    } catch {
      return await failRun(report, deps, state, started, 'OSV could not be read')
    }

    const { cache, writable } = loadCache(deps)
    const wanted = idsToPairs(queries, hits)
    report.vulns = wanted.size
    const toFetch = [...wanted.entries()]
      .filter(([id, w]) => needsFetch(cache[id], w.modified, w.pairs, started))
      // Never-fetched records first, then the newest ids (a fresh CVE is likelier to matter).
      .sort(([a], [b]) => Number(a in cache) - Number(b in cache) || (a < b ? 1 : a > b ? -1 : 0))
    const batch = toFetch.slice(0, DETAIL_FETCH_CAP)
    report.detailsDeferred = toFetch.length - batch.length
    await mapLimit(batch, DETAIL_CONCURRENCY, async ([id, w]) => {
      if (now() >= deadline) {
        report.detailsDeferred++
        return
      }
      try {
        const d = parseOsvDetail(await osvGetVuln(http, id), w.pairs, now())
        if (d) {
          // Keep what the cache knew for other pairs: this fetch answered only these.
          cache[id] = { ...d, x: { ...(cache[id]?.x ?? {}), ...d.x } }
          report.detailsFetched++
        } else {
          report.detailsFailed++
        }
      } catch {
        report.detailsFailed++
      }
    })

    const details = new Map<string, OsvDetail>()
    for (const id of wanted.keys()) if (cache[id]) details.set(id, cache[id])
    const result = findContainerFindings(entries, queries, hits, details)
    report.evaluated = result.evaluated.size
    report.incomplete = result.incomplete.size
    report.fixable = result.counts
    report.unsupported = [
      ...[...result.unsupported].map((f) => {
        const r = records.get(f)!
        const os = r.os ? `${r.os}${r.osVersion ? ` ${r.osVersion}` : ''}` : 'unknown OS'
        return `${f} ${os}${r.pm === 'none' ? ' (no package database)' : osvEcosystemFor(r) ? ' (no packages listed)' : ' (not checked)'}`
      }),
      ...[...unreadable].map((f) => `${f} (record not readable)`),
    ].sort()

    const plan = planContainerCards({ findings: result.findings, tracked, records, evaluated: result.evaluated, unreadable, now: started, cap: CONTAINER_CARD_CAP })
    report.deferred = plan.deferred

    const nextCards: TrackedContainerCard[] = [...plan.keep]
    // Never a page (see containerVulns.ts): a quiet card either way.
    const send = (c: PlannedContainerCard) => sendCard(deps.cards, { id: c.key, severity: 'warning', ping: false, title: c.title, body: c.body, url: c.url })
    for (const c of plan.cards) {
      if (!(await send(c))) {
        report.deferred++
        continue
      }
      report.emitted++
      nextCards.push(c.card)
    }
    // Same id: the open card is edited in place.
    for (const u of plan.updates) {
      if (await send(u)) {
        report.updated++
        nextCards.push(u.card)
      } else nextCards.push(u.previous)
    }
    // Unchanged and due: the hub edits nothing, unless a person resolved it (then it opens again).
    for (const u of plan.resend) {
      if (await send(u)) {
        report.resent++
        nextCards.push(u.card)
      } else nextCards.push(u.previous)
    }
    for (const c of plan.close) {
      if (await closeCard(deps.cards, c.card.key, c.note)) report.closed++
      // Not closed: still open, so the next run tries again.
      else nextCards.push(c.card)
    }
    // The boxes report the fix: the card says so and waits for a person. Marked, it is no
    // longer tracked, so it is not sent again. Not marked: the next run tries again.
    for (const c of plan.reportFixed) {
      if (await reportFixedCard(deps.cards, c.card.key, c.note)) report.reportedFixed++
      else nextCards.push(c.card)
    }

    let unreadableCarded = state.unreadableCarded === true
    if (unreadableCarded && (await closeCard(deps.cards, CONTAINER_UNREADABLE_KEY, 'The container check read the package lists and OSV again.'))) {
      unreadableCarded = false
      report.closed++
    }
    const cards = nextCards.sort((a, b) => a.at.localeCompare(b.at)).slice(-MAX_TRACKED_CONTAINER_CARDS)
    report.cardsTracked = cards.length
    const saved = await saveState(deps, report, {
      v: 1,
      ...(cards.length ? { cards } : {}),
      ...(unreadableCarded ? { unreadableCarded, ...(typeof state.unreadableSentAt === 'number' ? { unreadableSentAt: state.unreadableSentAt } : {}) } : {}),
    })
    await saveCache(
      deps,
      report,
      cache,
      [...wanted.keys()].filter((id) => cache[id]),
      writable,
    )
    report.ok = saved
    return report
  } catch {
    fail(report, deps, 'the run stopped unexpectedly; the next run tries again')
    return report
  }
}

/** The container check. `run()` never throws: errors are log lines and report fields. */
export function createContainerCheck(cfg: WatchConfig, deps: WatchDeps): { run(): Promise<ContainerRunReport> } {
  return { run: () => runContainerCheck(cfg, deps) }
}
