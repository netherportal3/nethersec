/**
 * GET /v1/state: what is open and who reports, for scripts and agents.
 * PURE. Read-only. Documented in docs/hub/api.md; change both together.
 *
 * Container records are summed up (counts, not package lists), and every list
 * is capped, so the answer stays small.
 */
import { activeRepos, countOpen } from './planner.js'
import { REBOOT_STALE_MS } from './reports/data.js'
import { MAX_OPEN_WATCH_CARDS, repoKey, type State } from './state.js'

export const STATE_VIEW_VERSION = 1
const MAX_LIST = 1_000

export interface CardView {
  kind: 'repo' | 'security' | 'uptime' | 'watch'
  id: string
  /** repo cards: critical, high, moderate or low. Others: critical, warning or info. */
  severity: string
  title: string
  detail: string
  source: string | null
  event: string | null
  group: string | null
  repos: string[] | null
  url: string | null
  openedAt: string
  updatedAt: string
  acked: boolean
  muted: boolean
  reportedFixed: boolean
}

export interface StateView {
  v: number
  generatedAt: string
  discord: { ready: boolean; setUp: boolean }
  repos: {
    scanning: 'on' | 'off' | 'paused'
    watched: number
    open: { critical: number; high: number; moderate: number; low: number }
    lastScanAt: string | null
  }
  cards: CardView[]
  /** The open watch cards against their cap. `refusedSince` is set while new ones are refused. */
  watch: { open: number; max: number; refusedSince: string | null; lastRefusedAt: string | null }
  hosts: Array<{ source: string; firstReportAt: string; lastReportAt: string; reports: number; open: number }>
  rebootPending: Array<{
    source: string
    since: string | null
    receivedAt: string
    stale: boolean
    checked: boolean
    livepatch: boolean | null
    packages: string[]
    more: number
    covered: number | null
    uncovered: number | null
  }>
  containers: Array<{
    box: string
    container: string
    image: string
    imageId: string | null
    builtAt: string | null
    os: string
    osVersion: string
    pm: string
    packages: number
    more: number
    receivedAt: string
  }>
}

const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString())

export function buildStateView(state: State, opts: { now: Date; discordReady: boolean; repoScanning: boolean }): StateView {
  const now = opts.now.getTime()
  const cards: CardView[] = []

  for (const c of Object.values(state.cards)) {
    if (c.resolvedAt) continue
    const open = Object.entries(c.repos).filter(([, s]) => s === 'open').map(([r]) => r)
    let title = `${c.advisoryId} in ${c.packageName}`
    let url: string | null = null
    for (const r of open) {
      const f = Object.values(state.repos[repoKey(r)]?.findings ?? {}).find((x) => x.cardId === c.id)
      if (f) {
        title = `${c.advisoryId} in ${c.packageName}: ${f.title}`
        url = f.url || null
        break
      }
    }
    cards.push({
      kind: 'repo',
      id: c.id,
      severity: c.severity,
      title,
      detail: '',
      source: null,
      event: null,
      group: null,
      repos: open,
      url,
      openedAt: c.createdAt,
      updatedAt: c.createdAt,
      acked: !!c.ackedBy,
      muted: !!c.mutedBy,
      reportedFixed: false,
    })
  }

  const openByHost = new Map<string, number>()
  let watchOpen = 0
  for (const c of Object.values(state.opsCards)) {
    if (c.closedAt) continue
    if (c.kind === 'watch') watchOpen++
    if (c.source) openByHost.set(c.source, (openByHost.get(c.source) ?? 0) + 1)
    cards.push({
      kind: c.kind,
      id: c.id,
      severity: c.severity,
      title: c.kind === 'watch' ? c.title : c.title || c.event || '',
      detail: c.body,
      source: c.source ?? null,
      event: c.event ?? null,
      group: c.group ?? null,
      repos: null,
      url: c.url ?? null,
      openedAt: c.createdAt,
      updatedAt: c.updatedAt,
      acked: !!c.ackedBy,
      muted: !!c.mutedBy,
      reportedFixed: !!c.reportedFixedAt,
    })
  }
  const rank: Record<string, number> = { critical: 0, high: 1, warning: 1, moderate: 2, info: 3, low: 3 }
  cards.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || b.updatedAt.localeCompare(a.updatedAt))

  const s = state.settings
  return {
    v: STATE_VIEW_VERSION,
    generatedAt: opts.now.toISOString(),
    discord: { ready: opts.discordReady, setUp: !!state.setup },
    repos: {
      scanning: !opts.repoScanning ? 'off' : s.paused ? 'paused' : 'on',
      watched: activeRepos(state.repos).length,
      open: countOpen(state.repos),
      lastScanAt: state.lastRun?.finishedAt ?? null,
    },
    cards: cards.slice(0, MAX_LIST),
    watch: {
      open: watchOpen,
      max: MAX_OPEN_WATCH_CARDS,
      refusedSince: state.watchCardsFull?.since ?? null,
      lastRefusedAt: state.watchCardsFull?.lastAt ?? null,
    },
    hosts: Object.values(state.hosts)
      .map((h) => ({ source: h.source, firstReportAt: h.firstReportAt, lastReportAt: h.lastReportAt, reports: h.reports, open: openByHost.get(h.source) ?? 0 }))
      .sort((a, b) => a.source.localeCompare(b.source))
      .slice(0, MAX_LIST),
    rebootPending: Object.values(state.rebootPending)
      .map((r) => ({
        source: r.source,
        since: iso(r.since),
        receivedAt: iso(r.receivedAt)!,
        stale: now - r.receivedAt > REBOOT_STALE_MS,
        checked: r.checked,
        livepatch: r.livepatch,
        packages: r.pkgs,
        more: r.more,
        covered: r.covered,
        uncovered: r.uncovered,
      }))
      .sort((a, b) => a.source.localeCompare(b.source))
      .slice(0, MAX_LIST),
    containers: Object.values(state.containers)
      .map((c) => ({
        box: c.box,
        container: c.container,
        image: c.image,
        imageId: c.imageId,
        builtAt: iso(c.builtAt),
        os: c.os,
        osVersion: c.osVersion,
        pm: c.pm,
        packages: c.packages.length,
        more: c.more,
        receivedAt: iso(c.receivedAt)!,
      }))
      .sort((a, b) => a.box.localeCompare(b.box) || a.container.localeCompare(b.container))
      .slice(0, MAX_LIST),
  }
}
