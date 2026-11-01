/**
 * The hub's saved state: one JSON document (see store.ts). Plain data only.
 *
 * Version 1 was the state of discord-cve-monitor 1.x. Version 2 adds the host
 * reports, the stored data events, the watch modules and their cards. A version
 * 1 file loads as is: every new collection starts empty, and the setup (its
 * channels and role) is kept.
 */
import type { Severity } from './scanner/advisories.js'
import type { FixLine } from './scanner/fix.js'
import type { LockEcosystem } from './scanner/lockfiles.js'

export const STATE_VERSION = 2

/** Open watch cards at most. Past it, a new watch card is refused and watchCardsFull is set. */
export const MAX_OPEN_WATCH_CARDS = 300

/** The kinds of card that are not repo advisories. */
export type OpsKind = 'security' | 'uptime' | 'watch'
export type OpsSeverity = 'critical' | 'warning' | 'info'

/**
 * One host or watch card. A host card's identity (`key`) is
 * `<kind>:<source>:<event>`; a watch card's is `watch:<card id>`. At most one
 * card per identity is open at a time.
 */
export interface OpsCardState {
  /** Short random id, used in the button ids. */
  id: string
  key: string
  kind: OpsKind
  source?: string
  event?: string
  group?: string
  severity: OpsSeverity
  /** Host: the report title (may be empty). Watch: the card title. */
  title: string
  /** Host: the report detail, shown as plain text. Watch: the card body, shown as markdown. */
  body: string
  url?: string
  channelId: string
  messageId: string
  createdAt: string
  updatedAt: string
  /** What the message shows, so an unchanged update edits nothing. */
  contentHash: string
  /**
   * A security card: the box sent `resolved`. A watch card: the module's only sign
   * of a fix came from the boxes. Either way the card stays open for a person.
   */
  reportedFixedAt?: string
  /** A watch card: who reports it fixed and what they report, shown on the card. */
  reportedFixedNote?: string
  ackedBy?: string
  ackedAt?: string
  mutedBy?: string
  mutedAt?: string
  closedAt?: string
  /** The person who pressed Resolve. Absent when a report, a watch module or the hub closed it. */
  closedBy?: string
  closeNote?: string
}

/**
 * Set while the open watch cards are at their cap, so a new watch card is
 * refused. Shown on the status board and in /v1/state. Cleared once a card
 * closes and there is room again.
 */
export interface WatchCardsFull {
  /** The first refusal since the cards filled up. */
  since: string
  /** The latest refusal. */
  lastAt: string
}

/**
 * Set when the total rate limit refused a report from a source that was under
 * its own limit: some key may be sending far more than its box should. Shown
 * on the status board. Cleared by the first report let through an hour or more
 * after the last refusal.
 */
export interface ReportsRefused {
  /** The first refusal. */
  since: string
  /** The latest refusal. */
  lastAt: string
}

/** A muted host check: no new card and no ping for this identity. */
export interface OpsMute {
  key: string
  by: string
  at: string
}

export interface HostRecord {
  source: string
  firstReportAt: string
  lastReportAt: string
  reports: number
}

/** A box's pending reboot (the `reboot-pending` data event). Times are ms epoch. */
export interface RebootPendingRecord {
  source: string
  /** When the box first saw the reboot pending. null = not sent. */
  since: number | null
  checked: boolean
  livepatch: boolean | null
  pkgs: string[]
  more: number
  /** High or Critical CVEs already covered (checked only). */
  covered: number | null
  /** High or Critical CVEs that still need the reboot (checked only). */
  uncovered: number | null
  receivedAt: number
}

/** One container's OS packages (the `container-packages` data event). Times are ms epoch. */
export interface ContainerPackagesRecord {
  box: string
  container: string
  /** The image reference without a digest, always with a tag. */
  image: string
  /** First 12 hex characters of the image id. null = not sent. */
  imageId: string | null
  builtAt: number | null
  /** os-release ID and VERSION_ID, empty when not sent. */
  os: string
  osVersion: string
  pm: 'dpkg' | 'apk' | 'none'
  /** Source packages, sorted by name then version. */
  packages: { name: string; version: string }[]
  /** How many packages the box (or the cap) left out. */
  more: number
  receivedAt: number
}

export interface Settings {
  /** `all` = every repo the token can read; `list` = only `repos`. */
  repoMode: 'all' | 'list'
  repos: string[]
  /** Skipped in `all` mode. */
  exclude: string[]
  includeForks: boolean
  includeArchived: boolean
  /** The lowest severity that gets its own alert. */
  minSeverity: Severity
  /** Ping the watcher role on critical alerts. */
  pingRole: boolean
  /** Also ping when every affected copy is a dev dependency. */
  pingDevOnly: boolean
  paused: boolean
  intervalMinutes: number
}

export interface Setup {
  categoryId: string
  criticalChannelId: string
  alertsChannelId: string
  statusChannelId: string
  roleId: string | null
  private: boolean
  dashboardMessageId?: string
}

export interface FindingState {
  advisoryId: string
  cveId: string | null
  ecosystem: LockEcosystem
  packageName: string
  severity: Severity
  malware?: boolean
  title: string
  url: string
  installed: string[]
  lockfiles: string[]
  devOnly: boolean
  fixes: FixLine[]
  firstSeen: string
  /** The alert card it was reported on, if any. */
  cardId?: string
}

export interface RepoState {
  /** Display name as GitHub returns it. */
  name: string
  /**
   * Per ecosystem: true once a read with a working advisory source recorded the
   * backlog (without alerting). Kept per ecosystem so a source that was down
   * during the first read does not cause a flood later.
   */
  baselined: Partial<Record<LockEcosystem, boolean>>
  /** Set when the repo dropped out of the scan; it is forgotten some time later. */
  droppedAt?: string
  findings: Record<string, FindingState>
  /** Consecutive scans that could not read it. */
  unreadableRuns: number
  unreadableNotified: boolean
  lastReason?: string
  lastOkAt?: string
  lockfiles: number
  skipped: Array<{ path: string; reason: string }>
}

export interface CardState {
  id: string
  channelId: string
  messageId: string
  advisoryId: string
  packageName: string
  severity: Severity
  /** Repo name -> open or fixed. */
  repos: Record<string, 'open' | 'fixed'>
  createdAt: string
  ackedBy?: string
  ackedAt?: string
  mutedBy?: string
  mutedAt?: string
  resolvedAt?: string
}

export interface Mute {
  advisoryId: string
  /** null = every repo. */
  repo: string | null
  by: string
  at: string
}

export interface RunSummary {
  startedAt: string
  finishedAt: string
  repos: number
  readable: number
  unreadable: Array<{ repo: string; reason: string }>
  notReached: number
  newAlerts: number
  fixed: number
  errors: string[]
}

export interface State {
  version: number
  setup: Setup | null
  settings: Settings
  repos: Record<string, RepoState>
  cards: Record<string, CardState>
  mutes: Mute[]
  lastRun: RunSummary | null
  /** Consecutive scans that failed before reading any repo. */
  failStreak: number
  failNotified: boolean
  /** Host and watch cards, by card id. */
  opsCards: Record<string, OpsCardState>
  opsMutes: OpsMute[]
  /** Sources that have reported, by source. */
  hosts: Record<string, HostRecord>
  /** By source. */
  rebootPending: Record<string, RebootPendingRecord>
  /** By `<box>/<container>`. */
  containers: Record<string, ContainerPackagesRecord>
  /** Each watch module's own saved state, by module name. */
  modules: Record<string, unknown>
  /** The ISO week the pending-reboot summary was last posted for. */
  rebootDigestWeek: string | null
  /** Set while new watch cards are refused because the open ones are at their cap. */
  watchCardsFull: WatchCardsFull | null
  /** Set when the total rate limit refused a source that was under its own limit. */
  reportsRefused: ReportsRefused | null
}

export function defaultSettings(intervalMinutes: number): Settings {
  return {
    repoMode: 'all',
    repos: [],
    exclude: [],
    includeForks: false,
    includeArchived: false,
    minSeverity: 'high',
    pingRole: true,
    pingDevOnly: false,
    paused: false,
    intervalMinutes,
  }
}

export function emptyState(intervalMinutes: number): State {
  return {
    version: STATE_VERSION,
    setup: null,
    settings: defaultSettings(intervalMinutes),
    repos: {},
    cards: {},
    mutes: [],
    lastRun: null,
    failStreak: 0,
    failNotified: false,
    opsCards: {},
    opsMutes: [],
    hosts: {},
    rebootPending: {},
    containers: {},
    modules: {},
    rebootDigestWeek: null,
    watchCardsFull: null,
    reportsRefused: null,
  }
}

/** The state key of a repo: GitHub names are case-insensitive. */
export function repoKey(name: string): string {
  return name.toLowerCase()
}

/** Muted by its advisory ID or by its CVE, everywhere or in this repo. */
export function isMuted(mutes: Mute[], advisoryId: string, repo: string, cveId: string | null = null): boolean {
  const r = repoKey(repo)
  const ids = new Set([advisoryId.toLowerCase(), ...(cveId ? [cveId.toLowerCase()] : [])])
  return mutes.some((m) => ids.has(m.advisoryId.toLowerCase()) && (m.repo === null || repoKey(m.repo) === r))
}

function normalizeRepo(raw: any): RepoState | null {
  if (!raw || typeof raw !== 'object' || typeof raw.name !== 'string') return null
  // Older files kept one flag for both ecosystems.
  const b = raw.baselined
  const baselined: RepoState['baselined'] = {}
  if (b === true || b?.npm === true) baselined.npm = true
  if (b === true || b?.PyPI === true) baselined.PyPI = true
  return {
    ...raw,
    baselined,
    findings: raw.findings && typeof raw.findings === 'object' ? raw.findings : {},
    unreadableRuns: Number(raw.unreadableRuns) || 0,
    unreadableNotified: raw.unreadableNotified === true,
    lockfiles: Number(raw.lockfiles) || 0,
    skipped: Array.isArray(raw.skipped) ? raw.skipped : [],
  }
}

/**
 * Bring a loaded document up to the current shape: missing fields get their
 * defaults, so an older file (or a hand edit) never crashes the bot.
 */
export function normalizeState(raw: any, intervalMinutes: number): State {
  const base = emptyState(intervalMinutes)
  if (!raw || typeof raw !== 'object') return base
  const settings = { ...base.settings, ...(raw.settings && typeof raw.settings === 'object' ? raw.settings : {}) }
  if (!Array.isArray(settings.repos)) settings.repos = []
  if (!Array.isArray(settings.exclude)) settings.exclude = []
  const repos: Record<string, RepoState> = {}
  if (raw.repos && typeof raw.repos === 'object') {
    for (const [k, r] of Object.entries(raw.repos)) {
      const repo = normalizeRepo(r)
      if (repo) repos[k] = repo
    }
  }
  return {
    version: STATE_VERSION,
    setup: raw.setup && typeof raw.setup === 'object' ? raw.setup : null,
    settings,
    repos,
    cards: raw.cards && typeof raw.cards === 'object' ? raw.cards : {},
    mutes: Array.isArray(raw.mutes) ? raw.mutes : [],
    lastRun: raw.lastRun && typeof raw.lastRun === 'object' ? raw.lastRun : null,
    failStreak: Number(raw.failStreak) || 0,
    failNotified: raw.failNotified === true,
    opsCards: opsCardsOf(raw.opsCards),
    opsMutes: Array.isArray(raw.opsMutes) ? raw.opsMutes.filter((m: any) => m && typeof m.key === 'string') : [],
    hosts: filtered<HostRecord>(raw.hosts, (h) => typeof h.source === 'string' && typeof h.firstReportAt === 'string' && typeof h.lastReportAt === 'string' && typeof h.reports === 'number'),
    rebootPending: filtered<RebootPendingRecord>(raw.rebootPending, (r) => typeof r.source === 'string' && typeof r.receivedAt === 'number' && Array.isArray(r.pkgs)),
    containers: filtered<ContainerPackagesRecord>(
      raw.containers,
      (c) => typeof c.box === 'string' && typeof c.container === 'string' && typeof c.image === 'string' && typeof c.receivedAt === 'number' && Array.isArray(c.packages),
    ),
    modules: recordOf(raw.modules),
    rebootDigestWeek: typeof raw.rebootDigestWeek === 'string' ? raw.rebootDigestWeek : null,
    watchCardsFull: spanOf(raw.watchCardsFull),
    reportsRefused: spanOf(raw.reportsRefused),
  }
}

/** A `{ since, lastAt }` record, or null. */
function spanOf(raw: any): { since: string; lastAt: string } | null {
  return raw && typeof raw === 'object' && typeof raw.since === 'string' && typeof raw.lastAt === 'string' ? { since: raw.since, lastAt: raw.lastAt } : null
}

/** A plain object as a record, or empty. */
function recordOf<T>(raw: unknown): Record<string, T> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  const out: Record<string, T> = {}
  for (const [k, v] of Object.entries(raw)) if (v !== undefined && v !== null) out[k] = v as T
  return out
}

/** Entries that are not objects of the expected shape (a hand edit, say) are dropped. */
function filtered<T>(raw: unknown, ok: (v: any) => boolean): Record<string, T> {
  const out: Record<string, T> = {}
  for (const [k, v] of Object.entries(recordOf<any>(raw))) if (typeof v === 'object' && ok(v)) out[k] = v as T
  return out
}

/** Cards missing what every card needs (a hand edit, say) are dropped. */
function opsCardsOf(raw: unknown): Record<string, OpsCardState> {
  const out: Record<string, OpsCardState> = {}
  for (const [id, c] of Object.entries(recordOf<any>(raw))) {
    const ok =
      typeof c === 'object' &&
      c.id === id &&
      ['key', 'channelId', 'messageId', 'createdAt', 'updatedAt', 'title', 'body'].every((f) => typeof c[f] === 'string') &&
      ['security', 'uptime', 'watch'].includes(c.kind) &&
      ['critical', 'warning', 'info'].includes(c.severity)
    if (ok) out[id] = { contentHash: '', ...c }
  }
  return out
}
