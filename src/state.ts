/**
 * The bot's saved state: one JSON document (see store.ts). Plain data only.
 */
import type { Severity } from './scanner/advisories.js'
import type { FixLine } from './scanner/fix.js'
import type { LockEcosystem } from './scanner/lockfiles.js'

export const STATE_VERSION = 1

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
  return {
    version: STATE_VERSION,
    setup: raw.setup && typeof raw.setup === 'object' ? raw.setup : null,
    settings,
    repos: raw.repos && typeof raw.repos === 'object' ? raw.repos : {},
    cards: raw.cards && typeof raw.cards === 'object' ? raw.cards : {},
    mutes: Array.isArray(raw.mutes) ? raw.mutes : [],
    lastRun: raw.lastRun && typeof raw.lastRun === 'object' ? raw.lastRun : null,
    failStreak: Number(raw.failStreak) || 0,
    failNotified: raw.failNotified === true,
  }
}
