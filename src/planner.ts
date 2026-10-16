/**
 * Turn a scan into what to post and what to remember. PURE: no I/O, no clock.
 *
 * Rules (each one keeps the channel quiet unless something real changed):
 *   1. The first successful read of a repo's npm or Python dependencies is a
 *      BASELINE: everything open is recorded and summed up in one status
 *      message, never one alert per advisory. Malware is the exception: it
 *      always gets its own alert.
 *   2. After that, an advisory that is new in a repo (or whose severity rose to
 *      the alert threshold) gets an alert, unless it is below the threshold or
 *      muted (by advisory ID or CVE). Malware always alerts.
 *   3. One alert per advisory: every repo it is new in this scan shares one card.
 *   4. At most CARD_CAP cards per scan. The rest are recorded and listed in one
 *      overflow message, never silently dropped.
 *   5. Nothing reads as fixed unless it was actually checked. A repo that cannot
 *      be read keeps what it remembered and is reported once after
 *      UNREADABLE_NOTICE_RUNS scans in a row. An ecosystem whose advisory source
 *      failed keeps its findings. A finding whose lockfile was skipped this scan
 *      (too big, unparseable, over the cap) or whose repo tree came back
 *      truncated is kept, not fixed.
 *   6. A repo that drops out of the scan (removed, or the token lost access) is
 *      kept for DROPPED_TTL_MS, so if it comes back its new advisories still
 *      alert instead of being quietly baselined again.
 */
import { SEVERITY_RANK, type Severity } from './scanner/advisories.js'
import type { LockEcosystem } from './scanner/lockfiles.js'
import type { Finding } from './scanner/match.js'
import type { ScanResult } from './scanner/scan.js'
import { isMuted, repoKey, type FindingState, type Mute, type RepoState, type Settings } from './state.js'

export const CARD_CAP = 10
export const UNREADABLE_NOTICE_RUNS = 2
export const DROPPED_TTL_MS = 30 * 24 * 60 * 60 * 1000
const ECOSYSTEMS: LockEcosystem[] = ['npm', 'PyPI']

export interface AlertGroup {
  /** `<ecosystem>:<advisory id>:<package>` */
  groupKey: string
  advisoryId: string
  packageName: string
  ecosystem: LockEcosystem
  severity: Severity
  malware: boolean
  /** One finding per repo the advisory is new in. */
  members: Finding[]
  channel: 'critical' | 'alerts'
  ping: boolean
}

export interface FixedItem {
  repo: string
  key: string
  finding: FindingState
}

export interface Plan {
  alerts: AlertGroup[]
  overflow: AlertGroup[]
  /** Repos (or ecosystems of a repo) read for the first time, with what was open. */
  baselined: Array<{ repo: string; findings: Finding[] }>
  fixed: FixedItem[]
  unreadableNotices: Array<{ repo: string; reason: string }>
  recovered: string[]
  /** Repos no longer scanned (removed from the watch list, or the token lost access). */
  dropped: string[]
  nextRepos: Record<string, RepoState>
}

export function severityAtLeast(s: Severity, min: Severity): boolean {
  return SEVERITY_RANK[s] >= SEVERITY_RANK[min]
}

export function groupKeyOf(f: Pick<Finding, 'ecosystem' | 'advisoryId' | 'packageName'>): string {
  return `${f.ecosystem}:${f.advisoryId}:${f.packageName}`
}

function toState(f: Finding, firstSeen: string, cardId?: string): FindingState {
  const s: FindingState = {
    advisoryId: f.advisoryId,
    cveId: f.cveId,
    ecosystem: f.ecosystem,
    packageName: f.packageName,
    severity: f.severity,
    title: f.title,
    url: f.url,
    installed: f.installed,
    lockfiles: f.lockfiles,
    devOnly: f.devOnly,
    fixes: f.fixes,
    firstSeen,
  }
  if (f.malware) s.malware = true
  if (cardId) s.cardId = cardId
  return s
}

export function shouldPing(
  settings: Pick<Settings, 'pingRole' | 'pingDevOnly'>,
  g: Pick<AlertGroup, 'malware' | 'severity' | 'members'>,
): boolean {
  if (!settings.pingRole) return false
  if (g.malware) return true
  if (g.severity !== 'critical') return false
  return settings.pingDevOnly || g.members.some((m) => !m.devOnly)
}

/** Repos still being watched (not dropped). */
export function activeRepos(repos: Record<string, RepoState>): RepoState[] {
  return Object.values(repos).filter((r) => !r.droppedAt)
}

function withoutDropped(r: RepoState): RepoState {
  if (!r.droppedAt) return r
  const { droppedAt: _dropped, ...rest } = r
  return rest
}

export function planScan(input: {
  scan: ScanResult
  repos: Record<string, RepoState>
  settings: Settings
  mutes: Mute[]
  now: string
}): Plan {
  const { scan, settings, mutes, now } = input
  const nextRepos: Record<string, RepoState> = {}
  const candidates: Finding[] = []
  const baselined: Plan['baselined'] = []
  const fixed: FixedItem[] = []
  const unreadableNotices: Plan['unreadableNotices'] = []
  const recovered: string[] = []
  const muted = (f: Finding) => isMuted(mutes, f.advisoryId, f.repo, f.cveId)

  for (const r of scan.repos) {
    const key = repoKey(r.repo)
    const prev = input.repos[key]

    if (r.status === 'not-reached') {
      if (prev) nextRepos[key] = withoutDropped(prev)
      continue
    }

    if (r.status === 'unreadable') {
      const base: RepoState = prev
        ? withoutDropped(prev)
        : { name: r.repo, baselined: {}, findings: {}, unreadableRuns: 0, unreadableNotified: false, lockfiles: 0, skipped: [] }
      const next: RepoState = { ...base, unreadableRuns: base.unreadableRuns + 1, lastReason: r.reason }
      if (next.unreadableRuns >= UNREADABLE_NOTICE_RUNS && !next.unreadableNotified) {
        next.unreadableNotified = true
        unreadableNotices.push({ repo: r.repo, reason: r.reason ?? 'Unknown reason.' })
      }
      nextRepos[key] = next
      continue
    }

    // Readable.
    if (prev?.unreadableNotified) recovered.push(r.repo)
    const findings: Record<string, FindingState> = {}
    const baseline: Partial<Record<LockEcosystem, boolean>> = { ...(prev?.baselined ?? {}) }
    const firstSeenHere: Finding[] = []
    // A finding from a lockfile that could not be read this scan cannot be called fixed.
    const unread = new Set(r.skipped.map((s) => s.path))
    const cannotTell = (f: FindingState) => r.treeTruncated || f.lockfiles.some((p) => unread.has(p))

    for (const eco of ECOSYSTEMS) {
      const before = Object.entries(prev?.findings ?? {}).filter(([, f]) => f.ecosystem === eco)
      if (!scan.ecosystemsOk[eco]) {
        // Its advisory source failed: keep what it had, nothing new, nothing fixed.
        for (const [k, f] of before) findings[k] = f
        continue
      }
      const current = r.findings.filter((f) => f.ecosystem === eco)

      if (!baseline[eco]) {
        for (const f of current) {
          findings[f.key] = toState(f, now)
          firstSeenHere.push(f)
          if (f.malware && !muted(f)) candidates.push(f)
        }
        baseline[eco] = true
        continue
      }

      const prevFindings = prev?.findings ?? {}
      for (const f of current) {
        const old = prevFindings[f.key]
        const rose = old && !severityAtLeast(old.severity, settings.minSeverity) && severityAtLeast(f.severity, settings.minSeverity)
        if (!old || rose) {
          findings[f.key] = toState(f, old?.firstSeen ?? now)
          const alertWorthy = f.malware === true || severityAtLeast(f.severity, settings.minSeverity)
          if (alertWorthy && !muted(f)) candidates.push(f)
        } else {
          findings[f.key] = toState(f, old.firstSeen, old.cardId)
        }
      }
      const seen = new Set(current.map((f) => f.key))
      for (const [k, f] of before) {
        if (seen.has(k)) continue
        if (cannotTell(f)) findings[k] = f
        else fixed.push({ repo: r.repo, key: k, finding: f })
      }
    }

    if (!prev || firstSeenHere.length) baselined.push({ repo: r.repo, findings: firstSeenHere })

    nextRepos[key] = {
      name: r.repo,
      baselined: baseline,
      findings,
      unreadableRuns: 0,
      unreadableNotified: false,
      lastOkAt: now,
      lockfiles: r.lockfiles.length,
      skipped: r.skipped.slice(0, 20),
    }
  }

  // Repos it watched before that this scan no longer covers: kept for a while, then forgotten.
  const scanned = new Set(scan.repos.map((r) => repoKey(r.repo)))
  const dropped: string[] = []
  const nowMs = Date.parse(now)
  for (const [k, r] of Object.entries(input.repos)) {
    if (scanned.has(k)) continue
    if (!r.droppedAt) {
      dropped.push(r.name)
      nextRepos[k] = { ...r, droppedAt: now }
    } else if (nowMs - Date.parse(r.droppedAt) < DROPPED_TTL_MS) {
      nextRepos[k] = r
    }
  }

  // One alert per advisory across repos.
  const groups = new Map<string, AlertGroup>()
  for (const f of candidates) {
    const gk = groupKeyOf(f)
    let g = groups.get(gk)
    if (!g) {
      g = {
        groupKey: gk,
        advisoryId: f.advisoryId,
        packageName: f.packageName,
        ecosystem: f.ecosystem,
        severity: f.severity,
        malware: f.malware === true,
        members: [],
        channel: 'alerts',
        ping: false,
      }
      groups.set(gk, g)
    }
    g.members.push(f)
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[g.severity]) g.severity = f.severity
    if (f.malware) g.malware = true
  }
  const ordered = [...groups.values()]
  for (const g of ordered) {
    g.members.sort((a, b) => a.repo.localeCompare(b.repo))
    g.channel = g.malware || g.severity === 'critical' ? 'critical' : 'alerts'
    g.ping = shouldPing(settings, g)
  }
  ordered.sort(
    (a, b) =>
      Number(b.malware) - Number(a.malware) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      b.members.length - a.members.length ||
      a.groupKey.localeCompare(b.groupKey),
  )

  return {
    alerts: ordered.slice(0, CARD_CAP),
    overflow: ordered.slice(CARD_CAP),
    baselined,
    fixed,
    unreadableNotices,
    recovered,
    dropped,
    nextRepos,
  }
}

/** Open findings across watched repos, by severity. */
export function countOpen(repos: Record<string, RepoState>): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, moderate: 0, low: 0 }
  for (const r of activeRepos(repos)) for (const f of Object.values(r.findings)) out[f.severity]++
  return out
}
