/**
 * Match one repo's parsed lockfiles against the advisory index. PURE.
 *
 * The same advisory for the same package across several lockfiles (or several
 * sources) collapses to ONE finding, keeping the highest known severity.
 */
import {
  advisoryMatchesVersion,
  ghsaFrom,
  indexKey,
  readableRange,
  SEVERITY_RANK,
  type Advisory,
  type AdvisoryIndex,
  type AdvisorySource,
  type Severity,
} from './advisories.js'
import { computeFixLine, type FixLine } from './fix.js'
import type { LockEcosystem, ParsedLockfile } from './lockfiles.js'

export interface Finding {
  repo: string
  /** `<advisory id>:<package>`: the per-repo identity kept in state. */
  key: string
  advisoryId: string
  cveId: string | null
  ecosystem: LockEcosystem
  packageName: string
  severity: Severity
  /** False while only a source without a severity has matched (moderate default). */
  severityKnown: boolean
  /** Some source reported a malicious release: critical, and it pings even when dev-only. */
  malware?: boolean
  installed: string[]
  lockfiles: string[]
  /** Every matched install is dev-only. Unknown scope counts as runtime. */
  devOnly: boolean
  sources: AdvisorySource[]
  title: string
  url: string
  /** The fix per installed version (first MAX_FIX_LINES). */
  fixes: FixLine[]
}

/** Most per-version fix lines kept on one finding. */
const MAX_FIX_LINES = 6

function pushUnique<T>(arr: T[], v: T): void {
  if (!arr.includes(v)) arr.push(v)
}

export function findingKey(advisoryId: string, packageName: string): string {
  return `${advisoryId}:${packageName}`
}

export function matchRepo(repo: string, lockfiles: ParsedLockfile[], index: AdvisoryIndex): Finding[] {
  const byKey = new Map<string, Finding>()
  /** key -> installed version -> the advisory entries it matched (for the fix). */
  const matchedBy = new Map<string, Map<string, Advisory[]>>()
  for (const lf of lockfiles) {
    for (const pkg of lf.packages) {
      const candidates = index.get(indexKey(lf.ecosystem, pkg.name))
      if (!candidates) continue
      for (const adv of candidates) {
        if (!advisoryMatchesVersion(adv, pkg.version)) continue
        const key = findingKey(adv.id, adv.packageName)
        const isDev = pkg.dev === true
        let f = byKey.get(key)
        if (!f) {
          f = {
            repo,
            key,
            advisoryId: adv.id,
            cveId: adv.cveId,
            ecosystem: adv.ecosystem,
            packageName: adv.packageName,
            severity: adv.severity,
            severityKnown: adv.severityKnown,
            installed: [],
            lockfiles: [],
            devOnly: isDev,
            sources: [],
            title: adv.title,
            url: adv.url,
            fixes: [],
          }
          byKey.set(key, f)
        } else {
          // A known severity beats the moderate default of a source that gave
          // none. Between two known ones, the higher wins.
          if (adv.severityKnown && !f.severityKnown) {
            f.severity = adv.severity
            f.severityKnown = true
          } else if (adv.severityKnown === f.severityKnown && SEVERITY_RANK[adv.severity] > SEVERITY_RANK[f.severity]) {
            f.severity = adv.severity
          }
          if (!f.cveId && adv.cveId) f.cveId = adv.cveId
          if (!isDev) f.devOnly = false
        }
        if (adv.malware) {
          f.malware = true
          f.severity = 'critical'
          f.severityKnown = true
        }
        pushUnique(f.installed, pkg.version)
        pushUnique(f.lockfiles, lf.path)
        pushUnique(f.sources, adv.source)
        let versions = matchedBy.get(key)
        if (!versions) matchedBy.set(key, (versions = new Map()))
        const entries = versions.get(pkg.version) ?? []
        if (!entries.includes(adv)) entries.push(adv)
        versions.set(pkg.version, entries)
      }
    }
  }
  const findings = [...byKey.values()]
  for (const f of findings) {
    const versions = matchedBy.get(f.key)
    f.fixes = f.installed.slice(0, MAX_FIX_LINES).map((v) => fixFor(f.ecosystem, v, versions?.get(v) ?? []))
  }
  return findings
}

function fixFor(ecosystem: LockEcosystem, version: string, entries: Advisory[]): FixLine {
  return computeFixLine(ecosystem, version, {
    vulnerableRanges: entries.map(readableRange).filter((r): r is string => !!r),
    patched: entries.flatMap((a) => a.patched),
    noFixListed: entries.length > 0 && entries.every((a) => a.noFixListed === true),
  })
}

/**
 * The GHSA to look up in the global GitHub advisory DB for a finding whose fix
 * the npm DB does not name (an inclusive `<=X` range only names the last
 * affected version), or null.
 */
export function fixLookupGhsa(f: Finding): string | null {
  if (f.ecosystem !== 'npm' || !f.sources.includes('npm')) return null
  if (!f.fixes.some((l) => l.to === null && !l.unfixed)) return null
  return ghsaFrom(f.advisoryId) === f.advisoryId ? f.advisoryId : null
}

/**
 * Fill in fix lines that have no target, from the global DB's reviewed entries
 * for this advisory and package. Display only: never changes what matched.
 */
export function applyGlobalFixes(f: Finding, advisories: Advisory[]): boolean {
  try {
    if (f.ecosystem !== 'npm') return false
    const entries = advisories.filter((a) => a.id === f.advisoryId && a.packageName === f.packageName)
    if (!entries.some((a) => a.patched.length > 0)) return false
    let changed = false
    f.fixes = f.fixes.map((l) => {
      if (l.to !== null || l.unfixed) return l
      const next = computeFixLine('npm', l.from, {
        vulnerableRanges: entries
          .filter((a) => advisoryMatchesVersion(a, l.from))
          .map(readableRange)
          .filter((r): r is string => !!r),
        patched: entries.flatMap((a) => a.patched),
      })
      if (!next.to) return l
      changed = true
      return next
    })
    return changed
  } catch {
    return false
  }
}
