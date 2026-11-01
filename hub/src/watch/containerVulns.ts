/**
 * The container check's decisions. PURE: no I/O, no clock.
 *
 * What cards: a CVE with a fix in the container's own distro release (Debian,
 * Ubuntu or Alpine), rated critical or high. One card per image: one rebuild fixes
 * them all, so every package fix the image needs, every CVE those fixes close and
 * every box running the image share it. The card lists each package and the version
 * that fixes it, and is edited in place when that list or its containers change. A
 * fix with no severity yet, a medium or low one, and a CVE with no fix are only
 * counted. Debian's "unimportant" rating counts as no security fix, and so does an
 * Ubuntu fix only Ubuntu Pro ships (a plain image cannot install it).
 *
 * Severity is the CVSS v3 base score OSV carries (the distro trackers copy NVD's),
 * or the distro's own rating when that is higher: Debian's "high" urgency, Ubuntu's
 * high or critical priority. A record with only a CVSS v4 vector, or none, reads as
 * unknown, never as a guess. Cards never page: the fix is a rebuild, which is
 * daytime work, and an OS package's score says little about whether the container
 * ever runs the vulnerable code.
 *
 * A container on a card is settled once it was checked in full this run (every
 * package's OSV answer and record read) and the fix is in, it now runs a different
 * image, or the hub no longer lists it (its box reported it gone, or sent nothing
 * for 30 days). A container whose box has not reported for STALE_MS settles nothing.
 * Each of those rests on what the boxes report, and a box cannot close an alert
 * about itself (docs/principles.md, rule 4). So once every container on a card is
 * settled, the card is marked reported fixed and waits for a person to press
 * Resolve; it is no longer sent again. Only a card whose every container settled
 * on something the hub read itself would close here, and there is no such evidence
 * for containers today.
 */
import type { OsvHit, OsvQuery } from './osv.js'
import type { ContainerPackagesRecord, ContainerSeverityCounts } from './types.js'
import { cardId, DAY_MS, esc, HOUR_MS, isoDay, joinAnd, plural, RESURFACE_MS, truncate } from './util.js'

export type CveSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'
export type CardSeverity = 'critical' | 'high'

/** Most new cards per run. The rest card on a later run. */
export const CONTAINER_CARD_CAP = 6
/** Tracked cards kept at most (oldest dropped). */
export const MAX_TRACKED_CONTAINER_CARDS = 200
/** Unchanged open cards sent again per run at most, the longest unsent first. */
export const CONTAINER_RESEND_CAP = 20
/** A box resends an unchanged list about every 20 hours; past this its containers are stale. */
export const STALE_MS = 3 * DAY_MS
/** A cached OSV record whose `modified` moved is fetched again once it is this old. */
export const DETAIL_REFRESH_MS = 6 * HOUR_MS
/** A cached OSV record is fetched again once it is this old, whatever OSV says. */
export const DETAIL_MAX_AGE_MS = 7 * DAY_MS
const FIXED_CAP = 8

const SEVERITY_RANK: Record<CveSeverity, number> = { critical: 5, high: 4, medium: 3, low: 2, none: 1, unknown: 0 }

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/** `box/container`, how a container is named on a card and in the state. */
export function containerField(r: Pick<ContainerPackagesRecord, 'box' | 'container'>): string {
  return `${r.box}/${r.container}`
}

/** An image reference without its digest, with `:latest` when it has no tag. */
export function normalizeImage(ref: string): string {
  const at = ref.indexOf('@')
  const bare = (at >= 0 ? ref.slice(0, at) : ref).trim()
  const slash = bare.lastIndexOf('/')
  const colon = bare.lastIndexOf(':')
  return colon > slash ? bare : `${bare}:latest`
}

/** The tag of a normalized reference. */
export function imageTag(image: string): string {
  const slash = image.lastIndexOf('/')
  const colon = image.lastIndexOf(':')
  return colon > slash ? image.slice(colon + 1) : 'latest'
}

/** The OSV ecosystem for a record's OS: `Debian:12`, `Ubuntu:24.04:LTS`, `Alpine:v3.19`. Null for anything else. */
export function osvEcosystemFor(rec: Pick<ContainerPackagesRecord, 'os' | 'osVersion' | 'pm'>): string | null {
  if (!rec.os || !rec.osVersion) return null
  if (rec.os === 'debian' && rec.pm === 'dpkg') {
    const m = /^(\d{1,2})(?:\.\d+)*$/.exec(rec.osVersion)
    return m ? `Debian:${m[1]}` : null
  }
  if (rec.os === 'ubuntu' && rec.pm === 'dpkg') {
    // An April release of an even year is an LTS, which OSV names with the suffix.
    const m = /^(\d{2})\.(04|10)$/.exec(rec.osVersion)
    if (!m) return null
    return Number(m[1]) % 2 === 0 && m[2] === '04' ? `Ubuntu:${rec.osVersion}:LTS` : `Ubuntu:${rec.osVersion}`
  }
  if (rec.os === 'alpine' && rec.pm === 'apk') {
    const m = /^(\d{1,2})\.(\d{1,3})/.exec(rec.osVersion)
    return m ? `Alpine:v${m[1]}.${m[2]}` : null
  }
  return null
}

// ---------------------------------------------------------------------------
// CVSS v3
// ---------------------------------------------------------------------------

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC: Record<string, number> = { L: 0.77, H: 0.44 }
const UI: Record<string, number> = { N: 0.85, R: 0.62 }
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }

/** CVSS v3.1 Roundup: the smallest one-decimal number at or above the input. */
function roundUp(x: number): number {
  const i = Math.round(x * 100_000)
  return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10
}

/** The CVSS v3.0/v3.1 base score of a vector, or null when it is not a complete v3 vector. */
export function cvssV3BaseScore(vector: unknown): number | null {
  if (typeof vector !== 'string' || vector.length > 200) return null
  const parts = vector.trim().split('/')
  if (parts[0] !== 'CVSS:3.0' && parts[0] !== 'CVSS:3.1') return null
  const m = new Map<string, string>()
  for (const p of parts.slice(1)) {
    const at = p.indexOf(':')
    if (at > 0 && !m.has(p.slice(0, at))) m.set(p.slice(0, at), p.slice(at + 1))
  }
  const scope = m.get('S')
  const av = AV[m.get('AV') ?? '']
  const ac = AC[m.get('AC') ?? '']
  const ui = UI[m.get('UI') ?? '']
  const c = CIA[m.get('C') ?? '']
  const i = CIA[m.get('I') ?? '']
  const a = CIA[m.get('A') ?? '']
  const prRaw = m.get('PR')
  const pr = prRaw === 'N' ? 0.85 : prRaw === 'L' ? (scope === 'C' ? 0.68 : 0.62) : prRaw === 'H' ? (scope === 'C' ? 0.5 : 0.27) : undefined
  if ((scope !== 'U' && scope !== 'C') || [av, ac, ui, c, i, a, pr].some((v) => v === undefined)) return null
  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = scope === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  if (impact <= 0) return 0
  const exploitability = 8.22 * av * ac * pr! * ui
  return scope === 'U' ? roundUp(Math.min(impact + exploitability, 10)) : roundUp(Math.min(1.08 * (impact + exploitability), 10))
}

/** The CVSS v3 qualitative rating of a base score. */
export function severityOfScore(score: number | null): CveSeverity {
  if (score === null || !Number.isFinite(score)) return 'unknown'
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

// ---------------------------------------------------------------------------
// OSV records, cached
// ---------------------------------------------------------------------------

/** `<ecosystem>|<package>`, the key a record's fixed versions are kept under. */
export function pairKey(ecosystem: string, pkg: string): string {
  return `${ecosystem}|${pkg}`
}

/** What the check keeps of one OSV record. Small: thousands are cached. */
export interface OsvDetail {
  /** The record's `modified`, as OSV gave it. */
  m: string | null
  /** When it was fetched, epoch ms. */
  f: number
  /** Its CVE (the record's upstream or alias), or null. */
  c: string | null
  /** CVSS v3 base score, or null. */
  s: number | null
  /** Fixed versions per pair; an empty list means no fix (or Debian rates it unimportant). */
  x: Record<string, string[]>
  /** Pairs Debian rates urgency high. */
  h?: string[]
  /** Ubuntu's priority for the CVE, when it is high or critical. */
  r?: CardSeverity
}

function cveOf(record: Record<string, unknown>): string | null {
  const ids = [record.id, ...(Array.isArray(record.upstream) ? record.upstream : []), ...(Array.isArray(record.aliases) ? record.aliases : [])]
  const cve = ids.find((v) => typeof v === 'string' && /^CVE-\d{4}-\d{4,7}$/i.test(v))
  return cve ? String(cve).toUpperCase() : null
}

function scoreOf(record: Record<string, unknown>): number | null {
  let best: number | null = null
  const affected = Array.isArray(record.affected) ? record.affected : []
  const lists = [record.severity, ...affected.map((a) => (a as Record<string, unknown> | null)?.severity)]
  for (const list of lists) {
    for (const s of Array.isArray(list) ? list : []) {
      if (s?.type !== 'CVSS_V3') continue
      const score = cvssV3BaseScore(s.score)
      if (score !== null && (best === null || score > best)) best = score
    }
  }
  return best
}

/**
 * Digest one OSV record for the pairs the check asked about. A pair the record
 * does not list gets an empty list (OSV matched it, so it is affected with no fix
 * listed). Only ECOSYSTEM ranges count: a GIT range's `fixed` is a commit.
 */
export function parseOsvDetail(raw: unknown, pairs: string[], fetchedAt: number): OsvDetail | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const record = raw as Record<string, any>
  if (typeof record.id !== 'string') return null
  const x: Record<string, string[]> = {}
  const h: string[] = []
  for (const pair of pairs) {
    const at = pair.indexOf('|')
    const eco = pair.slice(0, at)
    const name = pair.slice(at + 1)
    const fixed: string[] = []
    let unimportant = false
    for (const aff of Array.isArray(record.affected) ? record.affected : []) {
      if (String(aff?.package?.ecosystem || '') !== eco || String(aff?.package?.name || '') !== name) continue
      const urgency = String(aff?.ecosystem_specific?.urgency || '').toLowerCase()
      if (urgency === 'unimportant') unimportant = true
      // "Available with Ubuntu Pro": not a fix a plain image can install.
      if (/\bpro\b/i.test(String(aff?.ecosystem_specific?.availability || ''))) unimportant = true
      if (urgency === 'high' && !h.includes(pair)) h.push(pair)
      for (const r of Array.isArray(aff.ranges) ? aff.ranges : []) {
        if (r?.type !== 'ECOSYSTEM') continue
        for (const ev of Array.isArray(r.events) ? r.events : []) {
          const fx = typeof ev?.fixed === 'string' ? ev.fixed.trim() : ''
          if (fx && fx.length <= 100 && !fixed.includes(fx) && fixed.length < FIXED_CAP) fixed.push(fx)
        }
      }
    }
    x[pair] = unimportant ? [] : fixed.sort()
  }
  const ubuntu = (Array.isArray(record.severity) ? record.severity : []).find((v: any) => v?.type === 'Ubuntu')
  const priority = String(ubuntu?.score || '').toLowerCase()
  return {
    m: typeof record.modified === 'string' ? record.modified.slice(0, 40) : null,
    f: fetchedAt,
    c: cveOf(record),
    s: scoreOf(record),
    x,
    ...(h.length ? { h } : {}),
    ...(priority === 'critical' || priority === 'high' ? { r: priority } : {}),
  }
}

/** Whether a cached record must be fetched (again) before it can answer for `pairs`. */
export function needsFetch(cached: OsvDetail | undefined, modified: string | null, pairs: string[], now: number): boolean {
  if (!cached) return true
  if (pairs.some((p) => !Object.prototype.hasOwnProperty.call(cached.x, p))) return true
  const age = now - cached.f
  if (age >= DETAIL_MAX_AGE_MS || age < 0) return true
  return modified !== null && cached.m !== modified && age >= DETAIL_REFRESH_MS
}

/** A cached entry read back from the state, checked. Null when it is not usable. */
export function readCachedDetail(raw: unknown): OsvDetail | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const v = raw as Record<string, unknown>
  if (typeof v.f !== 'number' || !Number.isFinite(v.f)) return null
  if (!v.x || typeof v.x !== 'object' || Array.isArray(v.x)) return null
  const x: Record<string, string[]> = {}
  for (const [pair, list] of Object.entries(v.x as Record<string, unknown>)) {
    if (Array.isArray(list)) x[pair] = list.filter((s): s is string => typeof s === 'string' && s.length <= 100).slice(0, FIXED_CAP)
  }
  return {
    m: typeof v.m === 'string' ? v.m : null,
    f: v.f,
    c: typeof v.c === 'string' && /^CVE-\d{4}-\d{4,7}$/.test(v.c) ? v.c : null,
    s: typeof v.s === 'number' && v.s >= 0 && v.s <= 10 ? v.s : null,
    x,
    ...(Array.isArray(v.h) ? { h: v.h.filter((s): s is string => typeof s === 'string') } : {}),
    ...(v.r === 'critical' || v.r === 'high' ? { r: v.r } : {}),
  }
}

/** One vulnerability's rating for one pair. */
export function detailSeverity(d: OsvDetail, pair: string): CveSeverity {
  let best = severityOfScore(d.s)
  for (const rated of [d.h?.includes(pair) ? 'high' : 'unknown', d.r ?? 'unknown'] as CveSeverity[]) {
    if (SEVERITY_RANK[rated] > SEVERITY_RANK[best]) best = rated
  }
  return best
}

// ---------------------------------------------------------------------------
// Queries and findings
// ---------------------------------------------------------------------------

export interface InventoryEntry {
  field: string
  record: ContainerPackagesRecord
}

/** Every distinct (ecosystem, package, version) the records hold. */
export function inventoryQueries(entries: InventoryEntry[]): OsvQuery[] {
  const seen = new Set<string>()
  const out: OsvQuery[] = []
  for (const { record } of entries) {
    const ecosystem = osvEcosystemFor(record)
    if (!ecosystem) continue
    for (const { name, version } of record.packages) {
      const k = `${ecosystem}|${name}|${version}`
      if (seen.has(k)) continue
      seen.add(k)
      out.push({ ecosystem, name, version })
    }
  }
  return out
}

function queryKey(q: OsvQuery): string {
  return `${q.ecosystem}|${q.name}|${q.version}`
}

/** id -> the pairs OSV matched it for, from a querybatch answer. */
export function idsToPairs(queries: OsvQuery[], hits: OsvHit[][]): Map<string, { modified: string | null; pairs: string[] }> {
  const out = new Map<string, { modified: string | null; pairs: string[] }>()
  queries.forEach((q, i) => {
    for (const h of hits[i] ?? []) {
      let e = out.get(h.id)
      if (!e) out.set(h.id, (e = { modified: h.modified, pairs: [] }))
      const p = pairKey(q.ecosystem, q.name)
      if (!e.pairs.includes(p)) e.pairs.push(p)
    }
  })
  return out
}

export interface FindingCve {
  /** The CVE, or the OSV id when the record names none. */
  id: string
  osvId: string
  score: number | null
  severity: CveSeverity
}

export interface ContainerFinding {
  field: string
  box: string
  container: string
  image: string
  builtAt: number | null
  ecosystem: string
  pkg: string
  installed: string
  fixed: string[]
  cves: FindingCve[]
  severity: CardSeverity
}

export interface FindingsResult {
  findings: ContainerFinding[]
  /** Fields whose every package was answered and every matched record read. */
  evaluated: Set<string>
  /** Fields with a supported OS but a record still missing (over the fetch cap, failed). */
  incomplete: Set<string>
  /** Fields with an OS this check does not read, or no package database. */
  unsupported: Set<string>
  counts: ContainerSeverityCounts
}

function compareCves(a: FindingCve, b: FindingCve): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.score ?? 0) - (a.score ?? 0) || a.id.localeCompare(b.id)
}

/**
 * Match each record's packages against the OSV answers and the record details.
 * `hits` is per query, aligned with `queries`; a query with no answer leaves its
 * field incomplete.
 */
export function findContainerFindings(entries: InventoryEntry[], queries: OsvQuery[], hits: OsvHit[][], details: Map<string, OsvDetail>): FindingsResult {
  const byQuery = new Map<string, OsvHit[]>()
  queries.forEach((q, i) => byQuery.set(queryKey(q), hits[i] ?? []))
  const findings: ContainerFinding[] = []
  const evaluated = new Set<string>()
  const incomplete = new Set<string>()
  const unsupported = new Set<string>()
  const counts: ContainerSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, unfixed: 0 }

  for (const { field, record } of entries) {
    const ecosystem = osvEcosystemFor(record)
    if (!ecosystem || record.packages.length === 0) {
      unsupported.add(field)
      continue
    }
    let complete = true
    for (const { name: pkg, version: installed } of record.packages) {
      const answer = byQuery.get(`${ecosystem}|${pkg}|${installed}`)
      if (!answer) {
        complete = false
        continue
      }
      const pair = pairKey(ecosystem, pkg)
      // A DSA and its DEBIAN-CVE record are the same CVE: one entry, whatever order
      // OSV lists them in, rated by the best-scored record (a DSA carries no score).
      const byCve = new Map<string, { cve: FindingCve; fixed: string[] }>()
      for (const hit of answer) {
        const d = details.get(hit.id)
        if (!d || !Object.prototype.hasOwnProperty.call(d.x, pair)) {
          complete = false
          continue
        }
        const cveId = d.c || hit.id
        const severity = detailSeverity(d, pair)
        const prev = byCve.get(cveId)
        const better = !prev || SEVERITY_RANK[severity] > SEVERITY_RANK[prev.cve.severity] || (prev.cve.score === null && d.s !== null)
        const fixed = prev && prev.fixed.length && !d.x[pair].length ? prev.fixed : d.x[pair]
        if (better) byCve.set(cveId, { cve: { id: cveId, osvId: hit.id, score: d.s, severity }, fixed })
        else if (prev && !prev.fixed.length && fixed.length) prev.fixed = fixed
      }
      // fixed versions (joined) -> the CVEs that update closes
      const groups = new Map<string, { fixed: string[]; cves: FindingCve[] }>()
      for (const { cve, fixed } of byCve.values()) {
        if (fixed.length === 0) {
          counts.unfixed++
          continue
        }
        if (cve.severity === 'none') counts.low++
        else counts[cve.severity]++
        if (cve.severity !== 'critical' && cve.severity !== 'high') continue
        const k = fixed.join(' ')
        let g = groups.get(k)
        if (!g) groups.set(k, (g = { fixed, cves: [] }))
        g.cves.push(cve)
      }
      for (const g of groups.values()) {
        g.cves.sort(compareCves)
        findings.push({
          field,
          box: record.box,
          container: record.container,
          image: normalizeImage(record.image),
          builtAt: record.builtAt,
          ecosystem,
          pkg,
          installed,
          fixed: g.fixed,
          cves: g.cves,
          severity: g.cves.some((c) => c.severity === 'critical') ? 'critical' : 'high',
        })
      }
    }
    if (complete) evaluated.add(field)
    else incomplete.add(field)
  }
  return { findings, evaluated, incomplete, unsupported, counts }
}

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

const CARD_KEY_PREFIX = 'container'
/** Room for the list of fixes on a card. */
const FIXES_MAX = 1800

/** One card per image. */
export function containerCardKey(image: string): string {
  return cardId(CARD_KEY_PREFIX, image)
}

/** A package and the version that fixes it, as a card lists it: `curl 8.14.1-2+deb13u7`. */
function fixLabel(f: Pick<ContainerFinding, 'pkg' | 'fixed'>): string {
  return `${f.pkg} ${f.fixed.join(', ')}`
}

function fixesOf(findings: ContainerFinding[]): string[] {
  return [...new Set(findings.map(fixLabel))].sort()
}

export interface TrackedContainerCard {
  key: string
  image: string
  severity: CardSeverity
  /** The package fixes the card listed when it was last sent (`pkg version`), sorted. */
  fixes: string[]
  /** Fields (`box/container`) the card waits on. */
  members: string[]
  /** When it was carded, ISO. */
  at: string
  /** When it was last sent, ISO. Absent until it is edited or sent again; `at` counts then. */
  sent?: string
}

export interface PlannedContainerCard {
  key: string
  severity: CardSeverity
  title: string
  body: string
  url: string
  card: TrackedContainerCard
}

export interface PlannedContainerUpdate extends PlannedContainerCard {
  /** What stays tracked when the edit did not go out, so the next run sends it again. */
  previous: TrackedContainerCard
}

export interface PlannedContainerClose {
  card: TrackedContainerCard
  note: string
}

export interface ContainerCardPlan {
  cards: PlannedContainerCard[]
  /** New cards over the cap, left for a later run. */
  deferred: number
  /** Open cards whose fixes or containers changed: edited in place. */
  updates: PlannedContainerUpdate[]
  /**
   * Open cards with no change, sent again every RESURFACE_MS (at most
   * CONTAINER_RESEND_CAP a run): the hub edits nothing unless the text moved,
   * and a card a person resolved opens again.
   */
  resend: PlannedContainerUpdate[]
  /** Every container settled on what the hub read itself: closed. None today. */
  close: PlannedContainerClose[]
  /**
   * Every container settled, on what the boxes report: the card is marked
   * reported fixed and waits for a person. No longer tracked once marked, so it
   * is not sent again; a later gap in the image cards it anew.
   */
  reportFixed: PlannedContainerClose[]
  /** Still open and unchanged, with any new members added. */
  keep: TrackedContainerCard[]
}

/** How a container on a card stopped needing the fix, and whose word that is. */
interface Settled {
  how: 'fixed' | 'moved' | 'gone'
  /** 'box': what its box reported (its package list, its image, its record gone). 'hub': what the hub read itself. */
  by: 'box' | 'hub'
}

/**
 * A tag that moves: `latest`, a word (`stable`, `bookworm-slim`), or one short of a
 * full version (`16`, `3.2-alpine`). A pull may bring a newer base without any change here.
 */
export function isFloatingTag(tag: string): boolean {
  if (/^(latest|stable|edge|main|master|nightly|local)$/i.test(tag)) return true
  if (!/\d/.test(tag)) return true
  return !/^v?\d+\.\d+\.\d+/.test(tag)
}

function distroLabel(ecosystem: string): string {
  const [name, release] = ecosystem.split(':')
  return name === 'Alpine' ? `Alpine ${release.replace(/^v/, '')}` : `${name} ${release}`
}

function trackerUrl(ecosystem: string, cve: FindingCve): string {
  if (/^CVE-/.test(cve.id)) {
    if (ecosystem.startsWith('Debian:')) return `https://security-tracker.debian.org/tracker/${cve.id}`
    if (ecosystem.startsWith('Ubuntu:')) return `https://ubuntu.com/security/${cve.id}`
    if (ecosystem.startsWith('Alpine:')) return `https://security.alpinelinux.org/vuln/${cve.id}`
  }
  return `https://osv.dev/vulnerability/${encodeURIComponent(cve.osvId)}`
}

function cveLabel(c: FindingCve): string {
  return c.score !== null ? `${c.id} (${c.severity} ${c.score.toFixed(1)})` : `${c.id} (${c.severity})`
}

function uniqueCves(cves: FindingCve[]): FindingCve[] {
  return [...new Map(cves.map((c) => [c.id, c])).values()].sort(compareCves)
}

/** The card for one image, from its findings (every package fix, every container). What the boxes and OSV sent is escaped. */
export function containerCardText(members: ContainerFinding[], now: number): { title: string; body: string; url: string } {
  const lead = members[0]
  const byFix = new Map<string, ContainerFinding[]>()
  for (const m of members) {
    const k = fixLabel(m)
    const list = byFix.get(k)
    if (list) list.push(m)
    else byFix.set(k, [m])
  }
  const fixes = [...byFix.values()]
    .map((list) => ({
      pkg: list[0].pkg,
      fixed: list[0].fixed.join(', '),
      installed: [...new Set(list.map((m) => m.installed))].sort().join(', '),
      cves: uniqueCves(list.flatMap((m) => m.cves)),
    }))
    .sort((a, b) => compareCves(a.cves[0], b.cves[0]) || a.pkg.localeCompare(b.pkg))
  const cves = uniqueCves(fixes.flatMap((f) => f.cves))
  const pkgs = [...new Set(fixes.map((f) => f.pkg))]
  const label = members.some((m) => m.severity === 'critical') ? 'Critical' : 'High'
  const where = [...new Set(members.map((m) => `${m.box}: ${esc(m.container)}`))].sort()
  const built = members.map((m) => m.builtAt).filter((b): b is number => b !== null && Number.isFinite(b))
  const oldest = built.length ? Math.min(...built) : null
  const tag = imageTag(lead.image)
  const floating = isFloatingTag(tag)
  const age = oldest !== null ? `${isoDay(oldest)} (${plural(Math.max(0, Math.floor((now - oldest) / DAY_MS)), 'day', 'days')} ago)` : 'unknown'
  const pullHint = floating
    ? esc(`The tag "${tag}" moves, so pulling it again may already bring the fixes.`)
    : 'If the image comes from upstream and upstream has no newer release, build it yourself on the updated base.'

  // Worst first, as many as fit, then a count of the rest.
  const lines: string[] = []
  let used = 0
  for (const [i, f] of fixes.entries()) {
    const more = f.cves.length > 1 ? ` and ${f.cves.length - 1} more` : ''
    const line = truncate(esc(`${f.pkg} ${f.installed}, fixed in ${f.fixed}: ${cveLabel(f.cves[0])}${more}`), 300)
    // Room is kept for the closing count of what did not fit.
    if (lines.length && used + line.length > FIXES_MAX - 40) {
      lines.push(`...and ${plural(fixes.length - i, 'more package', 'more packages')}`)
      break
    }
    lines.push(line)
    used += line.length + 1
  }

  const what = pkgs.length === 1 ? pkgs[0] : `${pkgs.length} packages`
  const text =
    `${esc(lead.image)} has ${plural(cves.length, 'high or critical CVE', 'high or critical CVEs')} in ${plural(pkgs.length, 'package', 'packages')} that ${distroLabel(lead.ecosystem)} has fixed. The worst: ${esc(cveLabel(cves[0]))} in ${esc(fixes[0].pkg)}. ` +
    `The container publishes a port or uses the host network. Rebuild it on a patched base and redeploy: one rebuild fixes everything listed. ${pullHint} When the boxes report that every container listed runs the fixes, this card says so and waits for you to press Resolve. If you resolve it before that, it opens again within about 6 hours.`
  return {
    title: `${label} ${cves.length === 1 ? 'CVE' : 'CVEs'} in ${what} in container image ${lead.image}`,
    body: truncate(
      `${text}\n\nRuns on:\n${truncate(where.join('\n'), 800)}\n\n${pkgs.length === 1 ? 'Fix' : 'Fixes'}:\n${lines.join('\n')}\n\n${floating ? 'Image built (floating tag)' : 'Image built'}: ${age}`,
      3_500,
    ),
    url: trackerUrl(lead.ecosystem, cves[0]),
  }
}

function settle(
  card: TrackedContainerCard,
  field: string,
  records: Map<string, ContainerPackagesRecord>,
  evaluated: Set<string>,
  openKeys: Map<string, Set<string>>,
  unreadable: Set<string>,
  now: number,
): Settled | null {
  if (unreadable.has(field)) return null
  const rec = records.get(field)
  // Every outcome below is the box's word: a box that was taken over can send any of them.
  if (!rec) return { how: 'gone', by: 'box' }
  if (normalizeImage(rec.image) !== card.image) return { how: 'moved', by: 'box' }
  if (now - rec.receivedAt > STALE_MS) return null
  if (!evaluated.has(field)) return null
  if (openKeys.get(field)?.has(card.key)) return null
  return { how: 'fixed', by: 'box' }
}

function outcomeText(card: TrackedContainerCard, outcomes: Settled[]): string {
  const count = (how: Settled['how']) => outcomes.filter((o) => o.how === how).length
  const parts: string[] = []
  if (count('fixed')) parts.push(`${plural(count('fixed'), 'container runs', 'containers run')} the fixed packages`)
  if (count('moved')) parts.push(`${plural(count('moved'), 'container no longer runs', 'containers no longer run')} ${esc(card.image)}`)
  if (count('gone')) parts.push(`${plural(count('gone'), 'container is', 'containers are')} gone`)
  return joinAnd(parts)
}

function closeNote(card: TrackedContainerCard, outcomes: Settled[]): string {
  return `Fixed: ${outcomeText(card, outcomes)}, so this card is closed.`
}

function reportedFixedNote(card: TrackedContainerCard, outcomes: Settled[]): string {
  // A field is `box/container`, and a box name has no slash.
  const boxes = new Set(card.members.map((m) => m.slice(0, m.indexOf('/'))))
  return `${boxes.size === 1 ? 'The box now reports' : 'The boxes now report'} that ${outcomeText(card, outcomes)}.`
}

const SEVERITY_ORDER: Record<CardSeverity, number> = { critical: 1, high: 0 }

/**
 * What to card, edit, close and keep. `unreadable` are containers whose record the
 * hub listed but this check could not read: they settle nothing (never "gone").
 */
export function planContainerCards(input: {
  findings: ContainerFinding[]
  tracked: TrackedContainerCard[]
  records: Map<string, ContainerPackagesRecord>
  evaluated: Set<string>
  unreadable?: Set<string>
  now: number
  cap?: number
}): ContainerCardPlan {
  const { findings, tracked, records, evaluated, now } = input
  const unreadable = input.unreadable ?? new Set<string>()
  const cap = Math.max(0, input.cap ?? CONTAINER_CARD_CAP)
  const openKeys = new Map<string, Set<string>>()
  const byKey = new Map<string, ContainerFinding[]>()
  for (const f of findings) {
    const k = containerCardKey(f.image)
    let keys = openKeys.get(f.field)
    if (!keys) openKeys.set(f.field, (keys = new Set()))
    keys.add(k)
    const list = byKey.get(k)
    if (list) list.push(f)
    else byKey.set(k, [f])
  }
  // A box gone quiet neither opens a card nor changes one.
  const freshOf = (key: string) =>
    (byKey.get(key) ?? []).filter((f) => {
      const rec = records.get(f.field)
      return !!rec && now - rec.receivedAt <= STALE_MS
    })
  const severityOf = (list: ContainerFinding[]): CardSeverity => (list.some((f) => f.severity === 'critical') ? 'critical' : 'high')

  const close: PlannedContainerClose[] = []
  const reportFixed: PlannedContainerClose[] = []
  const updates: PlannedContainerUpdate[] = []
  const keep: TrackedContainerCard[] = []
  const due: PlannedContainerUpdate[] = []
  const at = new Date(now).toISOString()
  const lastSent = (c: TrackedContainerCard) => {
    const t = Date.parse(c.sent ?? c.at)
    return Number.isFinite(t) ? t : 0
  }
  const trackedKeys = new Set<string>()
  for (const card of tracked) {
    trackedKeys.add(card.key)
    const members = [...card.members]
    // Another box now runs the same image with gaps: the card waits on it too.
    for (const f of byKey.get(card.key) ?? []) if (!members.includes(f.field)) members.push(f.field)
    const next = { ...card, members: members.sort() }
    const outcomes = next.members.map((m) => settle(next, m, records, evaluated, openKeys, unreadable, now))
    if (outcomes.every((o): o is Settled => o !== null)) {
      // Only what the hub read itself closes a card; the boxes' word waits for a person.
      if (outcomes.every((o) => o.by === 'hub')) close.push({ card: next, note: closeNote(next, outcomes) })
      else reportFixed.push({ card: next, note: reportedFixedNote(next, outcomes) })
      continue
    }
    const fresh = freshOf(card.key)
    if (fresh.length) {
      const severity = severityOf(fresh)
      const fixes = fixesOf(fresh)
      const changed = severity !== card.severity || fixes.join('\n') !== card.fixes.join('\n') || next.members.join('\n') !== card.members.join('\n')
      if (changed || now - lastSent(card) >= RESURFACE_MS) {
        const planned: PlannedContainerUpdate = {
          key: card.key,
          severity,
          ...containerCardText(
            fresh.map((f) => ({ ...f, severity })),
            now,
          ),
          card: { ...next, severity, fixes, sent: at },
          previous: changed ? card : next,
        }
        if (changed) updates.push(planned)
        else due.push(planned)
        continue
      }
    }
    keep.push(next)
  }
  // The longest unsent first; the rest wait for a later run, as they were.
  due.sort((a, b) => lastSent(a.previous) - lastSent(b.previous) || a.key.localeCompare(b.key))
  const resend = due.slice(0, CONTAINER_RESEND_CAP)
  for (const r of due.slice(CONTAINER_RESEND_CAP)) keep.push(r.previous)

  const planned: PlannedContainerCard[] = []
  for (const key of byKey.keys()) {
    if (trackedKeys.has(key)) continue
    const fresh = freshOf(key)
    if (!fresh.length) continue
    const severity = severityOf(fresh)
    planned.push({
      key,
      severity,
      ...containerCardText(
        fresh.map((f) => ({ ...f, severity })),
        now,
      ),
      card: { key, image: fresh[0].image, severity, fixes: fixesOf(fresh), members: [...new Set(fresh.map((f) => f.field))].sort(), at },
    })
  }
  planned.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.card.image.localeCompare(b.card.image))
  return { cards: planned.slice(0, cap), deferred: Math.max(0, planned.length - cap), updates, resend, close, reportFixed, keep }
}

/** Tracked cards read back from the state, checked. */
export function readTrackedContainerCards(raw: unknown): TrackedContainerCard[] {
  if (!Array.isArray(raw)) return []
  const out: TrackedContainerCard[] = []
  for (const c of raw.slice(0, MAX_TRACKED_CONTAINER_CARDS * 2)) {
    if (!c || typeof c !== 'object') continue
    const v = c as Record<string, unknown>
    if (typeof v.key !== 'string' || typeof v.image !== 'string' || !Array.isArray(v.fixes) || !Array.isArray(v.members)) continue
    out.push({
      key: v.key,
      image: v.image,
      severity: v.severity === 'critical' ? 'critical' : 'high',
      fixes: v.fixes.filter((s): s is string => typeof s === 'string'),
      members: v.members.filter((s): s is string => typeof s === 'string'),
      at: typeof v.at === 'string' ? v.at : new Date(0).toISOString(),
      ...(typeof v.sent === 'string' ? { sent: v.sent } : {}),
    })
  }
  return out
}
