/**
 * Advisory parsing and version matching. PURE: no I/O, no clock.
 *
 * Sources, all folded into one shape (Advisory):
 *   - npm     the npm registry bulk advisory endpoint (the GitHub advisory DB).
 *             It returns every advisory whose range matches ANY submitted
 *             version of a package, so each advisory is re-checked here against
 *             EACH installed version before it is attributed.
 *   - github  a reviewed record from the global GitHub advisory DB, read only to
 *             learn the first patched version when the npm range does not name it.
 *   - osv     OSV, for Python packages.
 * One advisory is one alert: findings are keyed by GHSA id (or the OSV id when
 * there is no GHSA alias), so the PYSEC, GHSA and MAL copies of one issue merge.
 */
import semver from 'semver'
import { normalizePypiName, type LockEcosystem } from './lockfiles.js'

export type Severity = 'critical' | 'high' | 'moderate' | 'low'

export const SEVERITIES: Severity[] = ['critical', 'high', 'moderate', 'low']

export const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, moderate: 1, low: 0 }

export type AdvisorySource = 'npm' | 'github' | 'osv'

export const SOURCE_LABEL: Record<AdvisorySource, string> = {
  npm: 'npm advisory DB',
  github: 'GitHub advisory DB',
  osv: 'OSV',
}

/** Map any source's severity word to ours. Unknown lands as moderate: visible, never a guessed ping. */
export function canonSeverity(raw: unknown): Severity {
  const s = String(raw || '').toLowerCase()
  if (s === 'critical') return 'critical'
  if (s === 'high') return 'high'
  if (s === 'low') return 'low'
  // GitHub's Dependabot API says 'medium'; GHSA and npm say 'moderate'. Same bucket.
  return 'moderate'
}

export interface Advisory {
  /** GHSA id when known, else the OSV id, else `NPM-<n>`. */
  id: string
  cveId: string | null
  ecosystem: LockEcosystem
  /** npm name, or PEP 503-normalized PyPI name. */
  packageName: string
  severity: Severity
  /** False when the source gave no severity and `severity` is the moderate default. */
  severityKnown: boolean
  /** npm semver range. Null when `versions` lists the exact affected installs (OSV). */
  range: string | null
  /** OSV only: the installed versions OSV itself matched. */
  versions?: string[]
  /** The patched versions as the source gave them (GitHub DB, OSV), if any. */
  patched: string[]
  /** OSV only: no `fixed` and no `last_affected` event, so nothing is fixed yet. */
  noFixListed?: boolean
  /** A hijacked or malicious release (npm CWE-506, OSV MAL-*), not a bug. Always critical. */
  malware?: boolean
  title: string
  url: string
  source: AdvisorySource
}

/**
 * Is an npm bulk entry a malware advisory? GitHub files them as "Malware in
 * <pkg>" with CWE-506 (embedded malicious code) and no CVSS score.
 */
export function isNpmMalwareEntry(raw: any): boolean {
  const cwe = Array.isArray(raw?.cwe) ? raw.cwe.map(String) : []
  return cwe.includes('CWE-506') || /^Malware in /.test(String(raw?.title || ''))
}

/**
 * The MAL-* id of an OSV malicious-package report (ossf/malicious-packages), from
 * the record's own id or an alias, else null.
 */
export function osvMalwareId(record: any): string | null {
  const aliases: unknown[] = Array.isArray(record?.aliases) ? record.aliases : []
  const hit = [record?.id, ...aliases].find((a): a is string => typeof a === 'string' && /^MAL-\d{4}-\d+$/i.test(a))
  return hit ? hit.toUpperCase() : null
}

// ---------------------------------------------------------------------------
// Range matching
// ---------------------------------------------------------------------------

type RangeToken = { kind: 'lower' | 'upper' | 'exact'; text: string }

/**
 * Turn a GitHub-style advisory range into an npm semver range, or null when it
 * cannot be read. GitHub ranges are written by hand and come in several shapes:
 *   ">= 13.0.0, < 15.5.8"                 one range, comparators ANDed by comma
 *   ">=13.0.0 < 15.5.15, >= 16.0 < 16.2.3" two ranges, the comma means OR
 *   "19.0.0, 19.1.0, 19.1.1"              a list of exact versions (OR)
 *   "19.1.5 19.2.0"                       the same list with a comma missing
 *   "=>0.31.1"                            a typo for ">="
 * So the comparators are read left to right and grouped: a group is closed
 * when a new lower bound arrives after the group already has a bound on that
 * side or an upper one, and every exact version is a group of its own. Groups
 * are ORed. Anything that is not a plain comparator or version (a caret or
 * tilde range, "*", ...) falls back to semver's own reading of the text.
 */
export function normalizeRange(range: string): string | null {
  const alternatives: string[] = []
  for (const part of range.split('||')) {
    const text = part
      .trim()
      .replace(/=>/g, '>=')
      .replace(/=</g, '<=')
      // Attach an operator to its version: ">= 16.0" -> ">=16.0".
      .replace(/(>=|<=|>|<|=)[ \t]+/g, '$1')
    if (!text) continue
    const raw = text.split(/[\s,]+/).filter(Boolean)
    const tokens: RangeToken[] = []
    let plain = true
    for (const t of raw) {
      const m = t.match(/^(>=|<=|>|<|=)?v?(\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?)$/)
      if (!m) {
        plain = false
        break
      }
      const op = m[1] || ''
      const kind: RangeToken['kind'] = op.startsWith('>') ? 'lower' : op.startsWith('<') ? 'upper' : 'exact'
      tokens.push({ kind, text: `${op}${m[2]}` })
    }
    if (!plain) {
      // Not a plain comparator list: let semver read it (commas as spaces).
      const r = semver.validRange(text.replace(/,/g, ' '))
      if (!r) return null
      alternatives.push(r)
      continue
    }
    let group: RangeToken[] = []
    const flush = () => {
      if (group.length) alternatives.push(group.map((g) => g.text).join(' '))
      group = []
    }
    for (const tok of tokens) {
      if (tok.kind === 'exact') {
        flush()
        group.push(tok)
        flush()
        continue
      }
      const hasLower = group.some((g) => g.kind === 'lower')
      const hasUpper = group.some((g) => g.kind === 'upper')
      if ((tok.kind === 'lower' && (hasLower || hasUpper)) || (tok.kind === 'upper' && hasUpper)) flush()
      group.push(tok)
    }
    flush()
  }
  if (alternatives.length === 0) return null
  return semver.validRange(alternatives.join(' || '))
}

/** The advisory's range as an npm semver range, or null when it cannot be read. */
export function readableRange(adv: Pick<Advisory, 'range' | 'source'>): string | null {
  if (!adv.range) return null
  // npm DB ranges are already npm semver; GitHub-written ranges need reading.
  return adv.source === 'npm' ? (semver.validRange(adv.range) ?? normalizeRange(adv.range)) : normalizeRange(adv.range)
}

/** Does `version` fall inside the advisory? Unparseable ranges never match. */
export function advisoryMatchesVersion(adv: Advisory, version: string): boolean {
  if (adv.versions) return adv.versions.includes(version)
  const range = readableRange(adv)
  if (!range) return false
  // includePrerelease: a canary/preview install inside the range is still exposed.
  return semver.satisfies(version, range, { includePrerelease: true })
}

// ---------------------------------------------------------------------------
// Source parsers
// ---------------------------------------------------------------------------

const GHSA_RE = /GHSA(?:-[a-z0-9]{4}){3}/i

/** Pull a GHSA id out of a string, in GitHub's canonical `GHSA-xxxx-xxxx-xxxx` case. */
export function ghsaFrom(s: unknown): string | null {
  const m = String(s || '').match(GHSA_RE)
  return m ? 'GHSA' + m[0].slice(4).toLowerCase() : null
}

function cap(s: unknown, max: number): string {
  const str = String(s ?? '')
  return str.length > max ? str.slice(0, max - 1) + ELLIPSIS : str
}

export const ELLIPSIS = String.fromCharCode(0x2026)

/** Most OSV fixed versions kept per advisory (one per release line in practice). */
const OSV_FIXED_CAP = 50

/**
 * Parse the npm bulk advisory response: `{ "<pkg>": [{ id, url, title,
 * severity, vulnerable_versions }] }`. `{}` means clean.
 */
export function parseNpmBulk(body: unknown): Advisory[] {
  const out: Advisory[] = []
  if (!body || typeof body !== 'object' || Array.isArray(body)) return out
  for (const [pkg, list] of Object.entries(body as Record<string, unknown>)) {
    if (!Array.isArray(list)) continue
    for (const raw of list as any[]) {
      if (!raw || typeof raw !== 'object') continue
      const range = typeof raw.vulnerable_versions === 'string' ? raw.vulnerable_versions : ''
      if (!range) continue
      const ghsa = ghsaFrom(raw.url)
      const malware = isNpmMalwareEntry(raw)
      out.push({
        id: ghsa || `NPM-${Number(raw.id) || 0}`,
        cveId: null,
        ecosystem: 'npm',
        packageName: pkg,
        severity: malware ? 'critical' : canonSeverity(raw.severity),
        severityKnown: true,
        ...(malware ? { malware: true } : {}),
        range,
        patched: [],
        title: cap(raw.title || 'No title provided', 200),
        url: ghsa ? `https://github.com/advisories/${ghsa}` : safeUrl(raw.url),
        source: 'npm',
      })
    }
  }
  return out
}

/** Only an https URL is kept for a link; anything else becomes the empty string. */
function safeUrl(raw: unknown): string {
  const s = String(raw || '')
  try {
    const u = new URL(s)
    return u.protocol === 'https:' && s.length <= 300 ? u.toString() : ''
  } catch {
    return ''
  }
}

/** What the global GitHub advisory DB says about one GHSA. */
export type GlobalAdvisoryLookup =
  | { status: 'reviewed'; advisories: Advisory[] }
  | { status: 'missing' }
  | { status: 'failed' }

/**
 * Parse `GET /advisories/{ghsa}` (the global DB). Only a REVIEWED record is
 * trusted. Its npm entries carry curated ranges and the first patched version.
 */
export function parseGlobalAdvisory(body: any, ghsa: string): GlobalAdvisoryLookup {
  if (!body || typeof body !== 'object' || ghsaFrom(body.ghsa_id) !== ghsa) return { status: 'failed' }
  if (body.withdrawn_at) return { status: 'reviewed', advisories: [] }
  if (body.type !== 'reviewed') return { status: 'missing' }
  const advisories: Advisory[] = []
  for (const v of Array.isArray(body.vulnerabilities) ? body.vulnerabilities : []) {
    const eco = String(v?.package?.ecosystem || '').toLowerCase()
    const name = v?.package?.name
    const range = typeof v?.vulnerable_version_range === 'string' ? v.vulnerable_version_range : ''
    if (eco !== 'npm' || !name || !range) continue
    const fpv = typeof v.first_patched_version === 'string' ? v.first_patched_version : v.first_patched_version?.identifier
    advisories.push({
      id: ghsa,
      cveId: typeof body.cve_id === 'string' && body.cve_id ? body.cve_id : null,
      ecosystem: 'npm',
      packageName: String(name),
      severity: canonSeverity(body.severity),
      severityKnown: true,
      range,
      patched: typeof fpv === 'string' && fpv ? [fpv] : [],
      title: cap(body.summary || 'No summary provided', 200),
      url: `https://github.com/advisories/${ghsa}`,
      source: 'github',
    })
  }
  return { status: 'reviewed', advisories }
}

/**
 * Turn one OSV vulnerability record into an advisory for the installed
 * versions OSV matched. The id is the GHSA alias when there is one, else the
 * MAL-* alias, so the PYSEC, GHSA and MAL copies of the same issue are one alert.
 */
export function parseOsvVuln(record: any, packageName: string, versions: string[]): Advisory | null {
  if (!record || typeof record.id !== 'string') return null
  const aliases: string[] = Array.isArray(record.aliases) ? record.aliases.map(String) : []
  const ghsa = ghsaFrom(record.id) || aliases.map(ghsaFrom).find(Boolean) || null
  const cve = [record.id, ...aliases].find((a) => /^CVE-\d{4}-\d+$/i.test(a)) || null
  // GHSA-sourced records carry the GitHub severity here; anything else is unknown
  // and lands as moderate. A MAL-* record has no severity either, but a
  // malicious release is critical by definition.
  const malId = osvMalwareId(record)
  const malware = malId !== null
  const rawSeverity = malware ? 'critical' : record.database_specific?.severity
  const severityKnown = ['critical', 'high', 'moderate', 'medium', 'low'].includes(String(rawSeverity || '').toLowerCase())

  const want = normalizePypiName(packageName)
  // Only ECOSYSTEM ranges carry PyPI versions. A GIT range's `fixed` is a commit
  // sha, which is not a version to show or to bump to.
  const fixed: string[] = []
  let ecosystemRanges = 0
  let lastAffected = false
  for (const aff of Array.isArray(record.affected) ? record.affected : []) {
    if (String(aff?.package?.ecosystem || '') !== 'PyPI') continue
    if (normalizePypiName(String(aff?.package?.name || '')) !== want) continue
    for (const r of Array.isArray(aff.ranges) ? aff.ranges : []) {
      if (r?.type !== 'ECOSYSTEM') continue
      ecosystemRanges++
      for (const ev of Array.isArray(r?.events) ? r.events : []) {
        if (!ev || typeof ev !== 'object') continue
        if (typeof ev.last_affected === 'string') lastAffected = true
        const fx = typeof ev.fixed === 'string' ? ev.fixed.trim() : ''
        if (fx && fx.length <= 64 && !fixed.includes(fx) && fixed.length < OSV_FIXED_CAP) fixed.push(fx)
      }
    }
  }
  const id = ghsa || malId || String(record.id)
  return {
    id,
    cveId: cve ? cve.toUpperCase() : null,
    ecosystem: 'PyPI',
    packageName: want,
    severity: canonSeverity(rawSeverity),
    severityKnown,
    ...(malware ? { malware: true } : {}),
    range: null,
    versions: [...versions],
    patched: fixed,
    ...(ecosystemRanges > 0 && fixed.length === 0 && !lastAffected ? { noFixListed: true } : {}),
    title: cap(record.summary || record.details || 'No summary provided', 200),
    url: ghsa
      ? `https://github.com/advisories/${ghsa}`
      : `https://osv.dev/vulnerability/${encodeURIComponent(String(record.id))}`,
    source: 'osv',
  }
}

// ---------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------

export type AdvisoryIndex = Map<string, Advisory[]>

export function indexKey(eco: LockEcosystem, name: string): string {
  return `${eco}:${eco === 'PyPI' ? normalizePypiName(name) : name}`
}

export function buildAdvisoryIndex(advisories: Advisory[]): AdvisoryIndex {
  const idx: AdvisoryIndex = new Map()
  for (const a of advisories) {
    const k = indexKey(a.ecosystem, a.packageName)
    const list = idx.get(k)
    if (list) list.push(a)
    else idx.set(k, [a])
  }
  return idx
}
