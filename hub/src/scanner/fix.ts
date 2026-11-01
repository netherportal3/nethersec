/**
 * The version that fixes one installed copy. PURE and total: bad input gives
 * "no fix known", never a throw and never a version at or below the install.
 *
 * npm: an exclusive `<X` upper bound of the vulnerable comparator set the
 * install sits in is the fix; otherwise (or when X is on another release line)
 * the patched versions are read, preferring the same release line and a stable
 * release. PyPI: the smallest plain dotted fixed version above the install.
 */
import semver from 'semver'
import { ELLIPSIS } from './advisories.js'

export interface FixLine {
  from: string
  /** The version to move to, or null when none is known. */
  to: string | null
  /** The fix is on another release line (a major bump, or a 0.x minor bump). */
  crossesLine: boolean
  /** Only a prerelease fixes it so far. */
  prereleaseOnly?: boolean
  /** The advisory itself says nothing is fixed yet (an open-ended range, or OSV with no fix event). */
  unfixed?: boolean
}

export interface FixSource {
  /** npm semver ranges the install matched (already readable by semver). */
  vulnerableRanges?: string[]
  /** Patched versions or specs as the sources gave them. */
  patched?: string[]
  /** OSV: the record lists no fix at all. */
  noFixListed?: boolean
}

/** The release line a version belongs to: major, or 0.minor for 0.x versions. */
function releaseLine(v: semver.SemVer): string {
  return v.major === 0 ? `0.${v.minor}` : String(v.major)
}

/**
 * Split a patched spec into candidate tokens: an operator is joined to its
 * version (">= 14.2.35" becomes ">=14.2.35"), then the text is split on commas,
 * `||` and whitespace.
 */
function specTokens(spec: string): string[] {
  return spec
    .slice(0, 4000)
    .replace(/=>/g, '>=')
    .replace(/=</g, '<=')
    .replace(/(>=|<=|==|~=|!=|>|<|=|\^|~)\s+/g, '$1')
    .split(/\|\||[\s,;]+/)
    .filter(Boolean)
    .slice(0, 200)
}

/** True for a token that names an upper bound or a strict lower bound, never a fixed version. */
function isBoundToken(tok: string): boolean {
  return /^(<|>(?!=)|!)/.test(tok)
}

function hasEllipsis(tok: string): boolean {
  return tok.includes(ELLIPSIS) || tok.includes('...')
}

/** One npm patched token as a fixed version, or null when it does not name one. */
function npmCandidate(tok: string): semver.SemVer | null {
  if (tok.length > 100 || hasEllipsis(tok) || isBoundToken(tok)) return null
  const t = tok.replace(/^(>=|==|=|\^|~)/, '').replace(/^v/, '')
  if (!t) return null
  // A short form ("16", "16.3") is safe to widen; anything with letters is not
  // (coerce turns a sha into 74.0.0 and drops a canary tag).
  if (/^\d+(\.\d+)?$/.test(t)) return semver.coerce(t)
  return semver.parse(t)
}

/** A PyPI version as integer segments (leading zeros dropped), or null when it is not a plain dotted number. */
function pyTuple(s: string): string[] | null {
  if (typeof s !== 'string' || s.length > 64 || !/^\d+(\.\d+)*$/.test(s)) return null
  const segs = s.split('.')
  // A long run of digits is a sha or a date stamp, not a release; six segments is plenty.
  if (segs.length > 6 || segs.some((x) => x.length > 15)) return null
  return segs.map((x) => x.replace(/^0+(?=\d)/, ''))
}

/** Compare two PyPI tuples of any length, padding with zeros (2.31.0.1 > 2.31.0). */
function pyCompare(a: string[], b: string[]): number {
  const n = Math.max(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const x = a[i] ?? '0'
    const y = b[i] ?? '0'
    if (x.length !== y.length) return x.length < y.length ? -1 : 1
    if (x !== y) return x < y ? -1 : 1
  }
  return 0
}

function pyLine(t: string[]): string {
  return t[0] === '0' ? `0.${t[1] ?? '0'}` : t[0]
}

interface RangeInfo {
  /** The exclusive upper bound of the comparator set(s) the installed version sits in. */
  fix: semver.SemVer | null
  /** A matching set has no upper bound at all: the advisory says nothing is fixed yet. */
  openEnded: boolean
}

/**
 * Read the vulnerable ranges for the installed version. For every comparator
 * set it satisfies: a `<X` bound means X is the first fixed version of that
 * set; no upper bound means nothing is fixed yet. An inclusive `<=X` bound
 * names the last affected version, so it says neither (the fix, if any, is
 * above X but unnamed). An exact-version set tells nothing about the fix.
 */
function analyseRanges(ranges: unknown, inst: semver.SemVer): RangeInfo {
  let openEnded = false
  let fix: semver.SemVer | null = null
  if (!Array.isArray(ranges)) return { fix, openEnded }
  for (const r of ranges.slice(0, 20)) {
    if (typeof r !== 'string' || !r.trim() || r.length > 2000) continue
    let range: semver.Range
    try {
      range = new semver.Range(r, { includePrerelease: true })
    } catch {
      continue
    }
    for (const set of range.set) {
      if (!set.every((c) => c.test(inst))) continue
      let lt: semver.SemVer | null = null
      let le: semver.SemVer | null = null
      let exact = false
      for (const c of set) {
        if (c.value === '') continue // '*': no bound
        if (c.operator === '<') lt = !lt || semver.lt(c.semver, lt) ? c.semver : lt
        else if (c.operator === '<=') le = !le || semver.lt(c.semver, le) ? c.semver : le
        else if (c.operator === '' || c.operator === '=') exact = true
      }
      // Inclusive bound first: the last affected version, not "no fix exists".
      if (le && (!lt || semver.lte(le, lt))) continue
      if (lt) {
        if (!fix || semver.gt(lt, fix)) fix = lt
      } else if (!exact) {
        openEnded = true
      }
    }
  }
  if (openEnded) return { fix: null, openEnded }
  // A desugared bound ("^1.2.3" reads as "<2.0.0-0") means the release itself.
  if (fix && fix.prerelease.length === 1 && fix.prerelease[0] === 0) {
    fix = semver.parse(`${fix.major}.${fix.minor}.${fix.patch}`)
  }
  return { fix, openEnded }
}

/**
 * Smallest candidate above the installed version: on the same release line
 * first, else on a higher line (crosses = true). A stable install skips
 * prerelease candidates unless they are all the line has (pre = true).
 */
function pickNpm(pool: semver.SemVer[], inst: semver.SemVer): { v: semver.SemVer; crosses: boolean; pre: boolean } | null {
  const line = releaseLine(inst)
  const stableInstall = inst.prerelease.length === 0
  const sorted = pool.filter((c) => semver.gt(c, inst)).sort((a, b) => semver.compare(a, b))
  const choose = (list: semver.SemVer[]): { v: semver.SemVer; pre: boolean } | null => {
    if (!list.length) return null
    const stable = list.find((c) => c.prerelease.length === 0)
    if (stableInstall) return stable ? { v: stable, pre: false } : { v: list[0], pre: true }
    return { v: list[0], pre: list[0].prerelease.length > 0 && !stable }
  }
  const same = choose(sorted.filter((c) => releaseLine(c) === line))
  if (same) return { ...same, crosses: false }
  const higher = choose(sorted.filter((c) => releaseLine(c) !== line))
  return higher ? { ...higher, crosses: true } : null
}

function computeNpmLine(installed: string, src: FixSource): FixLine {
  const base: FixLine = { from: installed, to: null, crossesLine: false }
  const inst = semver.parse(installed)
  if (!inst) return base
  const { fix, openEnded } = analyseRanges(src.vulnerableRanges, inst)
  const cands: semver.SemVer[] = []
  for (const spec of (src.patched ?? []).slice(0, 50)) {
    if (typeof spec !== 'string') continue
    for (const tok of specTokens(spec)) {
      const c = npmCandidate(tok)
      if (c && semver.gt(c, inst)) cands.push(c)
    }
  }
  let pick: ReturnType<typeof pickNpm>
  if (fix && releaseLine(fix) === releaseLine(inst)) {
    // The range names the exact fix on this line. A patched entry only wins
    // when it is a stable release at or above it and the bound is a prerelease.
    pick = pickNpm([fix, ...cands.filter((c) => semver.gte(c, fix) && releaseLine(c) === releaseLine(fix))], inst)
  } else {
    // No bound, or the bound sits on another line: a patched backport on this
    // line (or a nearer line) may exist.
    pick = pickNpm(fix ? [fix, ...cands] : cands, inst)
  }
  if (!pick) return openEnded ? { ...base, unfixed: true } : base
  const out: FixLine = { from: installed, to: pick.v.version, crossesLine: pick.crosses }
  if (pick.pre) out.prereleaseOnly = true
  return out
}

function computePypiLine(installed: string, src: FixSource): FixLine {
  const base: FixLine = { from: installed, to: null, crossesLine: false }
  const it = pyTuple(installed)
  if (!it) return src.noFixListed ? { ...base, unfixed: true } : base
  let best: { raw: string; tuple: string[] } | null = null
  for (const spec of (src.patched ?? []).slice(0, 50)) {
    if (typeof spec !== 'string') continue
    for (const tok of specTokens(spec)) {
      if (hasEllipsis(tok) || isBoundToken(tok)) continue
      const raw = tok.replace(/^(>=|==|~=|=)/, '').replace(/^v/, '')
      const tuple = pyTuple(raw)
      if (!tuple || pyCompare(tuple, it) <= 0) continue
      if (!best || pyCompare(tuple, best.tuple) < 0) best = { raw, tuple }
    }
  }
  if (!best) return src.noFixListed ? { ...base, unfixed: true } : base
  return { from: installed, to: best.raw, crossesLine: pyLine(best.tuple) !== pyLine(it) }
}

/** The fix for one installed version. Never throws. */
export function computeFixLine(ecosystem: 'npm' | 'PyPI', installed: string, src: FixSource): FixLine {
  const from = typeof installed === 'string' ? installed.trim() : ''
  try {
    const s = src && typeof src === 'object' ? src : {}
    return ecosystem === 'PyPI' ? computePypiLine(from, s) : computeNpmLine(from, s)
  } catch {
    return { from, to: null, crossesLine: false }
  }
}
