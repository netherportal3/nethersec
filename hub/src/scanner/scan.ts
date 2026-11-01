/**
 * One scan: read every target repo's lockfiles, look up advisories, match.
 *
 * SAFETY: a read that fails is reported as such, never as clean.
 *   - A repo that cannot be read is `unreadable` (or `not-reached` when the
 *     GitHub rate limit stopped the run first) and has no findings; the planner
 *     keeps what it remembered for it.
 *   - When an advisory source fails, that ecosystem is marked not ok; the
 *     planner then neither resolves nor alerts on that ecosystem this run.
 *
 * Cheap repeat runs: a repo's tree is fetched with its ETag (a 304 does not
 * count against the GitHub rate limit), and a lockfile is parsed once per blob.
 */
import { buildAdvisoryIndex, type Advisory, type GlobalAdvisoryLookup } from './advisories.js'
import {
  failureKind,
  failureReason,
  mapLimit,
  SourceError,
  type FetchLike,
  type GitHubClient,
  type RepoInfo,
} from './http.js'
import { parseLockfile, selectLockfiles, type LockEcosystem, type ParsedLockfile, type SelectedLockfile } from './lockfiles.js'
import { applyGlobalFixes, fixLookupGhsa, matchRepo, type Finding } from './match.js'
import { fetchNpmAdvisories, fetchOsvAdvisories } from './sources.js'

export const MAX_LOCKFILES_PER_REPO = 20
export const MAX_LOCKFILE_BYTES = 5_000_000
const SCAN_CONCURRENCY = 4
/** Stop reading new repos when GitHub's remaining budget drops below this. */
const RATE_LIMIT_FLOOR = 100
/** Most global advisory lookups per run (fix versions the npm DB does not name). */
const GLOBAL_LOOKUP_CAP = 40
const GLOBAL_LOOKUP_TTL_MS = 24 * 60 * 60 * 1000

export interface RepoScan {
  repo: string
  status: 'ok' | 'unreadable' | 'not-reached'
  reason?: string
  lockfiles: Array<{ path: string; kind: string; packages: number; unpinned: number }>
  skipped: Array<{ path: string; reason: string }>
  treeTruncated: boolean
  findings: Finding[]
}

export interface ScanResult {
  repos: RepoScan[]
  /** False when that ecosystem's advisory source could not be read this run. */
  ecosystemsOk: Record<LockEcosystem, boolean>
  errors: string[]
}

type ParsedOrSkipped = ParsedLockfile | { skipped: string }

/** What one process remembers between runs. Lost on restart, which only costs a slower first run. */
export class ScanCache {
  trees = new Map<string, { ref: string; etag: string; selected: SelectedLockfile[]; skipped: RepoScan['skipped']; truncated: boolean }>()
  parsed = new Map<string, ParsedOrSkipped>()
  global = new Map<string, { at: number; lookup: GlobalAdvisoryLookup }>()
}

export interface RepoSelection {
  mode: 'all' | 'list'
  repos: string[]
  exclude: string[]
  includeForks: boolean
  includeArchived: boolean
}

/**
 * Pick the repos to scan from the token's repo list. Pure. A repo the owner
 * added by name is kept even when it is a fork or archived.
 */
export function filterRepos(all: RepoInfo[], sel: RepoSelection): RepoInfo[] {
  const excluded = new Set(sel.exclude.map((r) => r.toLowerCase()))
  const chosen = new Set(sel.repos.map((r) => r.toLowerCase()))
  return all
    .filter((r) => {
      const k = r.fullName.toLowerCase()
      if (chosen.has(k)) return true
      if (excluded.has(k)) return false
      return (sel.includeArchived || !r.archived) && (sel.includeForks || !r.fork)
    })
    .sort((a, b) => a.fullName.localeCompare(b.fullName))
}

/**
 * The repos to scan.
 *   - `all`: every repo the token can read (a failed listing THROWS: the run
 *     must not read as "nothing to watch"), minus exclusions, plus any repo in
 *     `repos` the listing does not include (someone else's public repo).
 *   - `list`: only the repos in `repos`.
 * A chosen repo that cannot be looked up comes back in `unreadable`.
 * `all` is the token's full repo list, for autocomplete (empty in `list` mode).
 */
export async function resolveTargets(
  github: GitHubClient,
  sel: RepoSelection,
): Promise<{
  targets: RepoInfo[]
  unreadable: Array<{ repo: string; reason: string }>
  ssoPartial: boolean
  /** The token can read more repos than the listing reads. */
  listCapped: boolean
  all: RepoInfo[]
}> {
  let listed: RepoInfo[] = []
  let ssoPartial = false
  let listCapped = false
  if (sel.mode === 'all') {
    const res = await github.listRepos()
    listed = res.repos
    ssoPartial = res.ssoPartial
    listCapped = res.capped
  }
  const have = new Set(listed.map((r) => r.fullName.toLowerCase()))
  const extra = sel.repos.filter((r) => !have.has(r.toLowerCase()))
  const unreadable: Array<{ repo: string; reason: string }> = []
  const found = await mapLimit(extra, SCAN_CONCURRENCY, async (repo) => {
    try {
      return await github.getRepo(repo)
    } catch (err) {
      unreadable.push({ repo, reason: failureReason(err, 'GitHub') })
      return null
    }
  })
  const chosen = found.filter((r): r is RepoInfo => r !== null)
  const fromListing = sel.mode === 'all' ? filterRepos(listed, sel) : []
  const seen = new Set(fromListing.map((r) => r.fullName.toLowerCase()))
  const targets = [...fromListing, ...chosen.filter((r) => !seen.has(r.fullName.toLowerCase()))]
  return { targets, unreadable, ssoPartial, listCapped, all: listed }
}

async function scanRepo(github: GitHubClient, cache: ScanCache, repo: RepoInfo, used: Set<string>): Promise<RepoScan & { parsed: ParsedLockfile[] }> {
  const base = { repo: repo.fullName, status: 'ok' as RepoScan['status'], lockfiles: [], skipped: [], treeTruncated: false, findings: [] }
  const out: RepoScan & { parsed: ParsedLockfile[] } = { ...base, parsed: [] }
  if (github.rateLimited || github.rateRemaining < RATE_LIMIT_FLOOR) {
    return { ...out, status: 'not-reached', reason: 'GitHub rate limit is low; this repo waits for the next scan.' }
  }
  const treeKey = repo.fullName.toLowerCase()
  let selected: SelectedLockfile[]
  try {
    const cached = cache.trees.get(treeKey)
    const etag = cached && cached.ref === repo.defaultBranch ? cached.etag : undefined
    const tree = await github.getTree(repo.fullName, repo.defaultBranch, etag)
    if (tree.notModified && cached) {
      selected = cached.selected
      out.skipped.push(...cached.skipped)
      out.treeTruncated = cached.truncated
    } else if (!tree.notModified) {
      const sel = selectLockfiles(tree.tree, { maxFiles: MAX_LOCKFILES_PER_REPO, maxBytes: MAX_LOCKFILE_BYTES })
      selected = sel.selected
      out.skipped.push(...sel.skipped)
      out.treeTruncated = tree.truncated
      if (tree.etag) cache.trees.set(treeKey, { ref: repo.defaultBranch, etag: tree.etag, selected, skipped: sel.skipped, truncated: tree.truncated })
      else cache.trees.delete(treeKey)
    } else {
      throw new SourceError('http', 'GitHub answered 304 for a tree that is not cached.')
    }
  } catch (err) {
    cache.trees.delete(treeKey)
    if (err instanceof SourceError && err.kind === 'empty') return out // an empty repo has no lockfiles
    if (failureKind(err) === 'rate') return { ...out, status: 'not-reached', reason: failureReason(err, 'GitHub') }
    return { ...out, status: 'unreadable', reason: failureReason(err, 'GitHub') }
  }

  for (const lf of selected) {
    const key = `${lf.sha}\0${lf.path}`
    used.add(key)
    let parsed = cache.parsed.get(key)
    if (!parsed) {
      let text: string | null
      try {
        text = await github.getBlobText(repo.fullName, lf.sha, MAX_LOCKFILE_BYTES)
      } catch (err) {
        if (failureKind(err) === 'rate') return { ...out, status: 'not-reached', reason: failureReason(err, 'GitHub') }
        return { ...out, status: 'unreadable', reason: `${lf.path}: ${failureReason(err, 'GitHub')}` }
      }
      if (text === null) parsed = { skipped: 'too big' }
      else {
        try {
          parsed = parseLockfile(lf.path, lf.kind, text)
        } catch {
          parsed = { skipped: 'could not be parsed' }
        }
      }
      cache.parsed.set(key, parsed)
    }
    if ('skipped' in parsed) {
      out.skipped.push({ path: lf.path, reason: parsed.skipped })
      continue
    }
    out.parsed.push(parsed)
    out.lockfiles.push({ path: parsed.path, kind: parsed.kind, packages: parsed.packages.length, unpinned: parsed.unpinned })
  }
  return out
}

/** Scan the targets. Never throws: every failure lands in the result. */
export async function runScan(opts: {
  github: GitHubClient
  fetchImpl: FetchLike
  cache: ScanCache
  targets: RepoInfo[]
  now?: () => number
}): Promise<ScanResult> {
  const { github, fetchImpl, cache, targets } = opts
  const now = opts.now ?? Date.now
  const used = new Set<string>()
  const scanned = await mapLimit(targets, SCAN_CONCURRENCY, (repo) => scanRepo(github, cache, repo, used))
  // Forget repos and lockfiles no longer scanned, so the cache only holds the current set.
  const targetKeys = new Set(targets.map((t) => t.fullName.toLowerCase()))
  for (const key of cache.trees.keys()) if (!targetKeys.has(key)) cache.trees.delete(key)
  for (const key of cache.parsed.keys()) if (!used.has(key)) cache.parsed.delete(key)

  const npmPkgs = new Map<string, Set<string>>()
  const pins = new Map<string, { name: string; version: string }>()
  for (const r of scanned) {
    if (r.status !== 'ok') continue
    for (const lf of r.parsed) {
      for (const p of lf.packages) {
        if (lf.ecosystem === 'npm') {
          let versions = npmPkgs.get(p.name)
          if (!versions) npmPkgs.set(p.name, (versions = new Set()))
          versions.add(p.version)
        } else {
          pins.set(`${p.name}@${p.version}`, { name: p.name, version: p.version })
        }
      }
    }
  }

  const errors: string[] = []
  const ecosystemsOk: Record<LockEcosystem, boolean> = { npm: true, PyPI: true }
  const advisories: Advisory[] = []
  try {
    if (npmPkgs.size > 0) advisories.push(...(await fetchNpmAdvisories(fetchImpl, npmPkgs)))
  } catch (err) {
    ecosystemsOk.npm = false
    errors.push(`npm advisories: ${failureReason(err, 'npm registry')}`)
  }
  try {
    if (pins.size > 0) advisories.push(...(await fetchOsvAdvisories(fetchImpl, [...pins.values()])))
  } catch (err) {
    ecosystemsOk.PyPI = false
    errors.push(`Python advisories: ${failureReason(err, 'OSV')}`)
  }

  const index = buildAdvisoryIndex(advisories)
  const repos: RepoScan[] = scanned.map(({ parsed, ...r }) =>
    r.status === 'ok' ? { ...r, findings: matchRepo(r.repo, parsed, index) } : r,
  )

  await fillGlobalFixes(github, cache, repos.flatMap((r) => r.findings), now)
  return { repos, ecosystemsOk, errors }
}

/**
 * Fix versions the npm DB does not name, from the global GitHub advisory DB.
 * Display only, best effort: a failed lookup leaves the fix unknown.
 */
async function fillGlobalFixes(github: GitHubClient, cache: ScanCache, findings: Finding[], now: () => number): Promise<void> {
  const wanted = new Map<string, Finding[]>()
  for (const f of findings) {
    const ghsa = fixLookupGhsa(f)
    if (!ghsa) continue
    const list = wanted.get(ghsa)
    if (list) list.push(f)
    else wanted.set(ghsa, [f])
  }
  const toFetch = [...wanted.keys()].filter((g) => {
    const hit = cache.global.get(g)
    return !hit || hit.lookup.status === 'failed' || now() - hit.at > GLOBAL_LOOKUP_TTL_MS
  })
  await mapLimit(toFetch.slice(0, GLOBAL_LOOKUP_CAP), SCAN_CONCURRENCY, async (ghsa) => {
    if (github.rateLimited || github.rateRemaining < RATE_LIMIT_FLOOR) return
    cache.global.set(ghsa, { at: now(), lookup: await github.getGlobalAdvisory(ghsa) })
  })
  for (const [ghsa, list] of wanted) {
    const hit = cache.global.get(ghsa)
    if (hit?.lookup.status !== 'reviewed') continue
    for (const f of list) applyGlobalFixes(f, hit.lookup.advisories)
  }
  // Keep the lookup cache bounded to what is still open.
  for (const key of cache.global.keys()) if (!wanted.has(key)) cache.global.delete(key)
}
