/**
 * HTTP for the scanner: GitHub reads with the token, and the public npm and OSV
 * advisory endpoints.
 *
 * The GitHub token is sent ONLY as an Authorization header on GET requests to
 * https://api.github.com. A redirect is followed only while it stays on that
 * host, so the header never leaves GitHub. Every failure maps to a fixed,
 * token-free reason: an error message never carries a URL or a header.
 */
import { parseGlobalAdvisory, type GlobalAdvisoryLookup } from './advisories.js'
import type { TreeEntryLite } from './lockfiles.js'

export const GITHUB_API = 'https://api.github.com'
export const USER_AGENT = 'discord-cve-monitor'
const FETCH_TIMEOUT_MS = 20_000
const BLOB_TIMEOUT_MS = 60_000
/** 100 repos a page. */
export const MAX_REPO_PAGES = 20
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
const MAX_GITHUB_REDIRECTS = 3

export type FailKind = 'auth' | 'forbidden' | 'not-found' | 'empty' | 'rate' | 'http' | 'timeout' | 'network' | 'bad-body'

export class SourceError extends Error {
  constructor(
    public kind: FailKind,
    message: string,
  ) {
    super(message)
    this.name = 'SourceError'
  }
}

/** Map a GitHub status to a fixed, token-free reason. */
export function describeGitHubStatus(status: number, rateLimited: boolean): { kind: FailKind; reason: string } {
  if (rateLimited) return { kind: 'rate', reason: 'GitHub rate limit reached.' }
  if (status === 401) return { kind: 'auth', reason: 'GitHub rejected the token (401). It is invalid, expired or revoked.' }
  if (status === 403) {
    return { kind: 'forbidden', reason: 'GitHub returned 403 (no access, or SSO is not authorized for this token).' }
  }
  if (status === 404) return { kind: 'not-found', reason: 'GitHub returned 404 (no access, or the repo was renamed or deleted).' }
  if (status === 409) return { kind: 'empty', reason: 'The repo is empty.' }
  return { kind: 'http', reason: `GitHub returned ${status}.` }
}

/** A reason that is safe to show: a SourceError's own message, else the error's name only. */
export function failureReason(err: unknown, what: string): string {
  if (err instanceof SourceError) return err.message
  if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
    return `No response from ${what} in time.`
  }
  // The error's name only (TypeError, SyntaxError...): never its message, which can carry a URL.
  const name = err instanceof Error && err.name ? ` (${err.name})` : ''
  return `The ${what} request failed${name}.`
}

export function failureKind(err: unknown): FailKind {
  if (err instanceof SourceError) return err.kind
  if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) return 'timeout'
  return 'network'
}

export function encodeRepoPath(fullName: string): string {
  return fullName
    .split('/')
    .map((seg) => encodeURIComponent(seg))
    .join('/')
}

/** `Link: <url>; rel="next"` -> url, else null. */
export function parseNextLink(linkHeader: string | null | undefined): string | null {
  if (!linkHeader) return null
  for (const part of linkHeader.split(',')) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="next"/)
    if (m) return m[1]
  }
  return null
}

/** Read a body up to `cap` bytes; null when it is bigger. */
export async function readTextUpTo(res: Response, cap: number): Promise<string | null> {
  const len = Number(res.headers.get('content-length'))
  if (Number.isFinite(len) && len > cap) {
    await res.body?.cancel().catch(() => {})
    return null
  }
  if (!res.body) return await res.text()
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > cap) {
      await reader.cancel().catch(() => {})
      return null
    }
    chunks.push(value)
  }
  return new TextDecoder().decode(Buffer.concat(chunks))
}

export interface RepoInfo {
  fullName: string
  defaultBranch: string
  archived: boolean
  fork: boolean
  private: boolean
}

function toRepoInfo(raw: any): RepoInfo | null {
  if (!raw || typeof raw.full_name !== 'string' || typeof raw.default_branch !== 'string') return null
  return {
    fullName: raw.full_name,
    defaultBranch: raw.default_branch,
    archived: raw.archived === true,
    fork: raw.fork === true,
    private: raw.private === true,
  }
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export class GitHubClient {
  /** Lowest X-RateLimit-Remaining seen since the last resetStats(). */
  rateRemaining = Number.POSITIVE_INFINITY
  rateLimited = false
  private readonly token: string
  private readonly fetchImpl: FetchLike

  constructor(opts: { token: string; fetchImpl?: FetchLike }) {
    this.token = opts.token
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init))
  }

  resetStats(): void {
    this.rateRemaining = Number.POSITIVE_INFINITY
    this.rateLimited = false
  }

  /**
   * `fetch` for api.github.com. A redirect is followed only while it stays on
   * api.github.com (a moved or renamed repo answers 301 to `/repositories/<id>/...`).
   * A redirect anywhere else, or past a few hops, throws.
   */
  private async fetchGitHub(url: string, init: RequestInit): Promise<Response> {
    let current = url
    for (let hop = 0; ; hop++) {
      if (new URL(current).origin !== GITHUB_API) throw new SourceError('http', 'Refused a non-GitHub URL.')
      const res = await this.fetchImpl(current, { ...init, redirect: 'manual' })
      if (!REDIRECT_STATUSES.has(res.status)) return res
      await res.body?.cancel().catch(() => {})
      const location = res.headers.get('location')
      if (!location || hop >= MAX_GITHUB_REDIRECTS) {
        throw new SourceError('http', `GitHub answered ${res.status} without a redirect it could follow.`)
      }
      current = new URL(location, current).toString()
    }
  }

  /**
   * GET from api.github.com. `pathOrUrl` is a path built from encoded segments,
   * or a pagination link, which must also be on api.github.com. Returns the
   * response for 2xx and, when `etag` is given, for 304. Throws SourceError otherwise.
   */
  async get(
    pathOrUrl: string,
    opts: { accept?: string; etag?: string; timeoutMs?: number } = {},
  ): Promise<Response> {
    const url = pathOrUrl.startsWith('https://') ? pathOrUrl : `${GITHUB_API}${pathOrUrl}`
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.token}`,
      Accept: opts.accept ?? 'application/vnd.github+json',
      'User-Agent': USER_AGENT,
      'X-GitHub-Api-Version': '2022-11-28',
    }
    if (opts.etag) headers['If-None-Match'] = opts.etag
    const res = await this.fetchGitHub(url, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(opts.timeoutMs ?? FETCH_TIMEOUT_MS),
    })
    const raw = res.headers.get('x-ratelimit-remaining')
    if (raw !== null && Number.isFinite(Number(raw))) this.rateRemaining = Math.min(this.rateRemaining, Number(raw))
    if (res.status === 304 && opts.etag) return res
    if (!res.ok) {
      await res.body?.cancel().catch(() => {})
      const rateLimited = (res.status === 403 || res.status === 429) && raw === '0'
      if (rateLimited || res.status === 429) this.rateLimited = true
      const { kind, reason } = describeGitHubStatus(res.status, rateLimited || res.status === 429)
      throw new SourceError(kind, reason)
    }
    return res
  }

  private async json(res: Response, what: string): Promise<any> {
    try {
      return await res.json()
    } catch {
      throw new SourceError('bad-body', `GitHub returned ${what} that is not JSON.`)
    }
  }

  /** Who the token belongs to, and whether a classic token lacks the `repo` scope (public repos only). */
  async whoami(): Promise<{ login: string; publicOnly: boolean }> {
    const res = await this.get('/user')
    const body = await this.json(res, 'a user')
    const scopes = res.headers.get('x-oauth-scopes')
    // Classic tokens list their scopes; fine-grained tokens send no header.
    const publicOnly =
      scopes !== null &&
      !scopes
        .split(',')
        .map((s) => s.trim())
        .includes('repo')
    return { login: typeof body?.login === 'string' ? body.login : 'unknown', publicOnly }
  }

  /**
   * Every repo the token can read: owned, collaborator, and org member, up to
   * MAX_REPO_PAGES pages. `capped` says the list stopped there with more to read.
   */
  async listRepos(): Promise<{ repos: RepoInfo[]; ssoPartial: boolean; capped: boolean }> {
    const out: RepoInfo[] = []
    let ssoPartial = false
    let next: string | null = '/user/repos?affiliation=owner,collaborator,organization_member&per_page=100&sort=full_name'
    for (let page = 0; page < MAX_REPO_PAGES && next; page++) {
      const res = await this.get(next)
      // GitHub drops repos of SAML SSO orgs the token is not authorized for, and
      // says so only in this header.
      if (/partial-results/i.test(res.headers.get('x-github-sso') || '')) ssoPartial = true
      const batch = await this.json(res, 'a repo list')
      if (!Array.isArray(batch)) throw new SourceError('bad-body', 'GitHub returned a repo list in an unexpected shape.')
      for (const raw of batch) {
        const r = toRepoInfo(raw)
        if (r) out.push(r)
      }
      next = parseNextLink(res.headers.get('link'))
    }
    return { repos: out, ssoPartial, capped: next !== null }
  }

  async getRepo(fullName: string): Promise<RepoInfo> {
    const res = await this.get(`/repos/${encodeRepoPath(fullName)}`)
    const r = toRepoInfo(await this.json(res, 'repo details'))
    if (!r) throw new SourceError('bad-body', 'GitHub returned repo details in an unexpected shape.')
    return r
  }

  /** The recursive tree of `ref`. `notModified` when the ETag still matches. */
  async getTree(
    fullName: string,
    ref: string,
    etag?: string,
  ): Promise<{ notModified: true } | { notModified: false; tree: TreeEntryLite[]; truncated: boolean; etag: string | null }> {
    const res = await this.get(`/repos/${encodeRepoPath(fullName)}/git/trees/${encodeURIComponent(ref)}?recursive=1`, { etag })
    if (res.status === 304) {
      await res.body?.cancel().catch(() => {})
      return { notModified: true }
    }
    const body = await this.json(res, 'a tree')
    if (!body || !Array.isArray(body.tree)) throw new SourceError('bad-body', 'GitHub returned a tree in an unexpected shape.')
    return { notModified: false, tree: body.tree, truncated: body.truncated === true, etag: res.headers.get('etag') }
  }

  /** A blob's raw text, or null when it is over `maxBytes`. */
  async getBlobText(fullName: string, sha: string, maxBytes: number): Promise<string | null> {
    const res = await this.get(`/repos/${encodeRepoPath(fullName)}/git/blobs/${encodeURIComponent(sha)}`, {
      accept: 'application/vnd.github.raw',
      timeoutMs: BLOB_TIMEOUT_MS,
    })
    return readTextUpTo(res, maxBytes)
  }

  /** One record of the global GitHub advisory DB. Never throws. */
  async getGlobalAdvisory(ghsa: string): Promise<GlobalAdvisoryLookup> {
    try {
      const res = await this.get(`/advisories/${encodeURIComponent(ghsa)}`)
      return parseGlobalAdvisory(await res.json().catch(() => null), ghsa)
    } catch (err) {
      return err instanceof SourceError && err.kind === 'not-found' ? { status: 'missing' } : { status: 'failed' }
    }
  }
}

/** POST JSON to a public endpoint (npm, OSV). No credentials. Throws SourceError. */
export async function postJson(fetchImpl: FetchLike, url: string, body: unknown): Promise<unknown> {
  const host = new URL(url).host
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': USER_AGENT },
    body: JSON.stringify(body),
    redirect: 'error',
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  })
  if (!res.ok) {
    await res.body?.cancel().catch(() => {})
    throw new SourceError('http', `${host} returned ${res.status}.`)
  }
  try {
    return await res.json()
  } catch {
    throw new SourceError('bad-body', `${host} returned a body that is not JSON.`)
  }
}

/** GET JSON from a public endpoint (OSV). No credentials. Throws SourceError. */
export async function getJson(fetchImpl: FetchLike, url: string): Promise<unknown> {
  const host = new URL(url).host
  const res = await fetchImpl(url, {
    headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
    redirect: 'error',
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  })
  if (!res.ok) {
    await res.body?.cancel().catch(() => {})
    throw new SourceError('http', `${host} returned ${res.status}.`)
  }
  try {
    return await res.json()
  } catch {
    throw new SourceError('bad-body', `${host} returned a body that is not JSON.`)
  }
}

/** Run `fn` over `items` with at most `limit` in flight. Order of results matches input. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await fn(items[i], i)
    }
  })
  await Promise.all(workers)
  return out
}
