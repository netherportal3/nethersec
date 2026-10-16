import { describe, expect, it } from 'vitest'
import { GitHubClient, MAX_REPO_PAGES, readTextUpTo } from '../src/scanner/http.js'
import { filterRepos, resolveTargets, runScan, ScanCache } from '../src/scanner/scan.js'
import type { RepoInfo } from '../src/scanner/http.js'

const TOKEN = 'test-token-not-real'

interface Call {
  method: string
  url: string
  auth: string | null
}

const lockText = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'app' },
    'node_modules/lodash': { version: '4.17.20' },
    'node_modules/left-pad': { version: '1.3.0', dev: true },
  },
})

function fakeFetch(opts: { npmFails?: boolean } = {}) {
  const calls: Call[] = []
  const json = (body: unknown, init: ResponseInit = {}) =>
    new Response(JSON.stringify(body), { status: 200, ...init, headers: { 'content-type': 'application/json', 'x-ratelimit-remaining': '4999', ...(init.headers as object) } })
  const impl = async (url: string, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers)
    calls.push({ method: init?.method ?? 'GET', url, auth: headers.get('authorization') })
    const u = new URL(url)
    if (u.origin === 'https://api.github.com') {
      if (u.pathname === '/repos/me/app/git/trees/main') {
        if (headers.get('if-none-match') === '"e1"') return new Response(null, { status: 304 })
        return json({ tree: [{ path: 'package-lock.json', type: 'blob', sha: 'sha1', size: lockText.length }], truncated: false }, { headers: { etag: '"e1"' } })
      }
      if (u.pathname === '/repos/me/app/git/blobs/sha1') return new Response(lockText, { status: 200 })
      if (u.pathname === '/repos/me/broken/git/trees/main') return new Response('{}', { status: 404 })
      if (u.pathname === '/repos/me/moved/git/trees/main') {
        return new Response(null, { status: 301, headers: { location: 'https://evil.example/steal' } })
      }
      if (u.pathname.startsWith('/advisories/')) return new Response('{}', { status: 404 })
      return new Response('{}', { status: 404 })
    }
    if (url === 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk') {
      if (opts.npmFails) return new Response('oops', { status: 503 })
      const body = JSON.parse(String(init?.body))
      expect(body.lodash).toEqual(['4.17.20'])
      return json({
        lodash: [{ id: 1, url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm', title: 'Command Injection in lodash', severity: 'high', vulnerable_versions: '<4.17.21' }],
      })
    }
    throw new Error(`unexpected ${url}`)
  }
  return { impl, calls }
}

const repo = (fullName: string): RepoInfo => ({ fullName, defaultBranch: 'main', archived: false, fork: false, private: true })

describe('runScan', () => {
  it('reads lockfiles, matches advisories, and sends the token only to api.github.com', async () => {
    const { impl, calls } = fakeFetch()
    const github = new GitHubClient({ token: TOKEN, fetchImpl: impl })
    const cache = new ScanCache()
    const result = await runScan({ github, fetchImpl: impl, cache, targets: [repo('me/app'), repo('me/broken')] })

    expect(result.ecosystemsOk).toEqual({ npm: true, PyPI: true })
    const app = result.repos.find((r) => r.repo === 'me/app')!
    expect(app.status).toBe('ok')
    expect(app.findings).toHaveLength(1)
    expect(app.findings[0]).toMatchObject({ advisoryId: 'GHSA-35jh-r3h4-6jhm', packageName: 'lodash', severity: 'high' })
    expect(app.findings[0].fixes[0].to).toBe('4.17.21')
    const broken = result.repos.find((r) => r.repo === 'me/broken')!
    expect(broken.status).toBe('unreadable')
    expect(broken.reason).toContain('404')

    for (const c of calls) {
      if (c.auth) expect(new URL(c.url).origin).toBe('https://api.github.com')
      if (new URL(c.url).origin === 'https://api.github.com') expect(c.auth).toBe(`Bearer ${TOKEN}`)
    }

    // Second run: the tree answers 304 and the lockfile is not downloaded again.
    calls.length = 0
    github.resetStats()
    const again = await runScan({ github, fetchImpl: impl, cache, targets: [repo('me/app')] })
    expect(again.repos[0].findings).toHaveLength(1)
    expect(calls.some((c) => c.url.includes('/git/blobs/'))).toBe(false)
  })

  it('a failed npm lookup marks npm as not ok instead of reporting clean', async () => {
    const { impl } = fakeFetch({ npmFails: true })
    const github = new GitHubClient({ token: TOKEN, fetchImpl: impl })
    const result = await runScan({ github, fetchImpl: impl, cache: new ScanCache(), targets: [repo('me/app')] })
    expect(result.ecosystemsOk.npm).toBe(false)
    expect(result.errors[0]).toContain('registry.npmjs.org returned 503')
    expect(result.repos[0].findings).toEqual([])
  })

  it('never follows a redirect off api.github.com', async () => {
    const { impl, calls } = fakeFetch()
    const github = new GitHubClient({ token: TOKEN, fetchImpl: impl })
    const result = await runScan({ github, fetchImpl: impl, cache: new ScanCache(), targets: [repo('me/moved')] })
    expect(result.repos[0].status).toBe('unreadable')
    expect(calls.some((c) => c.url.startsWith('https://evil.example'))).toBe(false)
  })

  it('stops reading repos when the GitHub budget is low', async () => {
    const { impl } = fakeFetch()
    const github = new GitHubClient({ token: TOKEN, fetchImpl: impl })
    github.rateRemaining = 10
    const result = await runScan({ github, fetchImpl: impl, cache: new ScanCache(), targets: [repo('me/app')] })
    expect(result.repos[0].status).toBe('not-reached')
  })
})

describe('repo selection', () => {
  const all: RepoInfo[] = [
    { fullName: 'me/app', defaultBranch: 'main', archived: false, fork: false, private: true },
    { fullName: 'me/old', defaultBranch: 'main', archived: true, fork: false, private: false },
    { fullName: 'me/forked', defaultBranch: 'main', archived: false, fork: true, private: false },
    { fullName: 'me/skip', defaultBranch: 'main', archived: false, fork: false, private: false },
  ]
  const base = { mode: 'all' as const, repos: [], exclude: ['ME/SKIP'], includeForks: false, includeArchived: false }

  it('skips excluded, archived and forked repos unless chosen by name', () => {
    expect(filterRepos(all, base).map((r) => r.fullName)).toEqual(['me/app'])
    expect(filterRepos(all, { ...base, includeForks: true, includeArchived: true }).map((r) => r.fullName)).toEqual(['me/app', 'me/forked', 'me/old'])
    expect(filterRepos(all, { ...base, repos: ['me/old'] }).map((r) => r.fullName)).toEqual(['me/app', 'me/old'])
  })

  it('list mode looks up each chosen repo and reports the unreadable ones', async () => {
    const impl = async (url: string) => {
      if (url.endsWith('/repos/me/app')) return new Response(JSON.stringify({ full_name: 'me/app', default_branch: 'main' }), { status: 200 })
      return new Response('{}', { status: 404 })
    }
    const github = new GitHubClient({ token: TOKEN, fetchImpl: impl })
    const t = await resolveTargets(github, { ...base, mode: 'list', repos: ['me/app', 'me/nope'] })
    expect(t.targets.map((r) => r.fullName)).toEqual(['me/app'])
    expect(t.unreadable).toEqual([{ repo: 'me/nope', reason: 'GitHub returned 404 (no access, or the repo was renamed or deleted).' }])
  })

  it('says when the repo list stopped at its page limit with more to read', async () => {
    const page = (n: number, more: boolean) =>
      new Response(JSON.stringify([{ full_name: `me/r${n}`, default_branch: 'main' }]), {
        status: 200,
        headers: more ? { link: `<https://api.github.com/user/repos?page=${n + 1}>; rel="next"` } : {},
      })
    const listing = (pages: number) => async (url: string) => {
      const n = Number(new URL(url).searchParams.get('page') ?? '1')
      return page(n, n < pages)
    }
    const small = await new GitHubClient({ token: TOKEN, fetchImpl: listing(3) }).listRepos()
    expect([small.repos.length, small.capped]).toEqual([3, false])
    const huge = await new GitHubClient({ token: TOKEN, fetchImpl: listing(50) }).listRepos()
    expect([huge.repos.length, huge.capped]).toEqual([MAX_REPO_PAGES, true])
    expect((await resolveTargets(new GitHubClient({ token: TOKEN, fetchImpl: listing(50) }), { ...base, exclude: [] })).listCapped).toBe(true)
  })
})

describe('readTextUpTo', () => {
  it('refuses a body over the cap', async () => {
    expect(await readTextUpTo(new Response('x'.repeat(100)), 50)).toBeNull()
    expect(await readTextUpTo(new Response('hello'), 50)).toBe('hello')
  })
})
