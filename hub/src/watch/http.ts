/**
 * HTTP for the watch: GETs with a size cap and an optional ETag, and the OSV POST.
 *
 * The GitHub token goes ONLY to https://api.github.com, as a header. Redirects are
 * refused, so no header ever follows a redirect to another host; a feed that moved
 * reads as failed until its address is updated. A failure is a status code or
 * nothing: no response text, URL or header ever reaches a log line.
 */
export const USER_AGENT = 'nethersec-hub-watch'
export const GITHUB_API = 'https://api.github.com'
const FETCH_TIMEOUT_MS = 20_000

export type TextRead = { status: 'ok'; text: string; etag?: string } | { status: 'not-modified' } | { status: 'failed'; code?: number }

export type Accept = 'github' | 'json' | 'rss'

const ACCEPT: Record<Accept, string> = {
  github: 'application/vnd.github+json',
  json: 'application/json',
  rss: 'application/rss+xml, application/xml;q=0.9, text/xml;q=0.8',
}

export interface HttpOptions {
  fetch: typeof fetch
  githubToken?: string
}

/** Reads a body, giving up (null) once it passes `cap` bytes. */
export async function readTextUpTo(res: Response, cap: number): Promise<string | null> {
  const reader = res.body?.getReader()
  if (!reader) return null
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      if (!value) continue
      total += value.byteLength
      if (total > cap) return null
      chunks.push(value)
    }
  } catch {
    return null
  } finally {
    await reader.cancel().catch(() => {})
  }
  return new TextDecoder().decode(Buffer.concat(chunks))
}

/** A GET. `etag` makes it conditional; a 304 is `not-modified`. Never throws. */
export async function fetchText(
  http: HttpOptions,
  url: string,
  accept: Accept,
  opts: { etag?: string; cap: number; timeoutMs?: number },
): Promise<TextRead> {
  const headers: Record<string, string> = { Accept: ACCEPT[accept], 'User-Agent': USER_AGENT }
  if (url.startsWith(`${GITHUB_API}/`)) {
    headers['X-GitHub-Api-Version'] = '2022-11-28'
    if (http.githubToken) headers.Authorization = `Bearer ${http.githubToken}`
  }
  if (opts.etag) headers['If-None-Match'] = opts.etag
  try {
    const res = await http.fetch(url, {
      headers,
      redirect: 'error',
      signal: AbortSignal.timeout(opts.timeoutMs ?? FETCH_TIMEOUT_MS),
    })
    if (res.status === 304) {
      await res.body?.cancel().catch(() => {})
      return { status: 'not-modified' }
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => {})
      return { status: 'failed', code: res.status }
    }
    const text = await readTextUpTo(res, opts.cap)
    if (text === null) return { status: 'failed' }
    return { status: 'ok', text, etag: res.headers.get('etag') || undefined }
  } catch {
    return { status: 'failed' }
  }
}

/** A GET of JSON. Null on any failure, a 304 included (no ETag is sent). */
export async function fetchJson(http: HttpOptions, url: string, cap: number, timeoutMs?: number): Promise<{ ok: true; body: unknown } | { ok: false; code?: number }> {
  const res = await fetchText(http, url, 'json', { cap, timeoutMs })
  if (res.status !== 'ok') return { ok: false, code: res.status === 'failed' ? res.code : undefined }
  try {
    return { ok: true, body: JSON.parse(res.text) }
  } catch {
    return { ok: false }
  }
}

/** A JSON POST. THROWS a fixed message on any failure. */
export async function postJson(http: HttpOptions, url: string, body: unknown, cap: number, timeoutMs?: number): Promise<unknown> {
  let res: Response
  try {
    res = await http.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': USER_AGENT },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs ?? FETCH_TIMEOUT_MS),
    })
  } catch {
    throw new Error(`${new URL(url).host} could not be reached.`)
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {})
    throw new Error(`${new URL(url).host} returned ${res.status}.`)
  }
  const text = await readTextUpTo(res, cap)
  if (text === null) throw new Error(`${new URL(url).host} returned a body that is too large or broken.`)
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`${new URL(url).host} returned a body that is not JSON.`)
  }
}
