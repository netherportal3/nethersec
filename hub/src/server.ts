/**
 * The hub's HTTP server (node:http, no framework):
 *
 *   POST /v1/report  a key's report (reports/handler.ts)
 *   GET  /v1/state   open alerts, hosts and data, with NETHERSEC_API_TOKEN
 *   GET  /v1/health  {"ok":true}, no token
 *
 * Plain HTTP: put it behind HTTPS or on a private network. Answers are JSON and
 * never echo a key, a title or a detail back.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { bearer, sha256 } from './reports/keys.js'
import { MAX_BODY_BYTES } from './reports/protocol.js'
import type { ReportHandler } from './reports/handler.js'

export interface ServerDeps {
  reports: ReportHandler
  /** The state view; called per request. */
  state: () => unknown
  /** null = GET /v1/state is off. */
  apiToken: string | null
  log?: (msg: string) => void
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  if (res.headersSent) return
  const text = JSON.stringify(body)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  })
  res.end(text)
}

/** A body up to this size is read to the end before a 413, so the sender gets the answer instead of a reset. */
const DRAIN_MAX_BYTES = 1_000_000

type Body = { ok: true; text: string } | { ok: false; drained: boolean }

/** The body as text, or not ok past MAX_BODY_BYTES (checked on the header and while reading). */
function readBody(req: IncomingMessage): Promise<Body> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'])
    if (Number.isFinite(declared) && declared > DRAIN_MAX_BYTES) return resolve({ ok: false, drained: false })
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > DRAIN_MAX_BYTES) {
        req.removeAllListeners('data')
        req.pause()
        resolve({ ok: false, drained: false })
        return
      }
      if (size <= MAX_BODY_BYTES) chunks.push(chunk)
    })
    req.on('end', () => resolve(size > MAX_BODY_BYTES ? { ok: false, drained: true } : { ok: true, text: Buffer.concat(chunks).toString('utf8') }))
    req.on('error', reject)
  })
}

/** Constant-time check of the state API token (both sides hashed, so lengths do not leak). */
export function apiTokenMatches(header: string | undefined, token: string | null): boolean {
  if (!token) return false
  const presented = bearer(header)
  if (!presented) return false
  return timingSafeEqual(sha256(presented), sha256(token))
}

export function createHubServer(deps: ServerDeps): Server {
  const log = deps.log ?? (() => {})
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://hub.invalid')
      const route = url.pathname

      if (route === '/v1/health') {
        if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Use GET.' }, { Allow: 'GET, HEAD' })
        return send(res, 200, { ok: true })
      }

      if (route === '/v1/state') {
        if (req.method !== 'GET') return send(res, 405, { error: 'Use GET.' }, { Allow: 'GET' })
        if (!deps.apiToken) return send(res, 404, { error: 'The state API is off. Set NETHERSEC_API_TOKEN on the hub to turn it on.' })
        if (!apiTokenMatches(req.headers.authorization, deps.apiToken)) {
          return send(res, 401, { error: 'Missing or wrong token.' }, { 'WWW-Authenticate': 'Bearer' })
        }
        return send(res, 200, deps.state())
      }

      if (route === '/v1/report') {
        if (req.method !== 'POST') return send(res, 405, { error: 'Use POST.' }, { Allow: 'POST' })
        const key = await deps.reports.authenticate(req.headers.authorization)
        if (!key) {
          res.setHeader('Connection', 'close')
          req.resume()
          return send(res, 401, { error: 'Missing or unknown key.' }, { 'WWW-Authenticate': 'Bearer' })
        }
        const body = await readBody(req)
        if (!body.ok) {
          res.setHeader('Connection', 'close')
          // A huge body is not read: the connection closes once the answer is out.
          if (!body.drained) res.once('finish', () => req.destroy())
          return send(res, 413, { error: `The body is over ${MAX_BODY_BYTES} bytes.` })
        }
        const reply = await deps.reports.handle(key, body.text)
        const headers: Record<string, string> = {}
        if (reply.retryAfterSec !== undefined) headers['Retry-After'] = String(reply.retryAfterSec)
        return send(res, reply.status, reply.body, headers)
      }

      return send(res, 404, { error: 'Not found.' })
    } catch (err) {
      log(`A request failed: ${err instanceof Error ? err.name : 'unknown'}`)
      send(res, 500, { error: 'Internal error.' })
    }
  })
  // A slow or stuck client cannot hold a connection for long.
  server.headersTimeout = 10_000
  server.requestTimeout = 20_000
  server.keepAliveTimeout = 5_000
  server.maxHeadersCount = 50
  return server
}

export function listen(server: Server, at: { host: string; port: number }): Promise<{ host: string; port: number }> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(at.port, at.host, () => {
      server.off('error', reject)
      const addr = server.address()
      resolve(typeof addr === 'object' && addr ? { host: addr.address, port: addr.port } : at)
    })
  })
}
