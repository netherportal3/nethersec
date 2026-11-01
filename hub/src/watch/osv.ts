/**
 * OSV (https://osv.dev) for the container check.
 *
 * querybatch answers, per (ecosystem, package, version), the ids of the
 * vulnerabilities that affect that exact version. OSV does the version compare, so
 * a Debian or Alpine version needs no parser here. It returns ids and `modified`
 * only; a record's details (severity, fixed versions) need one GET each.
 *
 * Both calls THROW on any failure, with a fixed message that carries no response
 * text: the caller treats a throw as "OSV could not be read", never as clean.
 */
import { fetchText, postJson, type HttpOptions } from './http.js'

export const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
export const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/'
/** Queries per OSV batch (OSV allows 1000). */
export const OSV_BATCH_CHUNK = 500
/** Most querybatch rounds per chunk (OSV pages a query with many matches). */
export const OSV_MAX_PAGES = 10
const MAX_BATCH_BYTES = 16 * 1024 * 1024
const MAX_VULN_BYTES = 2 * 1024 * 1024

export interface OsvQuery {
  ecosystem: string
  name: string
  version: string
}

export interface OsvHit {
  id: string
  /** The record's `modified` time as OSV gave it, or null. */
  modified: string | null
}

/**
 * Every vulnerability OSV lists for each query, all pages read. One list per
 * query, in the same order. THROWS when any chunk or page fails, OSV keeps paging
 * past OSV_MAX_PAGES, or the deadline passes before a later page.
 */
export async function osvQueryBatch(http: HttpOptions, queries: OsvQuery[], opts: { deadline: number; now: () => number }): Promise<OsvHit[][]> {
  const out: OsvHit[][] = queries.map(() => [])
  for (let i = 0; i < queries.length; i += OSV_BATCH_CHUNK) {
    // A query whose result carries next_page_token has more matches: only those
    // are sent again, with the token, until none is left.
    let pending = queries.slice(i, i + OSV_BATCH_CHUNK).map((q, k) => ({ q, at: i + k, pageToken: undefined as string | undefined }))
    for (let page = 0; pending.length > 0; page++) {
      if (page >= OSV_MAX_PAGES) throw new Error('OSV kept returning more pages than one run reads.')
      if (page > 0 && opts.now() >= opts.deadline) throw new Error('Out of time for OSV pages.')
      const body = (await postJson(
        http,
        OSV_BATCH_URL,
        {
          queries: pending.map(({ q, pageToken }) => ({
            package: { name: q.name, ecosystem: q.ecosystem },
            version: q.version,
            ...(pageToken ? { page_token: pageToken } : {}),
          })),
        },
        MAX_BATCH_BYTES,
      )) as { results?: unknown }
      const results = Array.isArray(body?.results) ? (body.results as Array<Record<string, unknown> | null>) : null
      // One result per query, in order. A short list would read the rest as clean.
      if (!results || results.length !== pending.length) throw new Error('OSV returned an unexpected shape.')
      const more: typeof pending = []
      pending.forEach((p, idx) => {
        const result = results[idx]
        for (const v of Array.isArray(result?.vulns) ? (result.vulns as Array<Record<string, unknown> | null>) : []) {
          if (typeof v?.id !== 'string' || v.id.length > 100) continue
          out[p.at].push({ id: v.id, modified: typeof v.modified === 'string' ? v.modified.slice(0, 40) : null })
        }
        const token = result?.next_page_token
        if (typeof token === 'string' && token) more.push({ ...p, pageToken: token })
      })
      pending = more
    }
  }
  return out
}

/** One full OSV record. THROWS on a non-2xx answer or a body that is not JSON. */
export async function osvGetVuln(http: HttpOptions, id: string): Promise<unknown> {
  const res = await fetchText(http, OSV_VULN_URL + encodeURIComponent(id), 'json', { cap: MAX_VULN_BYTES })
  if (res.status !== 'ok') throw new Error(`api.osv.dev returned ${res.status === 'failed' && res.code ? res.code : 'no answer'}.`)
  try {
    return JSON.parse(res.text)
  } catch {
    throw new Error('api.osv.dev returned a body that is not JSON.')
  }
}
