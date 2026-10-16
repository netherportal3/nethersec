/**
 * Advisory lookups against the public npm and OSV endpoints. No credentials.
 * Each function THROWS when its source cannot be read in full: the caller then
 * treats that ecosystem as unknown for this run (nothing is marked fixed, nothing new).
 */
import { parseNpmBulk, parseOsvVuln, type Advisory } from './advisories.js'
import { getJson, mapLimit, postJson, SourceError, type FetchLike } from './http.js'

const NPM_BULK_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'
const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/'
/** Package names per npm bulk request. */
const NPM_BULK_CHUNK = 400
/** Queries per OSV batch request (the API allows 1000). */
const OSV_BATCH_CHUNK = 500
/**
 * Most OSV records fetched in one run. Past it the lookup THROWS rather than
 * leave some out: a left-out advisory would read as fixed.
 */
export const OSV_DETAIL_CAP = 1000
/** Most follow-up pages for one batch (OSV pages a query with many matches). */
const OSV_MAX_PAGES = 10
const CONCURRENCY = 4

/** npm bulk lookup for every installed name and version. */
export async function fetchNpmAdvisories(fetchImpl: FetchLike, pkgs: Map<string, Set<string>>): Promise<Advisory[]> {
  const names = [...pkgs.keys()].sort()
  const chunks: string[][] = []
  for (let i = 0; i < names.length; i += NPM_BULK_CHUNK) chunks.push(names.slice(i, i + NPM_BULK_CHUNK))
  const results = await mapLimit(chunks, CONCURRENCY, async (chunk) => {
    const body: Record<string, string[]> = {}
    for (const n of chunk) body[n] = [...(pkgs.get(n) || [])].sort()
    return parseNpmBulk(await postJson(fetchImpl, NPM_BULK_URL, body))
  })
  return results.flat()
}

/** OSV lookup for exact Python pins. */
export async function fetchOsvAdvisories(
  fetchImpl: FetchLike,
  pins: Array<{ name: string; version: string }>,
): Promise<Advisory[]> {
  if (pins.length === 0) return []
  // vuln id -> package -> versions
  const hits = new Map<string, Map<string, Set<string>>>()
  for (let i = 0; i < pins.length; i += OSV_BATCH_CHUNK) {
    // A query whose result carries next_page_token has more matches: it is sent
    // again with that token until none is left.
    let queries = pins.slice(i, i + OSV_BATCH_CHUNK).map((pin) => ({ pin, pageToken: undefined as string | undefined }))
    for (let page = 0; queries.length > 0; page++) {
      if (page >= OSV_MAX_PAGES) throw new SourceError('bad-body', 'OSV kept returning more pages than one scan reads.')
      const body: any = await postJson(fetchImpl, OSV_BATCH_URL, {
        queries: queries.map(({ pin, pageToken }) => ({
          package: { name: pin.name, ecosystem: 'PyPI' },
          version: pin.version,
          ...(pageToken ? { page_token: pageToken } : {}),
        })),
      })
      const results = Array.isArray(body?.results) ? body.results : null
      // One result per query, in order. A short list would leave packages unchecked.
      if (!results || results.length !== queries.length) throw new SourceError('bad-body', 'OSV returned an unexpected shape.')
      const more: typeof queries = []
      queries.forEach(({ pin }, idx) => {
        const result = results[idx]
        for (const v of Array.isArray(result?.vulns) ? result.vulns : []) {
          if (typeof v?.id !== 'string') continue
          let byPkg = hits.get(v.id)
          if (!byPkg) hits.set(v.id, (byPkg = new Map()))
          let versions = byPkg.get(pin.name)
          if (!versions) byPkg.set(pin.name, (versions = new Set()))
          versions.add(pin.version)
        }
        if (typeof result?.next_page_token === 'string' && result.next_page_token) {
          more.push({ pin, pageToken: result.next_page_token })
        }
      })
      queries = more
    }
  }
  if (hits.size > OSV_DETAIL_CAP) {
    throw new SourceError('bad-body', `OSV matched more than ${OSV_DETAIL_CAP} advisories, more than one scan reads.`)
  }
  const ids = [...hits.keys()].sort()
  const records = await mapLimit(ids, CONCURRENCY, async (id) => ({
    id,
    record: await getJson(fetchImpl, OSV_VULN_URL + encodeURIComponent(id)),
  }))
  const out: Advisory[] = []
  for (const { id, record } of records) {
    for (const [pkg, versions] of hits.get(id) || []) {
      const adv = parseOsvVuln(record, pkg, [...versions])
      if (adv) out.push(adv)
    }
  }
  return out
}
