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
/** Most OSV records fetched in one run; malware reports are fetched first. */
const OSV_DETAIL_CAP = 300
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
    const chunk = pins.slice(i, i + OSV_BATCH_CHUNK)
    const body: any = await postJson(fetchImpl, OSV_BATCH_URL, {
      queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'PyPI' }, version: p.version })),
    })
    const results = Array.isArray(body?.results) ? body.results : null
    if (!results) throw new SourceError('bad-body', 'OSV returned an unexpected shape.')
    chunk.forEach((p, idx) => {
      for (const v of Array.isArray(results[idx]?.vulns) ? results[idx].vulns : []) {
        if (typeof v?.id !== 'string') continue
        let byPkg = hits.get(v.id)
        if (!byPkg) hits.set(v.id, (byPkg = new Map()))
        let versions = byPkg.get(p.name)
        if (!versions) byPkg.set(p.name, (versions = new Set()))
        versions.add(p.version)
      }
    })
  }
  // Malicious-package reports first, so the cap never drops one.
  const isMal = (id: string) => (/^MAL-/i.test(id) ? 0 : 1)
  const ids = [...hits.keys()].sort((a, b) => isMal(a) - isMal(b) || (a < b ? -1 : a > b ? 1 : 0)).slice(0, OSV_DETAIL_CAP)
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
