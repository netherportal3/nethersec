import { describe, expect, it } from 'vitest'
import { fetchOsvAdvisories, OSV_DETAIL_CAP } from '../src/scanner/sources.js'

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 })

/** A fake OSV: `batch` answers each querybatch call, records come from `/v1/vulns/<id>`. */
function fakeOsv(batch: (queries: any[], call: number) => unknown) {
  const bodies: any[] = []
  const impl = async (url: string, init?: RequestInit): Promise<Response> => {
    const u = new URL(url)
    if (u.pathname === '/v1/querybatch') {
      const body = JSON.parse(String(init?.body))
      bodies.push(body)
      return json(batch(body.queries, bodies.length))
    }
    const id = decodeURIComponent(u.pathname.replace('/v1/vulns/', ''))
    return json({ id, summary: id, affected: [{ package: { ecosystem: 'PyPI', name: 'flask' }, ranges: [] }] })
  }
  return { impl, bodies }
}

const PINS = [
  { name: 'flask', version: '1.0.0' },
  { name: 'requests', version: '2.0.0' },
]

describe('OSV lookups', () => {
  it('follows next_page_token until every query is read', async () => {
    const osv = fakeOsv((queries, call) =>
      call === 1
        ? { results: [{ vulns: [{ id: 'PYSEC-1' }], next_page_token: 'p2' }, { vulns: [] }] }
        : { results: queries.map(() => ({ vulns: [{ id: 'PYSEC-2' }] })) },
    )
    const out = await fetchOsvAdvisories(osv.impl, PINS)
    expect(out.map((a) => a.id).sort()).toEqual(['PYSEC-1', 'PYSEC-2'])
    // Only the paged query goes again, with its token.
    expect(osv.bodies[1].queries).toEqual([{ package: { name: 'flask', ecosystem: 'PyPI' }, version: '1.0.0', page_token: 'p2' }])
  })

  it('throws when the pages do not end, rather than leave advisories out', async () => {
    const osv = fakeOsv((queries) => ({ results: queries.map(() => ({ vulns: [], next_page_token: 'again' })) }))
    await expect(fetchOsvAdvisories(osv.impl, PINS)).rejects.toThrow(/more pages/)
  })

  it('throws when a result is missing, rather than read those packages as clean', async () => {
    const osv = fakeOsv(() => ({ results: [{ vulns: [] }] }))
    await expect(fetchOsvAdvisories(osv.impl, PINS)).rejects.toThrow(/unexpected shape/)
  })

  it('throws when there are more advisories than one scan reads', async () => {
    const many = Array.from({ length: OSV_DETAIL_CAP + 1 }, (_, i) => ({ id: `PYSEC-${i}` }))
    const osv = fakeOsv((queries) => ({ results: queries.map((_, i) => ({ vulns: i === 0 ? many : [] })) }))
    await expect(fetchOsvAdvisories(osv.impl, PINS)).rejects.toThrow(/more than 1000 advisories/)
  })
})
