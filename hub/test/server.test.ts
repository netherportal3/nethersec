import type { Server } from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { apiTokenMatches, createHubServer, listen } from '../src/server.js'
import { buildStateView } from '../src/stateView.js'
import { auth, keyLineFor, makeHub } from './hubHelpers.js'

const servers: Server[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))))
})

const API_TOKEN = 'state-token-'.padEnd(40, 'x')

async function serve(apiToken: string | null = API_TOKEN) {
  const h = await makeHub({ keys: [keyLineFor('web1', 'web1', 'page')] })
  const server = createHubServer({
    reports: h.reports,
    apiToken,
    state: () => buildStateView(h.store.state, { now: new Date('2025-03-03T10:00:00Z'), discordReady: true, repoScanning: false }),
  })
  servers.push(server)
  const at = await listen(server, { host: '127.0.0.1', port: 0 })
  const base = `http://127.0.0.1:${at.port}`
  const report = (body: unknown, authz: string | null = auth('web1')) =>
    fetch(`${base}/v1/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(authz ? { Authorization: authz } : {}) },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    })
  return { ...h, base, report }
}

describe('the report server', () => {
  it('health needs no token', async () => {
    const s = await serve()
    const res = await fetch(`${s.base}/v1/health`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
    expect((await fetch(`${s.base}/nope`)).status).toBe(404)
    expect((await fetch(`${s.base}/v1/report`)).status).toBe(405)
  })

  it('takes a report end to end: 202 and a card', async () => {
    const s = await serve()
    const res = await s.report({ kind: 'security', source: 'web1', event: 'ssh-auth-burst', severity: 'critical', title: 'Burst', detail: 'Do not echo me' })
    expect(res.status).toBe(202)
    const text = await res.text()
    expect(JSON.parse(text)).toEqual({ accepted: true, result: 'posted' })
    expect(text).not.toContain('Burst')
    expect(s.discord.sent).toHaveLength(1)
  })

  it('401 without a key or with an unknown one, and never echoes it', async () => {
    const s = await serve()
    expect((await s.report({ kind: 'security', source: 'web1', event: 'x' }, null)).status).toBe(401)
    const res = await s.report({ kind: 'security', source: 'web1', event: 'x' }, 'Bearer made-up-key')
    expect(res.status).toBe(401)
    expect(await res.text()).not.toContain('made-up-key')
  })

  it('400 names the field; 403 for another source', async () => {
    const s = await serve()
    const bad = await s.report({ kind: 'security', source: 'web1', event: 'x', severity: 'loud' })
    expect(bad.status).toBe(400)
    expect(await bad.json()).toMatchObject({ field: 'severity' })
    expect((await s.report('not json')).status).toBe(400)
    expect((await s.report({ kind: 'security', source: 'db1', event: 'x' })).status).toBe(403)
  })

  it('413 for a body over 100 kB', async () => {
    const s = await serve()
    const res = await s.report({ kind: 'security', source: 'web1', event: 'container-packages', detail: 'x'.repeat(100_001) })
    expect(res.status).toBe(413)
  })

  it('429 carries Retry-After', async () => {
    const s = await serve()
    let res: Response | undefined
    for (let i = 0; i < 31; i++) res = await s.report({ kind: 'security', source: 'web1', event: 'ssh-auth-burst', detail: `n${i}` })
    expect(res!.status).toBe(429)
    expect(Number(res!.headers.get('retry-after'))).toBeGreaterThan(0)
  })

  it('503 while Discord is not connected', async () => {
    const s = await serve()
    s.discord.state.ready = false
    expect((await s.report({ kind: 'security', source: 'web1', event: 'ssh-auth-burst' })).status).toBe(503)
  })
})

describe('the state API', () => {
  it('is off without NETHERSEC_API_TOKEN', async () => {
    const s = await serve(null)
    const res = await fetch(`${s.base}/v1/state`, { headers: { Authorization: `Bearer ${API_TOKEN}` } })
    expect(res.status).toBe(404)
  })

  it('needs its own token, never a box key', async () => {
    const s = await serve()
    expect((await fetch(`${s.base}/v1/state`)).status).toBe(401)
    expect((await fetch(`${s.base}/v1/state`, { headers: { Authorization: auth('web1') } })).status).toBe(401)
    expect((await fetch(`${s.base}/v1/state`, { headers: { Authorization: `Bearer ${API_TOKEN}x` } })).status).toBe(401)
    expect(apiTokenMatches(`Bearer ${API_TOKEN}`, API_TOKEN)).toBe(true)
    expect(apiTokenMatches(`Bearer ${API_TOKEN}`, null)).toBe(false)
  })

  it('shows open cards, hosts, pending reboots and container counts', async () => {
    const s = await serve()
    await s.report({ kind: 'security', source: 'web1', event: 'ssh-auth-burst', title: 'Burst', detail: 'Many logins' })
    await s.report({ kind: 'security', source: 'web1', event: 'reboot-pending', detail: 'v=1 checked=no pkgs=openssl' })
    await s.report({ kind: 'security', source: 'web1', event: 'container-packages', detail: 'v=1 ctr=api img=nginx:1 pm=apk pkgs=openssl@3.3.2-r0,zlib@1.3.1-r1' })
    const res = await fetch(`${s.base}/v1/state`, { headers: { Authorization: `Bearer ${API_TOKEN}` } })
    expect(res.status).toBe(200)
    const view = await res.json()
    expect(view).toMatchObject({
      v: 1,
      generatedAt: '2025-03-03T10:00:00.000Z',
      discord: { ready: true, setUp: true },
      repos: { scanning: 'off', watched: 0 },
      cards: [{ kind: 'security', severity: 'warning', title: 'Burst', detail: 'Many logins', source: 'web1', event: 'ssh-auth-burst', acked: false, reportedFixed: false }],
      hosts: [{ source: 'web1', reports: 3, open: 1 }],
      rebootPending: [{ source: 'web1', checked: false, packages: ['openssl'] }],
      containers: [{ box: 'web1', container: 'api', image: 'nginx:1', packages: 2, more: 0 }],
    })
  })
})
