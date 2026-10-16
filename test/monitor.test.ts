import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import type { Client } from 'discord.js'
import { afterEach, describe, expect, it } from 'vitest'
import type { Payload } from '../src/discord/cards.js'
import { Monitor } from '../src/monitor.js'
import { GitHubClient } from '../src/scanner/http.js'
import { Store } from '../src/store.js'

const SETUP = { categoryId: 'cat', criticalChannelId: 'crit', alertsChannelId: 'alerts', statusChannelId: 'status', roleId: '42', private: true }

function fakeDiscord() {
  const sent: Array<{ channelId: string; payload: Payload; id: string }> = []
  const edits: Array<{ channelId: string; messageId: string; payload: any }> = []
  const messages = new Map<string, any>()
  const failing = new Set<string>()
  let n = 0
  const channel = (id: string) => ({
    isSendable: () => true,
    isTextBased: () => true,
    send: async (payload: Payload) => {
      if (failing.has(id)) throw new Error('Missing Access')
      const mid = `m${++n}`
      sent.push({ channelId: id, payload, id: mid })
      messages.set(mid, payload)
      return { id: mid }
    },
    messages: {
      fetch: async (mid: string) => {
        const p = messages.get(mid)
        if (!p) throw new Error('Unknown Message')
        return {
          embeds: p.embeds.map((e: unknown) => ({ toJSON: () => e })),
          edit: async (next: any) => {
            edits.push({ channelId: id, messageId: mid, payload: next })
            messages.set(mid, { ...p, ...next })
          },
        }
      },
    },
  })
  const client = { channels: { fetch: async (id: string) => channel(id) } } as unknown as Client
  return { client, sent, edits, failing }
}

/** GitHub + npm, with the advisories the npm endpoint returns set per scan. */
function fakeSources() {
  let advisories: Record<string, unknown[]> = {}
  let onLookup: (() => void) | null = null
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/minimist': { version: '1.2.0' } } })
  const json = (body: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status: 200, headers: { 'x-ratelimit-remaining': '4000', ...headers } })
  const impl = async (url: string, init?: RequestInit): Promise<Response> => {
    const u = new URL(url)
    if (u.pathname === '/user') return json({ login: 'tester' }, { 'x-oauth-scopes': 'repo' })
    if (u.pathname === '/user/repos') return json([{ full_name: 'me/app', default_branch: 'main' }])
    if (u.pathname === '/repos/me/app/git/trees/main') return json({ tree: [{ path: 'package-lock.json', type: 'blob', sha: 'b1', size: lock.length }] })
    if (u.pathname === '/repos/me/app/git/blobs/b1') return new Response(lock, { status: 200 })
    if (u.pathname.endsWith('/advisories/bulk') && init?.method === 'POST') {
      onLookup?.()
      return json(advisories)
    }
    return new Response('{}', { status: 404 })
  }
  return {
    impl,
    set: (a: Record<string, unknown[]>) => (advisories = a),
    /** Run `fn` while the scan looks up advisories, before anything is posted. */
    duringLookup: (fn: (() => void) | null) => (onLookup = fn),
  }
}

const LODASH = { id: 1, url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm', title: 'Command Injection in lodash', severity: 'high', vulnerable_versions: '<4.17.21' }
const MINIMIST = { id: 2, url: 'https://github.com/advisories/GHSA-xvch-5gv4-984h', title: 'Prototype Pollution in minimist', severity: 'critical', vulnerable_versions: '<1.2.6' }

const monitors: Monitor[] = []
afterEach(() => {
  for (const m of monitors) m.stop()
})

async function setupMonitor() {
  const discord = fakeDiscord()
  const sources = fakeSources()
  const store = await Store.open(await mkdtemp(path.join(tmpdir(), 'cve-monitor-')), 60)
  store.state.setup = { ...SETUP }
  const github = new GitHubClient({ token: 'test-token', fetchImpl: sources.impl })
  const monitor = new Monitor({ client: discord.client, store, github, fetchImpl: sources.impl })
  monitors.push(monitor)
  return { discord, sources, store, monitor }
}

const titles = (sent: Array<{ channelId: string; payload: Payload }>) => sent.map((s) => `${s.channelId}: ${s.payload.embeds[0].title}`)

describe('Monitor', () => {
  it('baselines quietly, alerts what is new once, and marks it fixed when it goes away', async () => {
    const { discord, sources, store, monitor } = await setupMonitor()

    sources.set({ lodash: [LODASH] })
    await monitor.run()
    expect(titles(discord.sent)).toEqual(['status: Now watching', 'status: CVE Monitor'])
    expect(store.state.repos['me/app'].baselined).toEqual({ npm: true, PyPI: true })

    discord.sent.length = 0
    sources.set({ lodash: [LODASH], minimist: [MINIMIST] })
    await monitor.run()
    expect(titles(discord.sent)).toEqual(['crit: Critical: minimist (GHSA-xvch-5gv4-984h)'])
    const alert = discord.sent[0].payload
    expect(alert.content).toBe('<@&42>')
    expect(alert.allowedMentions).toEqual({ parse: [], roles: ['42'] })
    const cardId = store.state.repos['me/app'].findings['GHSA-xvch-5gv4-984h:minimist'].cardId!
    expect(store.state.cards[cardId]).toMatchObject({ channelId: 'crit', repos: { 'me/app': 'open' } })

    // The same advisory is not alerted again.
    discord.sent.length = 0
    await monitor.run()
    expect(titles(discord.sent)).toEqual([])

    // Gone: the card turns to fixed, and the status channel says so once.
    sources.set({ lodash: [LODASH] })
    await monitor.run()
    expect(store.state.cards[cardId].resolvedAt).toBeDefined()
    const edit = discord.edits.find((e) => e.messageId === store.state.cards[cardId].messageId)!
    expect(edit.payload.embeds[0].title).toMatch(/^Fixed: /)
    expect(titles(discord.sent)).toEqual(['status: Fixed since the last scan'])
    expect(store.state.lastRun).toMatchObject({ repos: 1, readable: 1, fixed: 1, newAlerts: 0 })
  })

  it('a card that fails to post is tried again on the next scan', async () => {
    const { discord, sources, store, monitor } = await setupMonitor()
    sources.set({})
    await monitor.run()

    discord.sent.length = 0
    discord.failing.add('crit')
    sources.set({ minimist: [MINIMIST] })
    await monitor.run()
    expect(titles(discord.sent)).toEqual([])
    expect(store.state.repos['me/app'].findings['GHSA-xvch-5gv4-984h:minimist']).toBeUndefined()
    expect(store.state.lastRun?.errors.some((e) => e.includes('GHSA-xvch-5gv4-984h'))).toBe(true)

    discord.failing.clear()
    await monitor.run()
    expect(titles(discord.sent)).toEqual(['crit: Critical: minimist (GHSA-xvch-5gv4-984h)'])
  })

  it('a stop before posting drops the scan, so the restart posts each card once', async () => {
    const { discord, sources, store, monitor } = await setupMonitor()
    sources.set({})
    await monitor.run()
    const before = JSON.stringify(store.state.repos)
    const lastRun = store.state.lastRun

    discord.sent.length = 0
    sources.set({ minimist: [MINIMIST] })
    sources.duringLookup(() => monitor.stop())
    const run = monitor.run()
    expect(await monitor.whenIdle(5_000)).toBe(true)
    await run
    expect(discord.sent).toEqual([])
    expect(JSON.stringify(store.state.repos)).toBe(before)
    expect(store.state.lastRun).toBe(lastRun)

    // The restart: a new process on the same saved state.
    sources.duringLookup(null)
    const github = new GitHubClient({ token: 'test-token', fetchImpl: sources.impl })
    const restarted = new Monitor({ client: discord.client, store, github, fetchImpl: sources.impl })
    monitors.push(restarted)
    await restarted.run()
    await restarted.run()
    expect(titles(discord.sent)).toEqual(['crit: Critical: minimist (GHSA-xvch-5gv4-984h)'])
  })

  it('whenIdle waits for a running scan, and gives up after the timeout', async () => {
    const { discord, sources, store, monitor } = await setupMonitor()
    expect(await monitor.whenIdle(10)).toBe(true)
    let release!: () => void
    const held = new Promise<void>((resolve) => (release = resolve))
    // The advisory lookup hangs until released.
    const slow = new Monitor({
      client: discord.client,
      store,
      github: new GitHubClient({ token: 'test-token', fetchImpl: sources.impl }),
      fetchImpl: async (url, init) => {
        if (url.includes('/advisories/bulk')) await held
        return sources.impl(url, init)
      },
    })
    monitors.push(slow)
    const run = slow.run()
    expect(await slow.whenIdle(20)).toBe(false)
    release()
    expect(await slow.whenIdle(5_000)).toBe(true)
    await run
  })

  it('does nothing until set up, and nothing while paused', async () => {
    const { discord, sources, store, monitor } = await setupMonitor()
    sources.set({ lodash: [LODASH] })
    store.state.settings.paused = true
    expect(monitor.scanNow()).toBe('paused')
    await monitor.run()
    expect(store.state.lastRun).toBeNull()
    // Only the status board is refreshed, to show "Paused".
    expect(titles(discord.sent)).toEqual(['status: CVE Monitor'])
    discord.sent.length = 0
    store.state.settings.paused = false
    store.state.setup = null
    expect(monitor.scanNow()).toBe('not-set-up')
    await monitor.run()
    expect(store.state.lastRun).toBeNull()
    expect(discord.sent).toEqual([])
  })
})
