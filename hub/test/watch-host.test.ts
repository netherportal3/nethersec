import { afterEach, describe, expect, it, vi } from 'vitest'
import { MAX_OPEN_WATCH_CARDS, WATCH_CRITICAL_RESERVE, WatchCardsFullError, type WatchCard } from '../src/cards/ops.js'
import { opsCardEdit } from '../src/cards/render.js'
import { COLORS, dashboardEmbed } from '../src/discord/cards.js'
import { HourlyJobs, MAX_MODULE_STATE_BYTES } from '../src/jobs.js'
import { buildStateView } from '../src/stateView.js'
import type { OpsCardState } from '../src/state.js'
import { Store } from '../src/store.js'
import { createWatchHost } from '../src/watchHost.js'
import { keyLineFor, auth, makeHub, titles } from './hubHelpers.js'

const WATCHER = '6'.repeat(18)

async function host(opts: { setup?: boolean } = {}) {
  const h = await makeHub({ keys: [keyLineFor('db1', 'db1')], ...opts })
  const logs: string[] = []
  const timers: Array<{ fn: () => void; ms: number }> = []
  const jobs = new HourlyJobs({
    isSetUp: () => !!h.store.state.setup,
    log: (m) => logs.push(m),
    setTimer: (fn, ms) => {
      timers.push({ fn, ms })
      return 0 as unknown as NodeJS.Timeout
    },
    clearTimer: () => {},
  })
  const w = createWatchHost({ ops: h.ops, store: h.store, jobs, log: (m) => logs.push(m) })
  return { ...h, w, jobs, logs, timers }
}

/** Open watch cards, written straight into the state (their messages are not in the fake Discord). */
function fillWatchCards(cards: Record<string, OpsCardState>, at: string, n = MAX_OPEN_WATCH_CARDS): void {
  for (let i = 0; i < n; i++) {
    cards[`w${i}`] = { id: `w${i}`, key: `watch:x${i}`, kind: 'watch', severity: 'info', title: 't', body: '', channelId: 'status', messageId: `m-${i}`, createdAt: at, updatedAt: at, contentHash: 'h' }
  }
}

const card = (over: Partial<WatchCard> = {}): WatchCard => ({ id: 'feed:CVE-2026-0001', severity: 'warning', ping: true, title: 'A new advisory', body: 'Fixed in **1.2.3**.', ...over })

describe('watch cards', () => {
  it('upsert creates once, edits in place on a change, and never reposts an unchanged card', async () => {
    const h = await host()
    await h.w.cards.upsert(card())
    await h.w.cards.upsert(card())
    expect(titles(h.discord.sent)).toEqual(['alerts: Warning: A new advisory'])
    expect(h.discord.edits).toHaveLength(0)
    // Watch bodies are markdown, written by the module.
    expect(h.discord.sent[0].payload.embeds[0].description).toBe('Fixed in **1.2.3**.')
    await h.w.cards.upsert(card({ body: 'Fixed in 1.2.4.' }))
    expect(h.discord.sent).toHaveLength(1)
    expect(h.discord.edits).toHaveLength(1)
    const labels = h.discord.sent[0].payload.components![0].components.map((c) => ('label' in c ? c.label : ''))
    expect(labels).toEqual(['Acknowledge', 'Resolve'])
  })

  it('honors ping only for critical, and on an open card only when it rose to critical', async () => {
    const h = await host()
    await h.w.cards.upsert(card({ id: 'a', severity: 'warning', ping: true }))
    expect(h.discord.sent[0].payload.content).toBeUndefined()
    await h.w.cards.upsert(card({ id: 'b', severity: 'critical', ping: true }))
    expect(h.discord.sent[1]).toMatchObject({ channelId: 'crit', payload: { content: '<@&42>' } })
    await h.w.cards.upsert(card({ id: 'c', severity: 'critical', ping: false }))
    expect(h.discord.sent[2].payload.content).toBeUndefined()
    await h.w.cards.upsert(card({ id: 'a', severity: 'critical', ping: true }))
    expect(titles(h.discord.sent).at(-1)).toBe('crit: Now critical: A new advisory')
    expect(h.discord.sent.at(-1)!.payload.content).toBe('<@&42>')
    await h.w.cards.upsert(card({ id: 'a', severity: 'critical', ping: true, body: 'changed' }))
    expect(h.discord.sent.filter((s) => s.payload.content)).toHaveLength(2)
  })

  it('info cards go to the status channel; close resolves, and is a no-op when nothing is open', async () => {
    const h = await host()
    await h.w.cards.upsert(card({ severity: 'info', url: 'https://osv.dev/vulnerability/CVE-2026-0001' }))
    expect(h.discord.sent[0].channelId).toBe('status')
    expect(h.discord.sent[0].payload.components![0].components[0]).toMatchObject({ label: 'Open', url: 'https://osv.dev/vulnerability/CVE-2026-0001' })
    await h.w.cards.close('feed:CVE-2026-0001', 'Withdrawn upstream.')
    const edit = h.discord.edits.at(-1)!.payload
    expect(edit.embeds[0].title).toBe('Closed: A new advisory')
    expect(edit.embeds[0].fields!.find((f) => f.name === 'Status')!.value).toMatch(/^Closed <t:\d+:R>: Withdrawn upstream\.$/)
    const edits = h.discord.edits.length
    await h.w.cards.close('feed:CVE-2026-0001', 'again')
    await h.w.cards.close('never-opened', 'x')
    expect(h.discord.edits).toHaveLength(edits)
    // The same id later is a new card.
    await h.w.cards.upsert(card())
    expect(h.discord.sent).toHaveLength(2)
  })

  it('rejects a bad card, and rejects while the hub cannot post', async () => {
    const h = await host()
    await expect(h.w.cards.upsert(card({ id: 'has space' }))).rejects.toThrow(TypeError)
    await expect(h.w.cards.upsert(card({ severity: 'high' as never }))).rejects.toThrow(TypeError)
    await expect(h.w.cards.upsert(card({ title: ' ' }))).rejects.toThrow(TypeError)
    h.discord.state.ready = false
    await expect(h.w.cards.upsert(card())).rejects.toThrow('Discord is not reachable')
    h.discord.state.ready = true
    h.discord.fail.send = true
    await expect(h.w.cards.upsert(card())).rejects.toThrow('could not be posted')
    expect(Object.keys(h.store.state.opsCards)).toHaveLength(0)
    const n = await host({ setup: false })
    await expect(n.w.cards.upsert(card())).rejects.toThrow('not set up')
  })

  it('caps the open watch cards', async () => {
    const h = await host()
    fillWatchCards(h.store.state.opsCards, new Date().toISOString())
    await expect(h.w.cards.upsert(card())).rejects.toThrow('Too many open watch cards')
  })

  it('Resolve closes a watch card, and a later upsert of the same id opens a new card', async () => {
    const h = await host()
    await h.w.cards.upsert(card())
    const first = h.ops.findOpen('watch:feed:CVE-2026-0001')!
    expect((await h.ops.press('mute', first.id, WATCHER)).ok).toBe(false)
    const pressed = await h.ops.press('resolve', first.id, WATCHER)
    expect(pressed.ok).toBe(true)
    const edit = opsCardEdit((pressed as { card: Parameters<typeof opsCardEdit>[0] }).card)
    expect(edit.embeds[0].title).toBe('Resolved: A new advisory')
    expect(edit.embeds[0].fields!.find((f) => f.name === 'Status')!.value).toContain(`Resolved by <@${WATCHER}> <t:`)
    expect(edit.components).toEqual([])
    expect(h.ops.findOpen('watch:feed:CVE-2026-0001')).toBeUndefined()
    // A module close of a resolved card has nothing to do.
    await h.w.cards.close('feed:CVE-2026-0001', 'Fixed.')
    expect(h.discord.edits).toHaveLength(0)

    // The module sends it again (the problem is still there): a new card, a new message.
    await h.w.cards.upsert(card())
    expect(titles(h.discord.sent)).toEqual(['alerts: Warning: A new advisory', 'alerts: Warning: A new advisory'])
    const again = h.ops.findOpen('watch:feed:CVE-2026-0001')!
    expect(again.id).not.toBe(first.id)
    expect(h.store.state.opsCards[first.id].closedBy).toBe(WATCHER)
  })

  it('reportFixed marks an open card and leaves it open for Resolve; the next upsert takes the mark off', async () => {
    const h = await host()
    const id = 'container:example/app:1.0.0'
    const key = `watch:${id}`
    const board = () => dashboardEmbed(h.store.state, { nextRunAt: null, running: false, repoScanning: false }).fields!.find((f) => f.name === 'Watch')!.value
    const status = () => h.discord.edits.at(-1)!.payload.embeds[0].fields!.find((f) => f.name === 'Status')?.value
    // Nothing open: nothing to mark, and no card is posted.
    await h.w.cards.reportFixed(id, 'The box now reports that 1 container runs the fixed packages.')
    expect(h.discord.sent).toHaveLength(0)

    await h.w.cards.upsert(card({ id }))
    await h.w.cards.reportFixed(id, 'The box now reports that 1 container runs the fixed packages.')
    const open = h.ops.findOpen(key)!
    expect(open).toMatchObject({ reportedFixedNote: 'The box now reports that 1 container runs the fixed packages.' })
    expect(open.closedAt).toBeUndefined()
    expect(h.discord.edits.at(-1)!.payload.embeds[0].title).toBe('Warning: A new advisory')
    expect(status()).toMatch(/^The box now reports that 1 container runs the fixed packages\. Reported <t:\d+:R>\. Press Resolve once you have checked it\.$/)
    expect(h.discord.edits.at(-1)!.payload.components![0].components.map((c) => ('label' in c ? c.label : ''))).toEqual(['Acknowledge', 'Resolve'])
    expect(board()).toBe('1 open card. 1 is reported fixed and waits for Resolve.')
    expect(buildStateView(h.store.state, { now: new Date(), discordReady: true, repoScanning: false }).cards[0]).toMatchObject({ kind: 'watch', reportedFixed: true })
    // The same mark again edits nothing.
    const edits = h.discord.edits.length
    await h.w.cards.reportFixed(id, 'The box now reports that 1 container runs the fixed packages.')
    expect(h.discord.edits).toHaveLength(edits)
    await expect(h.w.cards.reportFixed('has space', 'x')).rejects.toThrow(TypeError)

    // The module sends the problem again: the mark goes, on the same card.
    await h.w.cards.upsert(card({ id }))
    expect(h.ops.findOpen(key)).toMatchObject({ id: open.id, reportedFixedAt: undefined, reportedFixedNote: undefined })
    expect(status()).toBeUndefined()
    expect(board()).toBe('1 open card')

    // Marked again, then Resolve closes it.
    await h.w.cards.reportFixed(id, 'The box now reports that 1 container is gone.')
    expect((await h.ops.press('resolve', open.id, WATCHER)).ok).toBe(true)
    expect(h.ops.findOpen(key)).toBeUndefined()
    expect(h.discord.sent).toHaveLength(1)
  })

  it('watch cards show in the state view', async () => {
    const h = await host()
    await h.w.cards.upsert(card({ severity: 'critical' }))
    const view = buildStateView(h.store.state, { now: new Date(), discordReady: true, repoScanning: false })
    expect(view.cards).toEqual([expect.objectContaining({ kind: 'watch', severity: 'critical', title: 'A new advisory', source: null })])
  })
})

describe('when the open watch cards are full', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('a critical card still opens past the cap, up to the reserve', async () => {
    const h = await host()
    fillWatchCards(h.store.state.opsCards, new Date().toISOString())
    await expect(h.w.cards.upsert(card())).rejects.toBeInstanceOf(WatchCardsFullError)
    await h.w.cards.upsert(card({ id: 'kev:CVE-2026-0003', severity: 'critical' }))
    expect(h.discord.sent).toHaveLength(1)
    for (let i = 1; i < WATCH_CRITICAL_RESERVE; i++) await h.w.cards.upsert(card({ id: `kev:CVE-2026-1${String(i).padStart(3, '0')}`, severity: 'critical' }))
    await expect(h.w.cards.upsert(card({ id: 'kev:CVE-2026-9999', severity: 'critical' }))).rejects.toThrow(
      `Too many open watch cards (${MAX_OPEN_WATCH_CARDS + WATCH_CRITICAL_RESERVE}). Resolve some first.`,
    )
  })

  it('the refusal shows on the status board and in the state view, and goes once a person resolves a card', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const t0 = Date.parse('2025-03-29T10:00:00Z')
    vi.setSystemTime(t0)
    const h = await host()
    fillWatchCards(h.store.state.opsCards, new Date(t0).toISOString())
    const board = () => dashboardEmbed(h.store.state, { nextRunAt: null, running: false, repoScanning: false })
    const view = () => buildStateView(h.store.state, { now: new Date(), discordReady: true, repoScanning: false }).watch
    expect(board().fields!.find((f) => f.name === 'Watch')!.value).toBe('300 open cards')
    expect(view()).toEqual({ open: 300, max: 300, refusedSince: null, lastRefusedAt: null })

    // Refused: the module treats the throw as not sent and tries again on its next run.
    await expect(h.w.cards.upsert(card())).rejects.toBeInstanceOf(WatchCardsFullError)
    expect(h.discord.sent).toHaveLength(0)
    const since = new Date(t0).toISOString()
    expect(h.store.state.watchCardsFull).toEqual({ since, lastAt: since })
    // Saved, so a restart keeps showing it.
    expect((await Store.open(h.dir, 60)).state.watchCardsFull).toEqual({ since, lastAt: since })

    vi.setSystemTime(t0 + 3_600_000)
    await expect(h.w.cards.upsert(card({ id: 'feed:CVE-2026-0002' }))).rejects.toThrow('Too many open watch cards (300). Resolve some first.')
    const later = new Date(t0 + 3_600_000).toISOString()
    expect(h.store.state.watchCardsFull).toEqual({ since, lastAt: later })

    // One of them the boxes report fixed: the notice counts it.
    h.store.state.opsCards.w1.reportedFixedAt = since
    const b = board()
    expect(b.fields!.find((f) => f.name === 'Watch cards are full')!.value).toBe(
      `New watch cards are refused since <t:${t0 / 1000}:R> (the latest <t:${t0 / 1000 + 3600}:R>): 300 are open and 300 is the most. ` +
        '1 is reported fixed and waits for Resolve. ' +
        'Resolve the watch cards you have handled to make room (`/nethersec alerts kind:watch` lists them). The refused ones are tried again on the next hourly run.',
    )
    expect(b.fields!.some((f) => f.name === 'Watch')).toBe(false)
    expect(b.color).toBe(COLORS.high)
    expect(view()).toEqual({ open: 300, max: 300, refusedSince: since, lastRefusedAt: later })

    // A person resolves one: there is room again, and the notice goes.
    expect((await h.ops.press('resolve', 'w0', WATCHER)).ok).toBe(true)
    expect(h.store.state.watchCardsFull).toBeNull()
    expect(board().fields!.find((f) => f.name === 'Watch')!.value).toBe('299 open cards. 1 is reported fixed and waits for Resolve.')
    expect(view()).toEqual({ open: 299, max: 300, refusedSince: null, lastRefusedAt: null })
    // The module's next try gets its card out.
    await h.w.cards.upsert(card())
    expect(titles(h.discord.sent)).toEqual(['alerts: Warning: A new advisory'])
  })
})

describe('container package lists for the watch modules', () => {
  it('lists the stored records as copies', async () => {
    const h = await host()
    const key = (await h.reports.authenticate(auth('db1')))!
    await h.reports.handle(key, JSON.stringify({ kind: 'security', source: 'db1', event: 'container-packages', detail: 'v=1 ctr=web img=nginx:1.27 os=alpine osver=3.20.3 pm=apk pkgs=openssl@3.3.2-r0' }))
    const list = h.w.listContainerPackages()
    expect(list).toEqual([
      {
        box: 'db1', container: 'web', image: 'nginx:1.27', imageId: null, builtAt: null, os: 'alpine', osVersion: '3.20.3', pm: 'apk',
        packages: [{ name: 'openssl', version: '3.3.2-r0' }], more: 0, receivedAt: expect.any(Number),
      },
    ])
    list[0].packages.length = 0
    expect(h.w.listContainerPackages()[0].packages).toHaveLength(1)
  })
})

describe('module state', () => {
  it('saves and loads a copy, and refuses state over the cap', async () => {
    const h = await host()
    expect(h.w.loadModuleState('feeds')).toBeUndefined()
    await h.w.saveModuleState('feeds', { seen: ['a'] })
    const loaded = h.w.loadModuleState('feeds') as { seen: string[] }
    expect(loaded).toEqual({ seen: ['a'] })
    loaded.seen.push('b')
    expect(h.w.loadModuleState('feeds')).toEqual({ seen: ['a'] })
    await expect(h.w.saveModuleState('feeds', 'x'.repeat(MAX_MODULE_STATE_BYTES))).rejects.toThrow(RangeError)
    await expect(h.w.saveModuleState('Bad Name', 1)).rejects.toThrow(TypeError)
    await expect(h.w.saveModuleState('feeds', { n: 1n })).rejects.toThrow(TypeError)
    expect(h.w.loadModuleState('feeds')).toEqual({ seen: ['a'] })
  })
})

describe('hourly jobs', () => {
  it('runs a job a minute after start and then hourly; an error is logged and never thrown', async () => {
    const h = await host()
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    let runs = 0
    h.w.registerHourlyJob('feeds', async () => {
      runs++
      throw new Error('feed down')
    })
    expect(() => h.w.registerHourlyJob('feeds', async () => {})).toThrow('already registered')
    expect(() => h.w.registerHourlyJob('Bad', async () => {})).toThrow(TypeError)
    h.jobs.start()
    expect(h.timers[0].ms).toBe(60_000)
    h.timers[0].fn()
    await h.jobs.whenIdle(1_000)
    await new Promise((r) => setTimeout(r, 0))
    expect(runs).toBe(1)
    expect(h.logs).toContain('Job feeds failed: Error')
    expect(h.timers[1].ms).toBe(3_600_000)
    errors.mockRestore()
  })

  it('skips a job while the hub is not set up, and never runs one twice at once', async () => {
    const h = await host({ setup: false })
    let runs = 0
    let release!: () => void
    h.w.registerHourlyJob('slow', async () => {
      runs++
      await new Promise<void>((r) => (release = r))
    })
    await h.jobs.runNow('slow')
    expect(runs).toBe(0)
    expect(h.logs).toContain('Job slow waits until the hub is set up.')
    h.store.state.setup = { categoryId: 'c', criticalChannelId: 'crit', alertsChannelId: 'alerts', statusChannelId: 'status', roleId: '42', private: true }
    const first = h.jobs.runNow('slow')
    const second = h.jobs.runNow('slow')
    await new Promise((r) => setTimeout(r, 0))
    expect(runs).toBe(1)
    expect(await h.jobs.whenIdle(10)).toBe(false)
    release()
    await Promise.all([first, second])
    expect(await h.jobs.whenIdle(10)).toBe(true)
  })
})
