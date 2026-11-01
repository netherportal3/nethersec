import { afterEach, describe, expect, it, vi } from 'vitest'
import { MAX_AUTO_CLOSE_PER_RUN } from '../src/cards/ops.js'
import { HourlyJobs, MAX_MODULE_STATE_BYTES, MAX_MODULE_TOTAL_BYTES, saveModuleState } from '../src/jobs.js'
import { buildStateView } from '../src/stateView.js'
import { defaultWatchConfig, WatchConfigError, type WatchConfig } from '../src/watch/index.js'
import { createWatchHost, type WatchHost } from '../src/watchHost.js'
import { ADVISORY_JOB, CONTAINER_JOB, registerWatchJobs, WATCH_CONFIG_CARD_ID } from '../src/watchJobs.js'
import { makeHub } from './hubHelpers.js'

async function setup(readConfig: (file: string) => WatchConfig) {
  const h = await makeHub()
  const jobs = new HourlyJobs({ isSetUp: () => true, log: () => {}, setTimer: () => 0 as unknown as NodeJS.Timeout, clearTimer: () => {} })
  const w = createWatchHost({ ops: h.ops, store: h.store, jobs, log: (m) => h.logs.push(m) })
  const runs = new Map<string, () => Promise<void>>()
  const listContainerPackages = vi.fn(w.listContainerPackages)
  const host: WatchHost = {
    ...w,
    listContainerPackages,
    registerHourlyJob: (name, run) => {
      runs.set(name, run)
      w.registerHourlyJob(name, run)
    },
  }
  const fetch = vi.fn(async () => {
    throw new Error('no network in tests')
  }) as unknown as typeof globalThis.fetch
  registerWatchJobs(host, { dataDir: '/no/such/dir', fetch, readConfig })
  const openWatchCards = () =>
    buildStateView(h.store.state, { now: new Date(), discordReady: true, repoScanning: false }).cards.filter((c) => c.kind === 'watch')
  return { h, runs, fetch, listContainerPackages, openWatchCards }
}

describe('watch jobs', () => {
  it('registers the advisory watch and the container check', async () => {
    const t = await setup(() => defaultWatchConfig())
    expect([...t.runs.keys()]).toEqual([ADVISORY_JOB, CONTAINER_JOB])
  })

  it('a watch.json that cannot be used opens one card, runs nothing, and the card closes once it reads cleanly', async () => {
    let broken = true
    const t = await setup(() => {
      if (broken) throw new WatchConfigError(['components[0].id: required'])
      return defaultWatchConfig()
    })
    await t.runs.get(ADVISORY_JOB)!()
    await t.runs.get(CONTAINER_JOB)!()
    const open = t.openWatchCards()
    expect(open).toHaveLength(1)
    expect(open[0]).toEqual(expect.objectContaining({ severity: 'warning', title: expect.stringContaining('watch.json has a problem') }))
    expect(t.fetch).not.toHaveBeenCalled()
    expect(t.listContainerPackages).not.toHaveBeenCalled()
    expect(t.h.logs.some((l) => l.includes('components[0].id: required'))).toBe(true)

    // A person resolves it while the file is still wrong: the next run opens it again.
    expect((await t.h.ops.press('resolve', open[0].id, '6'.repeat(18))).ok).toBe(true)
    expect(t.openWatchCards()).toHaveLength(0)
    await t.runs.get(ADVISORY_JOB)!()
    expect(t.openWatchCards()).toEqual([expect.objectContaining({ title: expect.stringContaining('watch.json has a problem') })])
    expect(t.openWatchCards()[0].id).not.toBe(open[0].id)
    expect(t.openWatchCards()[0].detail).toContain('If you resolve this card before that, it opens again on the next run.')

    broken = false
    await t.runs.get(ADVISORY_JOB)!()
    expect(t.openWatchCards()).toHaveLength(0)
    expect(t.h.store.state).toBeDefined()
    expect(WATCH_CONFIG_CARD_ID).toBe('watch-config')
  })

  it('the container check stays off when watch.json turns it off', async () => {
    const t = await setup(() => ({ ...defaultWatchConfig(), containers: { enabled: false } }))
    await t.runs.get(CONTAINER_JOB)!()
    expect(t.listContainerPackages).not.toHaveBeenCalled()
  })

  it('the container check reads the stored package lists when on', async () => {
    const t = await setup(() => defaultWatchConfig())
    await t.runs.get(CONTAINER_JOB)!()
    expect(t.listContainerPackages).toHaveBeenCalled()
  })
})

describe('acknowledged advisory cards', () => {
  const DAY = 86_400_000
  const WATCHER = '6'.repeat(18)
  afterEach(() => {
    vi.useRealTimers()
  })

  async function withCards(days: () => number) {
    vi.useFakeTimers({ toFake: ['Date'] })
    const t0 = Date.parse('2026-06-01T00:00:00Z')
    vi.setSystemTime(t0)
    const t = await setup(() => ({ ...defaultWatchConfig(), advisoryCards: { closeAcknowledgedAfterDays: days() } }))
    const up = (id: string) => t.h.ops.upsert({ id, severity: 'warning', ping: false, title: `Card ${id}`, body: 'b' })
    const ack = async (id: string) => expect((await t.h.ops.press('ack', t.h.ops.findOpen(`watch:${id}`)!.id, WATCHER)).ok).toBe(true)
    const openIds = () => t.h.ops.openCards().map((c) => c.key.slice('watch:'.length)).sort()
    return { ...t, t0, up, ack, openIds }
  }

  it('close by themselves after advisoryCards.closeAcknowledgedAfterDays; others stay open', async () => {
    const t = await withCards(() => 90)
    const advisory = 'advisory:engine:GHSA-aaaa-aaaa-aaaa'
    const kev = 'advisory:kev:CVE-2026-0001'
    const unacked = 'advisory:engine:GHSA-bbbb-bbbb-bbbb'
    const kernel = 'advisory:linux-kernel:CVE-2026-50001'
    const ctr = 'container:example/app:1.0.0'
    const unreadable = 'advisory-unreadable:engine'
    for (const id of [advisory, kev, unacked, kernel, ctr, unreadable]) await t.up(id)
    for (const id of [advisory, kev, kernel, ctr, unreadable]) await t.ack(id)
    // A container card the box reports fixed waits for a person, acknowledged or not.
    await t.h.ops.reportFixed(ctr, 'The box now reports that 1 container runs the fixed packages.')
    const all = [advisory, kev, unacked, kernel, ctr, unreadable].sort()

    vi.setSystemTime(t.t0 + 89 * DAY)
    await t.runs.get(ADVISORY_JOB)!()
    expect(t.openIds()).toEqual(all)

    vi.setSystemTime(t.t0 + 90 * DAY)
    const edits = t.h.discord.edits.length
    await t.runs.get(ADVISORY_JOB)!()
    expect(t.openIds()).toEqual([unacked, kernel, ctr, unreadable].sort())
    expect(t.h.discord.edits).toHaveLength(edits + 2)
    const closed = t.h.discord.edits.at(-1)!.payload.embeds[0]
    expect(closed.title).toMatch(/^Closed: Card advisory:/)
    const status = closed.fields!.find((f) => f.name === 'Status')!.value
    expect(status).toContain('Closed by itself: acknowledged at least 90 days ago (advisoryCards in watch.json). The watch never checked whether the fix is installed.')
    expect(status).toContain(`Acknowledged by <@${WATCHER}>`)
    expect(t.h.logs).toContain('Closed 2 advisory cards acknowledged at least 90 days ago.')
  })

  it('0 turns it off', async () => {
    const t = await withCards(() => 0)
    await t.up('advisory:engine:GHSA-aaaa-aaaa-aaaa')
    await t.ack('advisory:engine:GHSA-aaaa-aaaa-aaaa')
    vi.setSystemTime(t.t0 + 3650 * DAY)
    await t.runs.get(ADVISORY_JOB)!()
    expect(t.openIds()).toEqual(['advisory:engine:GHSA-aaaa-aaaa-aaaa'])
  })

  it(`closes at most ${MAX_AUTO_CLOSE_PER_RUN} a run, the oldest acknowledgment first`, async () => {
    const t = await withCards(() => 30)
    const ids = Array.from({ length: MAX_AUTO_CLOSE_PER_RUN + 3 }, (_, i) => `advisory:engine:GHSA-${String(i).padStart(4, '0')}-aaaa-aaaa`)
    for (const id of ids) await t.up(id)
    // Acknowledged an hour apart, the last one first.
    for (const [i, id] of [...ids].reverse().entries()) {
      vi.setSystemTime(t.t0 + i * 3_600_000)
      await t.ack(id)
    }
    vi.setSystemTime(t.t0 + 40 * DAY)
    await t.runs.get(ADVISORY_JOB)!()
    expect(t.openIds()).toEqual(ids.slice(0, 3))
    await t.runs.get(ADVISORY_JOB)!()
    expect(t.openIds()).toEqual([])
  })
})

describe('module state caps', () => {
  it('refuses a save that would take all module state over the total cap', async () => {
    const { store } = await makeHub()
    const chunk = 'x'.repeat(MAX_MODULE_STATE_BYTES - 16)
    const fits = Math.floor(MAX_MODULE_TOTAL_BYTES / MAX_MODULE_STATE_BYTES)
    for (let i = 0; i < fits; i++) store.state.modules[`m${i}`] = chunk
    await expect(saveModuleState(store, 'one-more', chunk)).rejects.toThrow(RangeError)
    // Replacing an existing module counts its old size out.
    await expect(saveModuleState(store, 'm0', 'small')).resolves.toBeUndefined()
  })

  it('takes module names up to 64 characters', async () => {
    const { store } = await makeHub()
    await expect(saveModuleState(store, `watch-advisories-${'a'.repeat(40)}`, { ok: 1 })).resolves.toBeUndefined()
    await expect(saveModuleState(store, 'a'.repeat(65), {})).rejects.toThrow(TypeError)
  })
})
