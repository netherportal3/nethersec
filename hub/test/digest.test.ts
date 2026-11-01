import { afterEach, describe, expect, it, vi } from 'vitest'
import { rebootDigestMessage, rebootLines } from '../src/cards/render.js'
import { RebootDigest, inDigestWindow, isoWeekKey } from '../src/digest.js'
import type { RebootPendingRecord } from '../src/state.js'
import { makeHub } from './hubHelpers.js'

const DAY = 864e5

function rec(source: string, over: Partial<RebootPendingRecord> = {}): RebootPendingRecord {
  return { source, since: null, checked: true, livepatch: null, pkgs: [], more: 0, covered: 0, uncovered: 0, receivedAt: Date.now(), ...over }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('ISO weeks and the Monday window', () => {
  it('names weeks the ISO way, across a year boundary', () => {
    expect(isoWeekKey(Date.parse('2025-03-24T12:00:00Z'))).toBe('2025-W13')
    expect(isoWeekKey(Date.parse('2026-01-01T00:00:00Z'))).toBe('2026-W01')
    expect(isoWeekKey(Date.parse('2027-01-01T00:00:00Z'))).toBe('2026-W53')
  })
  it('opens on Monday at 09:00 UTC', () => {
    expect(inDigestWindow(Date.parse('2025-03-24T08:59:00Z'))).toBe(false)
    expect(inDigestWindow(Date.parse('2025-03-24T09:00:00Z'))).toBe(true)
    expect(inDigestWindow(Date.parse('2025-03-25T10:00:00Z'))).toBe(false)
  })
})

describe('the weekly pending-reboot summary', () => {
  it('posts once per week on Monday from 09:00 UTC, oldest box first', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2025-03-24T08:30:00Z'))
    const h = await makeHub()
    const now = Date.now()
    h.store.state.rebootPending = {
      web1: rec('web1', { since: now - 3 * DAY, receivedAt: now - 3_600_000, uncovered: 2, covered: 1, livepatch: true, pkgs: ['linux-image-generic'], more: 2 }),
      db1: rec('db1', { since: now - 41 * DAY, receivedAt: now - 3_600_000 }),
      ci1: rec('ci1', { since: now - 10 * DAY, receivedAt: now - 3_600_000, checked: false, covered: null, uncovered: null }),
      old1: rec('old1', { since: now - 20 * DAY, receivedAt: now - 3 * DAY }),
    }
    const digest = new RebootDigest({ store: h.store, port: h.discord.port })
    expect(await digest.check()).toBe('outside')

    vi.setSystemTime(new Date('2025-03-24T09:05:00Z'))
    expect(await digest.check()).toBe('posted')
    expect(h.discord.sent).toHaveLength(1)
    const msg = h.discord.sent[0]
    expect(msg.channelId).toBe('status')
    expect(msg.payload.allowedMentions).toEqual({ parse: [] })
    expect(msg.payload.embeds[0].title).toBe('Pending reboots (4)')
    expect(msg.payload.embeds[0].description!.split('\n')).toEqual([
      '**db1**: pending for 41 days. Nothing High or Critical waits for it.',
      '**old1**: pending for 20 days. No report for 3 days, so this may be out of date.',
      '**ci1**: pending for 10 days. Not checked (the CVE lookup did not finish).',
      '**web1**: pending for 3 days. 2 High or Critical CVEs wait for the reboot. Livepatch is on. Staged: linux-image-generic and 2 more.',
    ])
    expect(h.store.state.rebootDigestWeek).toBe('2025-W13')

    // Later the same Monday, and after a restart (the week is saved): nothing more.
    vi.setSystemTime(new Date('2025-03-24T15:00:00Z'))
    expect(await digest.check()).toBe('done')
    const again = new RebootDigest({ store: h.store, port: h.discord.port })
    expect(await again.check()).toBe('done')
    expect(h.discord.sent).toHaveLength(1)

    // The next Monday posts again.
    vi.setSystemTime(new Date('2025-03-31T09:00:00Z'))
    expect(await digest.check()).toBe('posted')
    expect(h.discord.sent).toHaveLength(2)
  })

  it('tries again at the next check when the post fails, and posts nothing for an empty week', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2025-03-24T10:00:00Z'))
    const h = await makeHub()
    const digest = new RebootDigest({ store: h.store, port: h.discord.port })
    expect(await digest.check()).toBe('empty')
    h.store.state.rebootPending = { web1: rec('web1') }
    h.discord.fail.send = true
    expect(await digest.check()).toBe('failed')
    expect(h.store.state.rebootDigestWeek).toBeNull()
    h.discord.fail.send = false
    expect(await digest.check()).toBe('posted')
  })

  it('drops boxes with no report for 30 days', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2025-03-25T10:00:00Z'))
    const h = await makeHub()
    h.store.state.rebootPending = { web1: rec('web1', { receivedAt: Date.now() - 31 * DAY }), db1: rec('db1') }
    await new RebootDigest({ store: h.store, port: h.discord.port }).check()
    expect(Object.keys(h.store.state.rebootPending)).toEqual(['db1'])
  })

  it('has no summary without a pending reboot', () => {
    expect(rebootDigestMessage([], Date.now())).toBeNull()
    expect(rebootLines([rec('web1', { since: Date.now() - 2 * 3_600_000 })], Date.now())[0]).toContain('pending for under a day')
  })
})
