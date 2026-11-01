import { describe, expect, it } from 'vitest'
import { INFO_NOTE_REPEAT_MS, MAX_OPEN_HOST_CARDS, MAX_OPEN_HOST_CARDS_PER_SOURCE } from '../src/cards/ops.js'
import { dashboardEmbed } from '../src/discord/cards.js'
import { OPS_ACK_PREFIX, OPS_MUTE_PREFIX, OPS_RESOLVE_PREFIX } from '../src/cards/render.js'
import { CONTAINERS_MAX_PER_BOX, CONTAINER_MAX_PKGS } from '../src/reports/data.js'
import { LIMITS, RateLimiter, windowsFor } from '../src/reports/ratelimit.js'
import type { Key } from '../src/reports/keys.js'
import type { Report } from '../src/reports/protocol.js'
import { DM_USER, auth, fakeKey, keyLineFor, makeHub, titles } from './hubHelpers.js'

const KEYS = [keyLineFor('web1', 'web1', 'page'), keyLineFor('db1', 'db1'), keyLineFor('pc1', 'pc1', `dm=${DM_USER}`)]

async function hub(opts: { setup?: boolean; now?: () => number; keys?: string[] } = {}) {
  const h = await makeHub({ keys: KEYS, ...opts })
  /** Send one report as `seed`'s key; the whole HTTP layer minus the socket. */
  const send = async (seed: string, body: Record<string, unknown>) => {
    const key = (await h.reports.authenticate(auth(seed))) as Key
    expect(key).not.toBeNull()
    return h.reports.handle(key, JSON.stringify(body))
  }
  const open = () => Object.values(h.store.state.opsCards).filter((c) => !c.closedAt)
  return { ...h, send, open }
}

const sec = (over: Record<string, unknown> = {}) => ({ kind: 'security', source: 'web1', event: 'ssh-auth-burst', title: 'SSH login burst', detail: 'Many failed logins', ...over })

describe('host cards', () => {
  it('a critical report from a page key posts a card in the critical channel and pings the role', async () => {
    const h = await hub()
    const r = await h.send('web1', sec({ severity: 'critical' }))
    expect(r).toEqual({ status: 202, body: { accepted: true, result: 'posted' } })
    expect(titles(h.discord.sent)).toEqual(['crit: Critical: SSH login burst (web1)'])
    const p = h.discord.sent[0].payload
    expect(p.content).toBe('<@&42>')
    expect(p.allowedMentions).toEqual({ parse: [], roles: ['42'] })
    const ids = p.components![0].components.map((c) => ('custom_id' in c ? c.custom_id : ''))
    const card = h.open()[0]
    expect(ids).toEqual([OPS_ACK_PREFIX + card.id, OPS_MUTE_PREFIX + card.id, OPS_RESOLVE_PREFIX + card.id])
    expect(h.store.state.hosts.web1).toMatchObject({ source: 'web1', reports: 1 })
  })

  it('a critical report without page is posted in the critical channel but pings nobody', async () => {
    const h = await hub()
    await h.send('db1', sec({ source: 'db1', severity: 'critical' }))
    expect(titles(h.discord.sent)).toEqual(['crit: Critical: SSH login burst (db1)'])
    expect(h.discord.sent[0].payload.content).toBeUndefined()
    expect(h.discord.sent[0].payload.allowedMentions).toEqual({ parse: [] })
  })

  it('the ping role setting turns every ping off', async () => {
    const h = await hub()
    h.store.state.settings.pingRole = false
    await h.send('web1', sec({ severity: 'critical' }))
    expect(h.discord.sent[0].payload.content).toBeUndefined()
  })

  it('warning goes to the alerts channel, info to the status channel as a note with no card', async () => {
    const h = await hub()
    await h.send('web1', sec())
    expect((await h.send('web1', sec({ event: 'kernel', severity: 'info', title: 'Kernel update staged' }))).body.result).toBe('noted')
    expect(titles(h.discord.sent)).toEqual(['alerts: Warning: SSH login burst (web1)', 'status: Info: Kernel update staged (web1)'])
    expect(h.open()).toHaveLength(1)
    expect(h.discord.sent.every((s) => !s.payload.content)).toBe(true)
  })

  it('an uptime report defaults to critical, and its resolve closes the card', async () => {
    const h = await hub()
    await h.send('db1', { kind: 'uptime', source: 'db1', event: 'disk', title: 'Disk full' })
    expect(titles(h.discord.sent)).toEqual(['crit: Critical: Disk full (db1)'])
    const r = await h.send('db1', { kind: 'uptime', source: 'db1', event: 'disk', state: 'resolved' })
    expect(r.body.result).toBe('closed')
    expect(h.open()).toHaveLength(0)
    const edit = h.discord.edits.at(-1)!.payload.embeds[0]
    expect(edit.title).toBe('Resolved: Disk full (db1)')
    expect(edit.fields!.find((f) => f.name === 'Status')!.value).toMatch(/^Back up <t:\d+:R>\.$/)
    expect(h.discord.edits.at(-1)!.payload.components).toEqual([])
    // A second resolve has nothing to close.
    expect((await h.send('db1', { kind: 'uptime', source: 'db1', event: 'disk', state: 'resolved' })).body.result).toBe('nothing-open')
  })

  it('a resolved security report keeps the card open until a person presses Resolve', async () => {
    const h = await hub()
    await h.send('web1', sec())
    const r = await h.send('web1', sec({ state: 'resolved' }))
    expect(r.body.result).toBe('reported-fixed')
    const card = h.open()[0]
    expect(card.reportedFixedAt).toBeDefined()
    const embed = h.discord.edits.at(-1)!.payload.embeds[0]
    expect(embed.fields!.find((f) => f.name === 'Status')!.value).toContain('The box reports this is fixed')
    const labels = h.discord.edits.at(-1)!.payload.components![0].components.map((c) => ('label' in c ? c.label : ''))
    expect(labels).toContain('Resolve')
    // Repeating the resolve changes nothing.
    expect((await h.send('web1', sec({ state: 'resolved' }))).body.result).toBe('unchanged')

    const pressed = await h.ops.press('resolve', card.id, '7'.repeat(18))
    expect(pressed.ok).toBe(true)
    expect(h.open()).toHaveLength(0)
    expect(h.store.state.opsCards[card.id]).toMatchObject({ closedBy: '7'.repeat(18) })
    // Closed: a new trigger opens a new card.
    await h.send('web1', sec())
    expect(h.open()).toHaveLength(1)
    expect(h.open()[0].id).not.toBe(card.id)
  })

  it('a repeat trigger edits in place, an unchanged one edits nothing', async () => {
    const h = await hub()
    await h.send('db1', sec({ source: 'db1' }))
    expect((await h.send('db1', sec({ source: 'db1' }))).body.result).toBe('unchanged')
    expect(h.discord.edits).toHaveLength(0)
    expect((await h.send('db1', sec({ source: 'db1', detail: 'Even more failed logins' }))).body.result).toBe('edited')
    expect(h.discord.sent).toHaveLength(1)
    expect(h.discord.edits).toHaveLength(1)
    expect(h.discord.edits[0].payload.embeds[0].description).toBe('Even more failed logins')
    expect(h.discord.edits[0].payload.content).toBeUndefined()
  })

  it('a card that rises to critical pings once with a page key, and not at all without one', async () => {
    const h = await hub()
    await h.send('web1', sec())
    await h.send('web1', sec({ severity: 'critical' }))
    expect(titles(h.discord.sent)).toEqual(['alerts: Warning: SSH login burst (web1)', 'crit: Now critical: SSH login burst (web1)'])
    const note = h.discord.sent[1].payload
    expect(note.content).toBe('<@&42>')
    expect(note.embeds[0].description).toMatch(/^\[Open the card\]\(https:\/\/discord\.com\/channels\/\d+\/alerts\/m1\)$/)
    // Still critical, new detail: an edit, no new ping.
    await h.send('web1', sec({ severity: 'critical', detail: 'more' }))
    expect(h.discord.sent).toHaveLength(2)

    await h.send('db1', sec({ source: 'db1' }))
    await h.send('db1', sec({ source: 'db1', severity: 'critical' }))
    const quiet = h.discord.sent.at(-1)!.payload
    expect(quiet.embeds[0].title).toBe('Now critical: SSH login burst (db1)')
    expect(quiet.content).toBeUndefined()
  })

  it('a card whose message was deleted is posted again on its next change', async () => {
    const h = await hub()
    await h.send('db1', sec({ source: 'db1' }))
    h.discord.messages.delete('m1')
    await h.send('db1', sec({ source: 'db1', detail: 'changed' }))
    expect(titles(h.discord.sent)).toEqual(['alerts: Warning: SSH login burst (db1)', 'alerts: Warning: SSH login burst (db1)'])
    expect(h.open()[0].messageId).toBe('m2')
  })

  it('nothing a box sends can mention anyone or format the card', async () => {
    const h = await hub()
    const hostile = '<@123456789012345678> <@&42> @everyone **bold** [click](https://evil.example) `code`'
    await h.send('db1', sec({ source: 'db1', severity: 'critical', title: '@here **x**', detail: hostile, group: '<@&42>' }))
    const p = h.discord.sent[0].payload
    expect(p.content).toBeUndefined()
    expect(p.allowedMentions).toEqual({ parse: [] })
    const d = p.embeds[0].description!
    expect(d).not.toMatch(/(^|[^\\])<@/)
    expect(d).not.toMatch(/(^|[^\\])@everyone/)
    expect(d).not.toContain('**bold**')
    expect(d).toContain('\\[click\\]')
    expect(p.embeds[0].fields![0].value).toContain('\\<\\@&42>')
  })

  it('a muted check opens no new card and never pings', async () => {
    const h = await hub()
    await h.send('web1', sec())
    const card = h.open()[0]
    expect((await h.ops.press('mute', card.id, '7'.repeat(18))).ok).toBe(true)
    await h.send('web1', sec({ severity: 'critical' }))
    expect(h.discord.sent.filter((s) => s.payload.content)).toHaveLength(0)
    await h.ops.press('resolve', card.id, '7'.repeat(18))
    expect((await h.send('web1', sec({ severity: 'critical', detail: 'new' }))).body.result).toBe('muted')
    expect(h.open()).toHaveLength(0)
    expect(await h.ops.unmute('security', 'web1', 'ssh-auth-burst')).toBe(true)
    expect((await h.send('web1', sec({ severity: 'critical', detail: 'again' }))).body.result).toBe('posted')
  })

  it('acknowledge records who and drops its button', async () => {
    const h = await hub()
    await h.send('web1', sec())
    const id = h.open()[0].id
    const r = await h.ops.press('ack', id, '7'.repeat(18))
    expect(r.ok && r.card.ackedBy).toBe('7'.repeat(18))
    expect((await h.ops.press('ack', id, '8'.repeat(18))).ok).toBe(false)
    expect((await h.ops.press('ack', 'nope', '8'.repeat(18))).ok).toBe(false)
  })

  it('stops opening host cards at the cap', async () => {
    const h = await hub()
    const now = new Date().toISOString()
    for (let i = 0; i < MAX_OPEN_HOST_CARDS; i++) {
      h.store.state.opsCards[`c${i}`] = {
        id: `c${i}`, key: `security:db1:e${i}`, kind: 'security', source: 'db1', event: `e${i}`, severity: 'warning',
        title: '', body: '', channelId: 'alerts', messageId: `x${i}`, createdAt: now, updatedAt: now, contentHash: 'h',
      }
    }
    const r = await h.send('web1', sec())
    expect(r.status).toBe(429)
    expect(h.discord.sent).toHaveLength(0)
  })

  it('one source cannot fill the open host cards for every box', async () => {
    const h = await hub()
    const now = new Date().toISOString()
    for (let i = 0; i < MAX_OPEN_HOST_CARDS_PER_SOURCE; i++) {
      h.store.state.opsCards[`c${i}`] = {
        id: `c${i}`, key: `security:web1:e${i}`, kind: 'security', source: 'web1', event: `e${i}`, severity: 'warning',
        title: '', body: '', channelId: 'alerts', messageId: `x${i}`, createdAt: now, updatedAt: now, contentHash: 'h',
      }
    }
    const r = await h.send('web1', sec({ event: 'one-more' }))
    expect(r).toEqual({ status: 429, body: { error: 'Too many open alerts for this source. Resolve some first.' }, retryAfterSec: 3600 })
    expect(h.discord.sent).toHaveLength(0)
    // Another box still gets its card, and the source's open cards are still edited.
    expect((await h.send('db1', sec({ source: 'db1' }))).body.result).toBe('posted')
    expect((await h.send('web1', sec({ event: 'e0', detail: 'changed' }))).body.result).toBe('edited')
    // A person resolves one: there is room again.
    expect((await h.ops.press('resolve', 'c1', '7'.repeat(18))).ok).toBe(true)
    expect((await h.send('web1', sec({ event: 'one-more' }))).body.result).toBe('posted')
  })

  it('an info note the same as one posted in the last hour is not posted again', async () => {
    let now = Date.parse('2025-03-03T10:00:00Z')
    const h = await hub({ now: () => now })
    const info = sec({ event: 'security-updates-applied', severity: 'info', title: 'Updates applied', detail: 'openssl' })
    expect((await h.send('web1', info)).body.result).toBe('noted')
    expect(await h.send('web1', info)).toEqual({ status: 202, body: { accepted: true, result: 'already-noted' } })
    expect(h.discord.sent).toHaveLength(1)
    // Another note, or the same one from another box, is posted.
    expect((await h.send('web1', { ...info, detail: 'curl' })).body.result).toBe('noted')
    expect((await h.send('db1', { ...info, source: 'db1' })).body.result).toBe('noted')
    expect(h.discord.sent).toHaveLength(3)
    // An hour on, the same note is posted again.
    now += INFO_NOTE_REPEAT_MS
    expect((await h.send('web1', info)).body.result).toBe('noted')
    // A note Discord did not take is not remembered, so the retry posts it.
    h.discord.fail.send = true
    expect((await h.send('web1', { ...info, detail: 'zlib' })).status).toBe(503)
    h.discord.fail.send = false
    expect((await h.send('web1', { ...info, detail: 'zlib' })).body.result).toBe('noted')
  })

  it('the info notes it remembers stay few, however many a key sends', async () => {
    const h = await hub()
    const note = (i: number): Report => ({ kind: 'security', source: 'web1', event: `e${i}`, state: 'triggered', severity: 'info', title: '', detail: '', group: '', data: false })
    for (let i = 0; i < 2_000; i++) expect((await h.ops.hostReport(note(i), { page: false })).body.result).toBe('noted')
    expect((h.ops as any).notes.size).toBeLessThanOrEqual(500)
    // The newest are still remembered.
    expect((await h.ops.hostReport(note(1_999), { page: false })).body.result).toBe('already-noted')
  })
})

describe('not delivered (503)', () => {
  it('records nothing when Discord did not take the card, so the retry posts it once', async () => {
    const h = await hub()
    h.discord.fail.send = true
    expect((await h.send('web1', sec({ severity: 'critical' }))).status).toBe(503)
    expect(h.open()).toHaveLength(0)
    h.discord.fail.send = false
    expect((await h.send('web1', sec({ severity: 'critical' }))).status).toBe(202)
    expect((await h.send('web1', sec({ severity: 'critical' }))).body.result).toBe('unchanged')
    expect(h.discord.sent).toHaveLength(1)
  })

  it('answers 503 while Discord is not connected or the hub is not set up', async () => {
    const h = await hub()
    h.discord.state.ready = false
    expect(await h.send('web1', sec())).toMatchObject({ status: 503, body: { error: 'Discord is not reachable.' } })
    const n = await hub({ setup: false })
    expect((await n.send('web1', sec())).status).toBe(503)
    // A resolve with nothing open needs no Discord.
    expect((await n.send('web1', sec({ state: 'resolved' }))).status).toBe(202)
  })

  it('a failed edit changes nothing, and the rise ping is sent on the retry', async () => {
    const h = await hub()
    await h.send('web1', sec())
    h.discord.fail.edit = true
    expect((await h.send('web1', sec({ severity: 'critical' }))).status).toBe(503)
    expect(h.open()[0].severity).toBe('warning')
    h.discord.fail.edit = false
    expect((await h.send('web1', sec({ severity: 'critical' }))).status).toBe(202)
    expect(h.discord.sent.filter((s) => s.payload.content === '<@&42>')).toHaveLength(1)
  })
})

describe('dm= keys', () => {
  it('sends one direct message per report and nothing else', async () => {
    const h = await hub()
    expect((await h.send('pc1', sec({ source: 'pc1', severity: 'critical' }))).body.result).toBe('dm')
    expect((await h.send('pc1', sec({ source: 'pc1', state: 'resolved' }))).body.result).toBe('dm')
    expect(h.discord.dms.map((d) => d.userId)).toEqual([DM_USER, DM_USER])
    expect(h.discord.dms[0].payload.embeds[0].title).toBe('Critical: SSH login burst (pc1)')
    expect(h.discord.dms[1].payload.embeds[0].title).toBe('Reported fixed: SSH login burst (pc1)')
    expect(h.discord.dms.every((d) => !d.payload.content && !d.payload.components && d.payload.allowedMentions.parse.length === 0)).toBe(true)
    expect(h.discord.sent).toHaveLength(0)
    expect(h.open()).toHaveLength(0)
  })

  it('answers 503 when the DM fails, and never falls back to a channel', async () => {
    const h = await hub()
    h.discord.fail.dm = true
    expect((await h.send('pc1', sec({ source: 'pc1' }))).status).toBe(503)
    expect(h.discord.sent).toHaveLength(0)
    expect(h.logs.join('\n')).not.toContain(DM_USER)
  })

  it('cannot send data events, and is capped per hour', async () => {
    let now = Date.parse('2025-03-03T10:00:00Z')
    const h = await hub({ now: () => now })
    expect((await h.send('pc1', { kind: 'security', source: 'pc1', event: 'reboot-pending', detail: 'v=1' })).status).toBe(403)
    for (let i = 0; i < LIMITS.dmPerHour; i++) {
      expect((await h.send('pc1', sec({ source: 'pc1', detail: `n${i}` }))).status).toBe(202)
      now += 60_000
    }
    const r = await h.send('pc1', sec({ source: 'pc1', detail: 'one too many' }))
    expect(r.status).toBe(429)
    expect(r.retryAfterSec).toBeGreaterThan(0)
  })
})

describe('the key decides the source', () => {
  it('a key cannot report for another source', async () => {
    const h = await hub()
    expect(await h.send('db1', sec())).toMatchObject({ status: 403 })
    expect(h.discord.sent).toHaveLength(0)
  })

  it('a bad body is 400 naming the field, and never echoes it', async () => {
    const h = await hub()
    const key = (await h.reports.authenticate(auth('web1')))!
    expect(await h.reports.handle(key, '{not json')).toMatchObject({ status: 400, body: { field: 'body' } })
    const r = await h.reports.handle(key, JSON.stringify(sec({ title: 'secret '.repeat(30) })))
    expect(r).toMatchObject({ status: 400, body: { field: 'title' } })
    expect(JSON.stringify(r.body)).not.toContain('secret')
    expect(await h.reports.authenticate('Bearer nope')).toBeNull()
  })
})

describe('rate limits', () => {
  it('limits alerts per source per minute, then lets them through in the next window', async () => {
    let now = Date.parse('2025-03-03T10:00:00Z')
    const h = await hub({ now: () => now })
    for (let i = 0; i < LIMITS.alertPerSource; i++) expect((await h.send('db1', sec({ source: 'db1', detail: `n${i}` }))).status).toBe(202)
    const r = await h.send('db1', sec({ source: 'db1', detail: 'over' }))
    expect(r.status).toBe(429)
    expect(r.retryAfterSec).toBe(60)
    // Another source still gets through, and the data events have their own window.
    expect((await h.send('web1', sec({ detail: 'other source' }))).status).toBe(202)
    expect((await h.send('db1', { kind: 'security', source: 'db1', event: 'reboot-pending', detail: 'v=1' })).status).toBe(202)
    now += 60_000
    expect((await h.send('db1', sec({ source: 'db1', detail: 'next minute' }))).status).toBe(202)
  })

  it('the total window caps many sources together', () => {
    const limiter = new RateLimiter(() => 0)
    // Each source stays under its own window; together they pass the total.
    const each = Math.min(LIMITS.alertPerSource, LIMITS.dataPerSource) - 1
    const sources = Math.ceil(Math.max(LIMITS.alertTotal, LIMITS.dataTotal) / each) + 1
    let admitted = 0
    for (let s = 0; s < sources; s++) for (let i = 0; i < each; i++) if (limiter.hit(windowsFor(`s${s}`, { data: false, dm: false })).ok) admitted++
    expect(admitted).toBe(LIMITS.alertTotal)
    let data = 0
    for (let s = 0; s < sources; s++) for (let i = 0; i < each; i++) if (limiter.hit(windowsFor(`s${s}`, { data: true, dm: false })).ok) data++
    expect(data).toBe(LIMITS.dataTotal)
  })

  it('a source over its own limit does not use up the total, so every other box still gets through', async () => {
    const h = await hub({ now: () => Date.parse('2025-03-03T10:00:00Z') })
    // A stolen key sends a no-op far past its own limit, all in one minute.
    const noop = { kind: 'security', source: 'web1', event: 'noop', state: 'resolved' }
    let refused = 0
    for (let i = 0; i < LIMITS.alertTotal * 2; i++) if ((await h.send('web1', noop)).status === 429) refused++
    expect(refused).toBe(LIMITS.alertTotal * 2 - LIMITS.alertPerSource)
    // Another box's critical report still gets its card.
    expect(await h.send('db1', sec({ source: 'db1', severity: 'critical' }))).toEqual({ status: 202, body: { accepted: true, result: 'posted' } })
    // Its own refusals are not the total's, so nothing is flagged.
    expect(h.logs.filter((l) => l.includes('refused'))).toEqual([])
    expect(h.store.state.reportsRefused).toBeNull()

    // The same on the limiter alone, for alerts and data events: what one source sends past its own window counts nowhere.
    for (const data of [false, true]) {
      const limiter = new RateLimiter(() => 0)
      const total = data ? LIMITS.dataTotal : LIMITS.alertTotal
      const each = data ? LIMITS.dataPerSource : LIMITS.alertPerSource
      for (let i = 0; i < total * 3; i++) limiter.hit(windowsFor('web1', { data, dm: false }))
      let others = 0
      for (let s = 0; s < Math.ceil(total / each) + 1; s++) for (let i = 0; i < each; i++) if (limiter.hit(windowsFor(`s${s}`, { data, dm: false })).ok) others++
      expect(others).toBe(total - each)
    }
  })

  it('the total refusing a source under its own limit is logged once a minute, never with a key, and shown on the status board for an hour', async () => {
    const t0 = Date.parse('2025-03-03T10:00:00Z')
    let now = t0
    const seeds = ['s1', 's2', 's3', 's4', 's5']
    const h = await hub({ now: () => now, keys: seeds.map((s) => keyLineFor(s, s)) })
    const noop = (source: string) => ({ kind: 'security', source, event: 'noop', state: 'resolved' })
    /** Four sources each use their whole own limit, which fills the total. */
    const fill = async () => {
      for (const s of seeds.slice(0, 4)) for (let i = 0; i < LIMITS.alertPerSource; i++) expect((await h.send(s, noop(s))).status).toBe(202)
    }
    const refusals = () => h.logs.filter((l) => l.includes('refused'))
    const board = () => dashboardEmbed(h.store.state, { nextRunAt: null, running: false, repoScanning: false }).fields!.find((f) => f.name === 'Reports refused')

    await fill()
    // Over its own limit: not the total's doing, so not flagged.
    expect((await h.send('s1', noop('s1'))).status).toBe(429)
    expect(refusals()).toEqual([])
    // s5 has sent nothing and is refused: logged once, with the busiest sources.
    expect(await h.send('s5', noop('s5'))).toMatchObject({ status: 429, retryAfterSec: 60 })
    expect(await h.send('s5', noop('s5'))).toMatchObject({ status: 429 })
    expect(refusals()).toHaveLength(1)
    expect(refusals()[0]).toContain('An alert report from s5 was refused: the total limit for alert reports is full, although s5 is under its own.')
    expect(refusals()[0]).toContain('Busiest sources this minute: s1 (25), s2 (25), s3 (25).')
    const since = new Date(t0).toISOString()
    expect(h.store.state.reportsRefused).toEqual({ since, lastAt: since })
    expect(board()!.value).toContain(`since <t:${t0 / 1000}:R> (the latest <t:${t0 / 1000}:R>)`)

    // A minute on, again: one more line, which counts the refusal it did not log.
    now += 60_000
    await fill()
    expect((await h.send('s5', noop('s5'))).status).toBe(429)
    expect(refusals()).toHaveLength(2)
    expect(refusals()[1]).toContain('1 more was refused since the last line like this.')
    expect(h.store.state.reportsRefused).toEqual({ since, lastAt: new Date(now).toISOString() })
    for (const line of h.logs) for (const s of seeds) expect(line).not.toContain(fakeKey(s))

    // Reports get through again, but the line stays until an hour after the last refusal.
    now += 60_000
    expect((await h.send('s5', noop('s5'))).status).toBe(202)
    expect(board()).toBeDefined()
    now += 3_600_000
    expect((await h.send('s5', noop('s5'))).status).toBe(202)
    expect(h.store.state.reportsRefused).toBeNull()
    expect(board()).toBeUndefined()
  })

  it('a flood of made-up keys cannot grow the counters without end, and the total window survives it', () => {
    const limiter = new RateLimiter(() => 0)
    for (let i = 0; i < LIMITS.alertTotal; i++) limiter.hit([{ key: '_alert', max: LIMITS.alertTotal, ms: 60_000 }])
    for (let i = 0; i < 5_000; i++) limiter.hit([{ key: `alert:s${i}`, max: LIMITS.alertPerSource, ms: 60_000 }])
    expect((limiter as any).windows.size).toBeLessThanOrEqual(1_000)
    expect(limiter.hit([{ key: '_alert', max: LIMITS.alertTotal, ms: 60_000 }]).ok).toBe(false)
  })
})

describe('data events', () => {
  it('stores and clears a pending reboot, never as a card', async () => {
    const h = await hub()
    const since = Math.floor(Date.now() / 1000) - 86400 * 3
    const r = await h.send('web1', {
      kind: 'security', source: 'web1', event: 'reboot-pending', severity: 'critical',
      detail: `v=1 since=${since} checked=yes livepatch=on pkgs=linux-image-generic,openssl,BAD!,openssl more=4 hc_covered=2 hc_uncovered=1`,
    })
    expect(r.body.result).toBe('stored')
    expect(h.discord.sent).toHaveLength(0)
    expect(h.store.state.rebootPending.web1).toMatchObject({
      source: 'web1', since: since * 1000, checked: true, livepatch: true, pkgs: ['linux-image-generic', 'openssl'], more: 4, covered: 2, uncovered: 1,
    })
    expect((await h.send('web1', { kind: 'security', source: 'web1', event: 'reboot-pending', state: 'resolved' })).body.result).toBe('cleared')
    expect(h.store.state.rebootPending.web1).toBeUndefined()
  })

  it('reads a pending reboot that could not be checked, and ignores a box clock far in the future', async () => {
    const h = await hub()
    const future = Math.floor(Date.now() / 1000) + 86400 * 30
    await h.send('web1', { kind: 'security', source: 'web1', event: 'reboot-pending', detail: `v=1 since=${future} checked=no livepatch=off pkgs=- more=0 hc_covered=1 hc_uncovered=1` })
    expect(h.store.state.rebootPending.web1).toMatchObject({ since: null, checked: false, livepatch: false, pkgs: [], covered: null, uncovered: null })
  })

  it('stores a container package list, capped and sorted, and clears it on resolve', async () => {
    const h = await hub()
    const pkgs = ['zlib@1:1.2.13', 'openssl@3.0.13-1', 'openssl@3.0.13-1', 'bad!name@1', 'busybox@1.36.1-r2'].join(',')
    const r = await h.send('db1', {
      kind: 'security', source: 'db1', event: 'container-packages',
      detail: `v=1 ctr=api img=ghcr.io/example/api@sha256:${'a'.repeat(64)} iid=sha256:${'b'.repeat(64)} built=1760000000 os=debian osver=12 pm=dpkg more=3 pkgs=${pkgs}`,
    })
    expect(r.body.result).toBe('stored')
    const rec = h.store.state.containers['db1/api']
    expect(rec).toMatchObject({ box: 'db1', container: 'api', image: 'ghcr.io/example/api:latest', imageId: 'b'.repeat(12), builtAt: 1_760_000_000_000, os: 'debian', osVersion: '12', pm: 'dpkg', more: 3 })
    expect(rec.packages).toEqual([{ name: 'busybox', version: '1.36.1-r2' }, { name: 'openssl', version: '3.0.13-1' }, { name: 'zlib', version: '1:1.2.13' }])
    expect((await h.send('db1', { kind: 'security', source: 'db1', event: 'container-packages', state: 'resolved', detail: 'v=1 ctr=api' })).body.result).toBe('cleared')
    expect(h.store.state.containers['db1/api']).toBeUndefined()
  })

  it('refuses a container report without a container or image, and caps the package list', async () => {
    const h = await hub()
    expect(await h.send('db1', { kind: 'security', source: 'db1', event: 'container-packages', detail: 'v=1 img=nginx' })).toMatchObject({ status: 400, body: { field: 'detail' } })
    expect(await h.send('db1', { kind: 'security', source: 'db1', event: 'container-packages', state: 'resolved', detail: 'v=1' })).toMatchObject({ status: 400 })
    const many = Array.from({ length: CONTAINER_MAX_PKGS + 50 }, (_, i) => `p${i}@1`).join(',')
    await h.send('db1', { kind: 'security', source: 'db1', event: 'container-packages', detail: `v=1 ctr=big img=nginx:1 pm=dpkg pkgs=${many}` })
    const rec = h.store.state.containers['db1/big']
    expect(rec.packages).toHaveLength(CONTAINER_MAX_PKGS)
    expect(rec.more).toBe(50)
    expect(rec.os).toBe('')
  })

  it('caps the containers kept per source', async () => {
    let now = Date.parse('2025-03-03T10:00:00Z')
    const h = await hub({ now: () => now })
    for (let i = 0; i < CONTAINERS_MAX_PER_BOX; i++) {
      // Past the data window, which is not what this test is about.
      now += 2_000
      expect((await h.send('db1', { kind: 'security', source: 'db1', event: 'container-packages', detail: `v=1 ctr=c${i} img=nginx:1` })).status).toBe(202)
    }
    expect((await h.send('db1', { kind: 'security', source: 'db1', event: 'container-packages', detail: 'v=1 ctr=one-more img=nginx:1' })).status).toBe(429)
    // An update of a known container still works.
    expect((await h.send('db1', { kind: 'security', source: 'db1', event: 'container-packages', detail: 'v=1 ctr=c0 img=nginx:2' })).status).toBe(202)
  })

  it('stores data while Discord is down', async () => {
    const h = await hub()
    h.discord.state.ready = false
    expect((await h.send('web1', { kind: 'security', source: 'web1', event: 'reboot-pending', detail: 'v=1' })).status).toBe(202)
  })
})
