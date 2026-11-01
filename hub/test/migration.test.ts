import { readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { ChannelType, type Guild } from 'discord.js'
import { describe, expect, it } from 'vitest'
import { ACK_PREFIX, MUTE_PREFIX } from '../src/discord/cards.js'
import { CATEGORY_NAME, CHANNELS, ROLE_NAME, runSetup } from '../src/discord/setup.js'
import { STATE_VERSION } from '../src/state.js'
import { Store } from '../src/store.js'
import { tempDir } from './hubHelpers.js'

/** A made-up Discord ID, built at runtime. */
const id = (n: number) => `1${'0'.repeat(16)}${n}`

/** A state.json as discord-cve-monitor 1.x wrote it (version 1, made-up IDs). */
const V1 = {
  version: 1,
  setup: {
    categoryId: id(1),
    criticalChannelId: id(2),
    alertsChannelId: id(3),
    statusChannelId: id(4),
    roleId: id(5),
    private: true,
    dashboardMessageId: id(6),
  },
  settings: { repoMode: 'list', repos: ['me/app'], exclude: [], includeForks: false, includeArchived: false, minSeverity: 'high', pingRole: true, pingDevOnly: false, paused: false, intervalMinutes: 30 },
  repos: {
    'me/app': {
      name: 'me/app',
      baselined: { npm: true, PyPI: true },
      findings: {
        'GHSA-xvch-5gv4-984h:minimist': {
          advisoryId: 'GHSA-xvch-5gv4-984h', cveId: null, ecosystem: 'npm', packageName: 'minimist', severity: 'critical', title: 'Prototype Pollution in minimist',
          url: 'https://github.com/advisories/GHSA-xvch-5gv4-984h', installed: ['1.2.0'], lockfiles: ['package-lock.json'], devOnly: false, fixes: [], firstSeen: '2026-09-01T00:00:00.000Z', cardId: 'abcdef0123',
        },
      },
      unreadableRuns: 0, unreadableNotified: false, lockfiles: 1, skipped: [], lastOkAt: '2026-09-30T00:00:00.000Z',
    },
  },
  cards: {
    abcdef0123: { id: 'abcdef0123', channelId: id(2), messageId: id(7), advisoryId: 'GHSA-xvch-5gv4-984h', packageName: 'minimist', severity: 'critical', repos: { 'me/app': 'open' }, createdAt: '2026-09-01T00:00:00.000Z' },
  },
  mutes: [{ advisoryId: 'GHSA-aaaa-bbbb-cccc', repo: null, by: id(8), at: '2026-09-02T00:00:00.000Z' }],
  lastRun: { startedAt: '2026-09-30T00:00:00.000Z', finishedAt: '2026-09-30T00:01:00.000Z', repos: 1, readable: 1, unreadable: [], notReached: 0, newAlerts: 0, fixed: 0, errors: [] },
  failStreak: 0,
  failNotified: false,
}

function fakeGuild(have: { roleIds: string[]; channels: Array<{ id: string; type: ChannelType; name: string; parentId?: string }> }) {
  let n = 0
  const created: Array<{ what: 'role' | 'channel'; name: string; type?: ChannelType; parent?: string }> = []
  const channel = (c: { id: string; type: ChannelType; name: string; parentId?: string }) => ({
    ...c,
    parentId: c.parentId ?? null,
    async setParent(id: string) {
      this.parentId = id
    },
    permissionOverwrites: { set: async () => {} },
  })
  const roles = new Map(have.roleIds.map((id) => [id, { id }]))
  const channels = new Map(have.channels.map((c) => [c.id, channel(c)]))
  const guild = {
    client: { user: { id: 'bot' } },
    roles: {
      everyone: { id: 'everyone' },
      cache: roles,
      fetch: async () => roles,
      create: async (o: { name: string }) => {
        created.push({ what: 'role', name: o.name })
        const r = { id: `new-role-${++n}` }
        roles.set(r.id, r)
        return r
      },
    },
    channels: {
      cache: channels,
      fetch: async () => channels,
      create: async (o: { name: string; type: ChannelType; parent?: string }) => {
        created.push({ what: 'channel', name: o.name, type: o.type, parent: o.parent })
        const c = channel({ id: `new-ch-${++n}`, type: o.type, name: o.name, parentId: o.parent })
        channels.set(c.id, c)
        return c
      },
    },
  }
  return { guild: guild as unknown as Guild, created }
}

describe('a discord-cve-monitor 1.x data folder', () => {
  it('loads as is: settings, repos, cards and mutes are kept and the new collections start empty', async () => {
    const dir = await tempDir()
    await writeFile(path.join(dir, 'state.json'), JSON.stringify(V1, null, 2))
    const store = await Store.open(dir, 60)
    const s = store.state
    expect(s.version).toBe(STATE_VERSION)
    expect(s.setup).toEqual(V1.setup)
    expect(s.settings).toEqual(V1.settings)
    expect(s.repos['me/app'].findings['GHSA-xvch-5gv4-984h:minimist'].cardId).toBe('abcdef0123')
    expect(s.cards).toEqual(V1.cards)
    expect(s.mutes).toEqual(V1.mutes)
    expect(s.lastRun).toEqual(V1.lastRun)
    expect(s).toMatchObject({ opsCards: {}, opsMutes: [], hosts: {}, rebootPending: {}, containers: {}, modules: {}, rebootDigestWeek: null })

    // Saved as version 2, and loads again the same.
    await store.save()
    const saved = JSON.parse(await readFile(path.join(dir, 'state.json'), 'utf8'))
    expect(saved.version).toBe(2)
    expect((await Store.open(dir, 60)).state.setup).toEqual(V1.setup)
  })

  it('drops hand-edited entries that would break the state view', async () => {
    const dir = await tempDir()
    await writeFile(
      path.join(dir, 'state.json'),
      JSON.stringify({
        ...V1,
        version: 2,
        hosts: { web1: { source: 'web1', firstReportAt: 'x', lastReportAt: 'y', reports: 1 }, bad: 'nope' },
        containers: { 'web1/api': { box: 'web1', container: 'api', image: 'nginx:1', receivedAt: 1, packages: [] }, 'web1/bad': { box: 'web1' } },
        rebootPending: { web1: { source: 'web1', receivedAt: 1, pkgs: [] }, db1: { source: 'db1' } },
        opsCards: { abc: { id: 'abc' } },
      }),
    )
    const s = (await Store.open(dir, 60)).state
    expect(Object.keys(s.hosts)).toEqual(['web1'])
    expect(Object.keys(s.containers)).toEqual(['web1/api'])
    expect(Object.keys(s.rebootPending)).toEqual(['web1'])
    expect(s.opsCards).toEqual({})
  })

  it('keeps the button ids of cards already posted, so their buttons still work', () => {
    expect(ACK_PREFIX).toBe('cve:ack:')
    expect(MUTE_PREFIX).toBe('cve:mute:')
  })

  it('setup on a migrated install reuses its channels and role by ID, keeping their names', async () => {
    const s = V1.setup
    const { guild, created } = fakeGuild({
      roleIds: [s.roleId],
      channels: [
        { id: s.categoryId, type: ChannelType.GuildCategory, name: 'CVE Monitor' },
        { id: s.criticalChannelId, type: ChannelType.GuildText, name: 'cve-critical', parentId: s.categoryId },
        { id: s.alertsChannelId, type: ChannelType.GuildText, name: 'cve-alerts', parentId: s.categoryId },
        { id: s.statusChannelId, type: ChannelType.GuildText, name: 'cve-status', parentId: s.categoryId },
      ],
    })
    const next = await runSetup(guild, s, true)
    expect(created).toEqual([])
    expect(next).toEqual(s)
  })

  it('a fresh setup makes the nethersec category, channels and role', async () => {
    const { guild, created } = fakeGuild({ roleIds: [], channels: [] })
    const next = await runSetup(guild, null, true)
    expect(created.map((c) => c.name)).toEqual([ROLE_NAME, CATEGORY_NAME, CHANNELS.critical.name, CHANNELS.alerts.name, CHANNELS.status.name])
    expect([ROLE_NAME, CATEGORY_NAME, CHANNELS.critical.name, CHANNELS.alerts.name, CHANNELS.status.name]).toEqual([
      'nethersec watch',
      'nethersec',
      'nethersec-critical',
      'nethersec-alerts',
      'nethersec-status',
    ])
    expect(created.filter((c) => c.what === 'channel' && c.type === ChannelType.GuildText).every((c) => c.parent === next.categoryId)).toBe(true)
    expect(next.dashboardMessageId).toBeUndefined()
  })

  it('setup recreates only what was deleted', async () => {
    const s = V1.setup
    const { guild, created } = fakeGuild({
      roleIds: [s.roleId],
      channels: [
        { id: s.categoryId, type: ChannelType.GuildCategory, name: 'CVE Monitor' },
        { id: s.criticalChannelId, type: ChannelType.GuildText, name: 'cve-critical', parentId: s.categoryId },
        { id: s.alertsChannelId, type: ChannelType.GuildText, name: 'cve-alerts', parentId: s.categoryId },
      ],
    })
    const next = await runSetup(guild, s, true)
    expect(created).toEqual([{ what: 'channel', name: 'nethersec-status', type: ChannelType.GuildText, parent: s.categoryId }])
    expect(next.criticalChannelId).toBe(s.criticalChannelId)
    expect(next.statusChannelId).not.toBe(s.statusChannelId)
    // The old status board lived in the old status channel, so it is dropped.
    expect(next.dashboardMessageId).toBeUndefined()
  })
})
