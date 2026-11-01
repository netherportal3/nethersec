import type { Client, Interaction } from 'discord.js'
import { PermissionFlagsBits } from 'discord.js'
import { describe, expect, it } from 'vitest'
import { OPS_ACK_PREFIX, OPS_MUTE_PREFIX, OPS_RESOLVE_PREFIX } from '../src/cards/render.js'
import { handleInteraction, type HandlerDeps } from '../src/discord/handlers.js'
import { Monitor } from '../src/monitor.js'
import { GUILD, auth, keyLineFor, makeHub } from './hubHelpers.js'

const ADMIN = '5'.repeat(18)
const WATCHER = '6'.repeat(18)
const NOBODY = '7'.repeat(18)

async function setup() {
  const h = await makeHub({ keys: [keyLineFor('web1', 'web1', 'page')] })
  const monitor = new Monitor({ client: {} as Client, store: h.store, github: null })
  const deps: HandlerDeps = { monitor, github: null, guildId: GUILD, ops: h.ops, keys: h.keys, publicUrl: null }
  await h.reports.handle((await h.reports.authenticate(auth('web1')))!, JSON.stringify({ kind: 'security', source: 'web1', event: 'ssh-auth-burst', title: 'Burst' }))
  const card = Object.values(h.store.state.opsCards)[0]
  return { ...h, deps, card }
}

/** A button press by `userId`, recording what the handler answered. */
function press(customId: string, userId: string) {
  const calls: Array<[string, any]> = []
  const isAdmin = userId === ADMIN
  const roles = userId === WATCHER ? ['42'] : []
  const interaction = {
    inGuild: () => true,
    guildId: GUILD,
    isAutocomplete: () => false,
    isButton: () => true,
    isChatInputCommand: () => false,
    isRepliable: () => true,
    customId,
    user: { id: userId },
    member: { roles },
    memberPermissions: { has: (p: bigint) => isAdmin && p === PermissionFlagsBits.ManageGuild },
    deferred: false,
    replied: false,
    reply: async (x: unknown) => void calls.push(['reply', x]),
    deferUpdate: async () => void calls.push(['deferUpdate', null]),
    editReply: async (x: unknown) => void calls.push(['editReply', x]),
    followUp: async (x: unknown) => void calls.push(['followUp', x]),
  }
  return { interaction: interaction as unknown as Interaction, calls }
}

/** A `/nethersec <sub>` command by an admin, recording what the handler answered. */
function slash(sub: string, options: Record<string, string>) {
  const calls: Array<[string, any]> = []
  const interaction = {
    inGuild: () => true,
    guildId: GUILD,
    isAutocomplete: () => false,
    isButton: () => false,
    isChatInputCommand: () => true,
    isRepliable: () => true,
    commandName: 'nethersec',
    user: { id: ADMIN },
    options: {
      getSubcommandGroup: () => null,
      getSubcommand: () => sub,
      getString: (name: string) => options[name] ?? null,
    },
    deferred: false,
    replied: false,
    reply: async (x: unknown) => void calls.push(['reply', x]),
  }
  return { interaction: interaction as unknown as Interaction, calls }
}

describe('advisory mutes', () => {
  const GHSA = 'GHSA-aaaa-bbbb-cccc'
  const everywhere = { advisoryId: GHSA, repo: null, by: ADMIN, at: '2025-03-28T12:00:00.000Z' }
  const oneRepo = { advisoryId: GHSA, repo: 'example/app', by: ADMIN, at: '2025-03-28T12:00:00.000Z' }

  it('unmute with a repo that does not read is refused and removes nothing', async () => {
    const s = await setup()
    s.store.state.mutes = [{ ...everywhere }, { ...oneRepo }]
    for (const repo of ['not a repo', 'example', 'https://example.com/a/b']) {
      const c = slash('unmute', { advisory: GHSA, repo })
      await handleInteraction(s.deps, c.interaction)
      expect(c.calls).toEqual([['reply', expect.objectContaining({ content: 'Give the repo as owner/name. Nothing was unmuted.' })]])
    }
    expect(s.store.state.mutes).toEqual([everywhere, oneRepo])
  })

  it('unmute with a repo lifts only that repo, and without one only the every-repo mute', async () => {
    const s = await setup()
    s.store.state.mutes = [{ ...everywhere }, { ...oneRepo }]
    const one = slash('unmute', { advisory: GHSA, repo: 'https://github.com/Example/App' })
    await handleInteraction(s.deps, one.interaction)
    expect(one.calls[0][1].content).toBe(`Unmuted ${GHSA} for Example/App. Alerts for it come back for repos where it is new.`)
    expect(s.store.state.mutes).toEqual([everywhere])
    const all = slash('unmute', { advisory: GHSA })
    await handleInteraction(s.deps, all.interaction)
    expect(all.calls[0][1].content).toBe(`Unmuted ${GHSA}. Alerts for it come back for repos where it is new.`)
    expect(s.store.state.mutes).toEqual([])
  })
})

describe('host card buttons', () => {
  it('Resolve: the watcher role may press it, the card closes and the message is edited', async () => {
    const s = await setup()
    const p = press(OPS_RESOLVE_PREFIX + s.card.id, WATCHER)
    await handleInteraction(s.deps, p.interaction)
    expect(p.calls.map((c) => c[0])).toEqual(['deferUpdate', 'editReply'])
    const edit = p.calls[1][1]
    expect(edit.embeds[0].title).toBe('Resolved: Burst (web1)')
    expect(edit.embeds[0].fields.find((f: any) => f.name === 'Status').value).toContain(`Resolved by <@${WATCHER}>`)
    expect(edit.components).toEqual([])
    expect(edit.allowedMentions).toEqual({ parse: [] })
    expect(s.store.state.opsCards[s.card.id].closedAt).toBeDefined()
  })

  it('refuses people without the role, and Mute to anyone but an admin', async () => {
    const s = await setup()
    const nobody = press(OPS_RESOLVE_PREFIX + s.card.id, NOBODY)
    await handleInteraction(s.deps, nobody.interaction)
    expect(nobody.calls.map((c) => c[0])).toEqual(['reply'])
    const watcherMute = press(OPS_MUTE_PREFIX + s.card.id, WATCHER)
    await handleInteraction(s.deps, watcherMute.interaction)
    expect(watcherMute.calls[0][1].content).toContain('Only server admins')
    expect(s.store.state.opsMutes).toEqual([])

    const adminMute = press(OPS_MUTE_PREFIX + s.card.id, ADMIN)
    await handleInteraction(s.deps, adminMute.interaction)
    expect(adminMute.calls.map((c) => c[0])).toEqual(['deferUpdate', 'editReply', 'followUp'])
    expect(s.store.state.opsMutes.map((m) => m.key)).toEqual(['security:web1:ssh-auth-burst'])
  })

  it('a watch card has Acknowledge and Resolve; Resolve closes it like a host card, and Mute is refused', async () => {
    const s = await setup()
    await s.ops.upsert({ id: 'advisory:engine:GHSA-aaaa-aaaa-aaaa', severity: 'warning', ping: false, title: 'High advisory for Engine', body: 'Fixed in 1.2.3.' })
    const posted = s.discord.sent.at(-1)!.payload
    const watch = s.ops.findOpen('watch:advisory:engine:GHSA-aaaa-aaaa-aaaa')!
    expect(posted.components![0].components.map((c) => ('custom_id' in c ? c.custom_id : ''))).toEqual([OPS_ACK_PREFIX + watch.id, OPS_RESOLVE_PREFIX + watch.id])
    const hostResolve = s.discord.sent[0].payload.components![0].components.find((c) => 'label' in c && c.label === 'Resolve')
    expect(posted.components![0].components[1]).toMatchObject({ label: 'Resolve', style: (hostResolve as { style: number }).style })

    const nobody = press(OPS_RESOLVE_PREFIX + watch.id, NOBODY)
    await handleInteraction(s.deps, nobody.interaction)
    expect(nobody.calls.map((c) => c[0])).toEqual(['reply'])
    expect(s.ops.findOpen(watch.key)).toBeDefined()

    const mute = press(OPS_MUTE_PREFIX + watch.id, ADMIN)
    await handleInteraction(s.deps, mute.interaction)
    expect(mute.calls[1][1].content).toBe('Watch cards cannot be muted.')

    const p = press(OPS_RESOLVE_PREFIX + watch.id, WATCHER)
    await handleInteraction(s.deps, p.interaction)
    expect(p.calls.map((c) => c[0])).toEqual(['deferUpdate', 'editReply'])
    const edit = p.calls[1][1]
    expect(edit.embeds[0].title).toBe('Resolved: High advisory for Engine')
    expect(edit.embeds[0].fields.find((f: any) => f.name === 'Status').value).toContain(`Resolved by <@${WATCHER}>`)
    expect(edit.components).toEqual([])
    expect(s.ops.findOpen(watch.key)).toBeUndefined()
  })

  it('a press on a closed card says so instead of editing it', async () => {
    const s = await setup()
    await handleInteraction(s.deps, press(OPS_RESOLVE_PREFIX + s.card.id, ADMIN).interaction)
    const again = press(OPS_RESOLVE_PREFIX + s.card.id, ADMIN)
    await handleInteraction(s.deps, again.interaction)
    expect(again.calls.map((c) => c[0])).toEqual(['deferUpdate', 'followUp'])
    expect(again.calls[1][1].content).toBe('This alert is already closed.')
  })
})
