import { PermissionFlagsBits, type Guild } from 'discord.js'
import { describe, expect, it } from 'vitest'
import { BOT_PERMISSIONS, missingSetupPermissions, overwritesFor } from '../src/discord/setup.js'

const THREADS_AND_REACTIONS = [
  PermissionFlagsBits.CreatePublicThreads,
  PermissionFlagsBits.CreatePrivateThreads,
  PermissionFlagsBits.SendMessagesInThreads,
  PermissionFlagsBits.AddReactions,
]

describe('channel permissions', () => {
  const guild = { roles: { everyone: { id: 'everyone' } } } as unknown as Guild
  const byId = (isPrivate: boolean) => Object.fromEntries(overwritesFor(guild, 'watch', 'bot', isPrivate).map((o) => [o.id, o]))

  it('everyone can only read: no messages, threads or reactions', () => {
    const everyone = byId(false).everyone
    for (const p of [PermissionFlagsBits.SendMessages, ...THREADS_AND_REACTIONS]) expect(everyone.deny).toContain(p)
    expect(everyone.deny).not.toContain(PermissionFlagsBits.ViewChannel)
    expect(byId(true).everyone.deny).toContain(PermissionFlagsBits.ViewChannel)
  })

  it('the watcher role can see, open public threads and react, but not post', () => {
    const watch = byId(true).watch
    expect(watch.allow).toEqual(
      expect.arrayContaining([
        PermissionFlagsBits.ViewChannel,
        PermissionFlagsBits.CreatePublicThreads,
        PermissionFlagsBits.SendMessagesInThreads,
        PermissionFlagsBits.AddReactions,
      ]),
    )
    expect(watch.allow).not.toContain(PermissionFlagsBits.CreatePrivateThreads)
    expect(watch.deny).toEqual([PermissionFlagsBits.SendMessages])
  })

  it('the bot asks for every permission it sets on the channels', () => {
    for (const p of [PermissionFlagsBits.ManageChannels, PermissionFlagsBits.ManageRoles, ...THREADS_AND_REACTIONS]) {
      expect(BOT_PERMISSIONS & p).toBe(p)
    }
    const me = { permissions: { has: (p: bigint) => p !== PermissionFlagsBits.AddReactions } }
    expect(missingSetupPermissions({ members: { me } } as unknown as Guild)).toEqual(['Add Reactions'])
  })
})
