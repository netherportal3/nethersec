/**
 * /nethersec setup: the "nethersec" category, three read-only channels and the
 * "nethersec watch" role. Running it again reuses what still exists (by ID, so
 * channels and a role from discord-cve-monitor 1.x keep their names), recreates
 * what was deleted, and applies the private/public choice again.
 */
import {
  ChannelType,
  PermissionFlagsBits,
  type CategoryChannel,
  type Guild,
  type OverwriteResolvable,
  type Role,
  type TextChannel,
} from 'discord.js'
import type { Setup } from '../state.js'

export const ROLE_NAME = 'nethersec watch'
export const CATEGORY_NAME = 'nethersec'
const REASON = 'nethersec setup'

export const CHANNELS = {
  critical: { name: 'nethersec-critical', topic: 'Critical alerts. The nethersec watch role can be pinged here.' },
  alerts: { name: 'nethersec-alerts', topic: 'Other alerts: repo advisories at your alert level, host warnings, watch cards.' },
  status: { name: 'nethersec-status', topic: 'The status board, host notes, the weekly reboot summary, fixes and problems.' },
} as const

/**
 * Threads and reactions are separate from Send Messages, so the channels deny
 * them too. The bot must hold a permission to set it on a channel.
 */
const THREADS_AND_REACTIONS = [
  PermissionFlagsBits.CreatePublicThreads,
  PermissionFlagsBits.CreatePrivateThreads,
  PermissionFlagsBits.SendMessagesInThreads,
  PermissionFlagsBits.AddReactions,
]

/** The permissions the bot needs in the server, for the invite link. */
export const BOT_PERMISSIONS = [
  PermissionFlagsBits.ViewChannel,
  PermissionFlagsBits.SendMessages,
  PermissionFlagsBits.EmbedLinks,
  PermissionFlagsBits.ReadMessageHistory,
  PermissionFlagsBits.ManageChannels,
  PermissionFlagsBits.ManageRoles,
  ...THREADS_AND_REACTIONS,
].reduce((all, p) => all | p, 0n)

/**
 * Read-only for everyone: no messages, threads or reactions. The watcher role
 * can open a thread on an alert and react, to talk it over. Private: hidden
 * from everyone but the watcher role, admins and the bot. Only permissions the
 * bot itself holds are used, since Discord refuses an overwrite that grants
 * more than the bot has.
 */
export function overwritesFor(guild: Guild, roleId: string, botId: string, isPrivate: boolean): OverwriteResolvable[] {
  const everyoneDeny = [PermissionFlagsBits.SendMessages, ...THREADS_AND_REACTIONS]
  if (isPrivate) everyoneDeny.push(PermissionFlagsBits.ViewChannel)
  return [
    { id: guild.roles.everyone.id, deny: everyoneDeny },
    {
      id: roleId,
      allow: [
        PermissionFlagsBits.ViewChannel,
        PermissionFlagsBits.ReadMessageHistory,
        PermissionFlagsBits.CreatePublicThreads,
        PermissionFlagsBits.SendMessagesInThreads,
        PermissionFlagsBits.AddReactions,
      ],
      deny: [PermissionFlagsBits.SendMessages],
    },
    {
      id: botId,
      allow: [
        PermissionFlagsBits.ViewChannel,
        PermissionFlagsBits.SendMessages,
        PermissionFlagsBits.EmbedLinks,
        PermissionFlagsBits.ReadMessageHistory,
      ],
    },
  ]
}

/** What the bot is missing for setup, by name. Empty when it has everything. */
export function missingSetupPermissions(guild: Guild): string[] {
  const me = guild.members.me
  if (!me) return ['(the bot is not in this server)']
  const names: Array<[bigint, string]> = [
    [PermissionFlagsBits.ManageChannels, 'Manage Channels'],
    [PermissionFlagsBits.ManageRoles, 'Manage Roles'],
    [PermissionFlagsBits.ViewChannel, 'View Channels'],
    [PermissionFlagsBits.SendMessages, 'Send Messages'],
    [PermissionFlagsBits.EmbedLinks, 'Embed Links'],
    [PermissionFlagsBits.ReadMessageHistory, 'Read Message History'],
    [PermissionFlagsBits.CreatePublicThreads, 'Create Public Threads'],
    [PermissionFlagsBits.CreatePrivateThreads, 'Create Private Threads'],
    [PermissionFlagsBits.SendMessagesInThreads, 'Send Messages in Threads'],
    [PermissionFlagsBits.AddReactions, 'Add Reactions'],
  ]
  return names.filter(([flag]) => !me.permissions.has(flag)).map(([, name]) => name)
}

export async function runSetup(guild: Guild, existing: Setup | null, isPrivate: boolean): Promise<Setup> {
  const botId = guild.client.user.id
  await guild.roles.fetch()
  await guild.channels.fetch()

  let role: Role | undefined = existing?.roleId ? guild.roles.cache.get(existing.roleId) : undefined
  if (!role) {
    role = await guild.roles.create({
      name: ROLE_NAME,
      // Mentionable so the bot can ping it without the "Mention All Roles" permission.
      mentionable: true,
      reason: REASON,
    })
  }
  const overwrites = overwritesFor(guild, role.id, botId, isPrivate)

  let category = existing ? guild.channels.cache.get(existing.categoryId) : undefined
  if (!category || category.type !== ChannelType.GuildCategory) {
    category = await guild.channels.create({
      name: CATEGORY_NAME,
      type: ChannelType.GuildCategory,
      permissionOverwrites: overwrites,
      reason: REASON,
    })
  } else {
    await category.permissionOverwrites.set(overwrites, REASON)
  }

  const ensure = async (id: string | undefined, spec: { name: string; topic: string }): Promise<TextChannel> => {
    const found = id ? guild.channels.cache.get(id) : undefined
    if (found && found.type === ChannelType.GuildText) {
      if (found.parentId !== category.id) await found.setParent(category.id, { lockPermissions: false })
      await found.permissionOverwrites.set(overwrites, REASON)
      return found
    }
    return guild.channels.create({
      name: spec.name,
      type: ChannelType.GuildText,
      parent: (category as CategoryChannel).id,
      topic: spec.topic,
      permissionOverwrites: overwrites,
      reason: REASON,
    })
  }

  const critical = await ensure(existing?.criticalChannelId, CHANNELS.critical)
  const alerts = await ensure(existing?.alertsChannelId, CHANNELS.alerts)
  const status = await ensure(existing?.statusChannelId, CHANNELS.status)

  return {
    categoryId: category.id,
    criticalChannelId: critical.id,
    alertsChannelId: alerts.id,
    statusChannelId: status.id,
    roleId: role.id,
    private: isPrivate,
    // Keep the old status board only if it lives in the same channel.
    dashboardMessageId: existing?.statusChannelId === status.id ? existing.dashboardMessageId : undefined,
  }
}
