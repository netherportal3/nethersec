/**
 * Entry point: read the settings, open the saved state, log in to Discord and
 * start the scan timer.
 */
import { Client, Events, GatewayIntentBits, OAuth2Scopes, type Guild } from 'discord.js'
import { loadConfig } from './config.js'
import { cveCommand } from './discord/commands.js'
import { handleInteraction } from './discord/handlers.js'
import { BOT_PERMISSIONS } from './discord/setup.js'
import { log } from './log.js'
import { Monitor } from './monitor.js'
import { GitHubClient } from './scanner/http.js'
import { Store } from './store.js'

async function main(): Promise<void> {
  const config = loadConfig()
  const store = await Store.open(config.dataDir, config.intervalMinutes)
  const github = new GitHubClient({ token: config.githubToken })
  // Guilds is the only intent needed: the bot never reads messages.
  const client = new Client({ intents: [GatewayIntentBits.Guilds], allowedMentions: { parse: [] } })
  const monitor = new Monitor({ client, store, github })
  const deps = { monitor, github, guildId: config.guildId }

  const registerCommands = async (guild: Guild) => {
    try {
      await guild.commands.set([cveCommand.toJSON()])
      log(`Slash commands registered in ${guild.name}.`)
    } catch (err) {
      log(`Could not register slash commands: ${err instanceof Error ? err.message : 'unknown error'}`)
    }
  }

  // One install serves one server: the GitHub token's repos must not be readable from anyone else's.
  const leaveIfForeign = async (guild: Guild): Promise<boolean> => {
    if (guild.id === config.guildId) return false
    log(`Leaving server ${guild.id}: this bot only serves DISCORD_GUILD_ID.`)
    await guild.leave().catch(() => {})
    return true
  }

  client.once(Events.ClientReady, async (ready) => {
    log(`Logged in to Discord as ${ready.user.tag}.`)
    for (const guild of ready.guilds.cache.values()) await leaveIfForeign(guild)
    const home = ready.guilds.cache.get(config.guildId)
    if (home) {
      await registerCommands(home)
      if (!store.state.setup) log('Run /cve setup in your server to create the channels and start scanning.')
    } else {
      const url = ready.generateInvite({ scopes: [OAuth2Scopes.Bot, OAuth2Scopes.ApplicationsCommands], permissions: BOT_PERMISSIONS })
      log(`The bot is not in server ${config.guildId} yet. Invite it with: ${url}`)
    }
    monitor.start()
  })

  client.on(Events.GuildCreate, async (guild) => {
    if (await leaveIfForeign(guild)) return
    await registerCommands(guild)
  })

  client.on(Events.InteractionCreate, (interaction) => {
    void handleInteraction(deps, interaction)
  })

  client.on(Events.Error, (err) => log(`Discord client error: ${err.name}`))

  const shutdown = async (signal: string) => {
    log(`${signal} received, shutting down.`)
    monitor.stop()
    await store.save().catch(() => {})
    await client.destroy()
    process.exit(0)
  }
  process.on('SIGINT', () => void shutdown('SIGINT'))
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
  process.on('unhandledRejection', (err) => {
    log(`Unhandled rejection: ${err instanceof Error ? err.name : 'unknown'}`)
    console.error(err)
  })

  try {
    await client.login(config.discordToken)
  } catch (err) {
    monitor.stop()
    await client.destroy().catch(() => {})
    throw err
  }
}

main().catch((err) => {
  console.error(`${new Date().toISOString()} Could not start: ${err instanceof Error ? err.message : String(err)}`)
  process.exitCode = 1
})
