/**
 * Entry point: read the settings, open the saved state, start the report
 * server, log in to Discord and start the timers.
 */
import path from 'node:path'
import { Client, Events, GatewayIntentBits, OAuth2Scopes, type Guild } from 'discord.js'
import { OpsCards } from './cards/ops.js'
import { clientPort } from './cards/port.js'
import { loadConfig } from './config.js'
import { RebootDigest } from './digest.js'
import { nethersecCommand } from './discord/commands.js'
import { handleInteraction } from './discord/handlers.js'
import { BOT_PERMISSIONS } from './discord/setup.js'
import { HourlyJobs } from './jobs.js'
import { log } from './log.js'
import { Monitor } from './monitor.js'
import { ReportHandler } from './reports/handler.js'
import { KEYS_FILE, KeyRing } from './reports/keys.js'
import { GitHubClient } from './scanner/http.js'
import { createHubServer, listen } from './server.js'
import { buildStateView } from './stateView.js'
import { Store } from './store.js'
import { createWatchHost } from './watchHost.js'
import { registerWatchJobs } from './watchJobs.js'

/** How long shutdown waits for a running scan or job. Keep it under the container's stop timeout. */
const SHUTDOWN_WAIT_MS = 45_000
/** The status board is refreshed at most this often after host or watch cards change. */
const BOARD_REFRESH_MS = 30_000

async function main(): Promise<void> {
  const config = loadConfig()
  const store = await Store.open(config.dataDir, config.intervalMinutes)
  const github = config.githubToken ? new GitHubClient({ token: config.githubToken }) : null
  // Guilds is the only intent needed: the bot never reads messages.
  const client = new Client({ intents: [GatewayIntentBits.Guilds], allowedMentions: { parse: [] } })
  const port = clientPort(client)
  const monitor = new Monitor({ client, store, github, publicUrl: config.publicUrl })

  let boardTimer: NodeJS.Timeout | null = null
  const refreshBoardSoon = () => {
    if (boardTimer) return
    boardTimer = setTimeout(() => {
      boardTimer = null
      monitor.updateDashboard().catch(() => {})
    }, BOARD_REFRESH_MS)
    boardTimer.unref()
  }

  const ops = new OpsCards({ store, port, guildId: config.guildId, log, onChange: refreshBoardSoon })
  const keys = new KeyRing(path.join(config.dataDir, KEYS_FILE), { log })
  const reports = new ReportHandler({ store, keys, ops, port, log, onChange: refreshBoardSoon })
  const jobs = new HourlyJobs({ isSetUp: () => !!store.state.setup, log })
  const digest = new RebootDigest({ store, port, log })

  // The watch modules get everything they need from this one object.
  const watchHost = createWatchHost({ ops, store, jobs, log })
  registerWatchJobs(watchHost, { dataDir: config.dataDir, githubToken: config.githubToken || undefined })

  const server = createHubServer({
    reports,
    apiToken: config.apiToken,
    state: () => buildStateView(store.state, { now: new Date(), discordReady: client.isReady(), repoScanning: monitor.scanning }),
    log,
  })
  const at = await listen(server, config.listen)
  log(`Report server listening on ${at.host.includes(':') ? `[${at.host}]` : at.host}:${at.port}.${config.apiToken ? '' : ' The state API is off (NETHERSEC_API_TOKEN is not set).'}`)
  if (!github) log('Repo scanning is off: GITHUB_TOKEN is not set.')
  await keys.current()

  const deps = { monitor, github, guildId: config.guildId, ops, keys, publicUrl: config.publicUrl }

  const registerCommands = async (guild: Guild) => {
    try {
      // Replaces the whole set, so a 1.x /cve command goes away.
      await guild.commands.set([nethersecCommand.toJSON()])
      log(`Slash commands registered in ${guild.name}.`)
    } catch (err) {
      log(`Could not register slash commands: ${err instanceof Error ? err.message : 'unknown error'}`)
    }
  }

  // One install serves one server: the alerts must not be readable from anyone else's.
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
      if (!store.state.setup) log('Run /nethersec setup in your server to create the channels.')
    } else {
      const url = ready.generateInvite({ scopes: [OAuth2Scopes.Bot, OAuth2Scopes.ApplicationsCommands], permissions: BOT_PERMISSIONS })
      log(`The bot is not in server ${config.guildId} yet. Invite it with: ${url}`)
    }
    monitor.start()
    jobs.start()
    digest.start()
    void digest.check()
  })

  client.on(Events.GuildCreate, async (guild) => {
    if (await leaveIfForeign(guild)) return
    await registerCommands(guild)
  })

  client.on(Events.InteractionCreate, (interaction) => {
    void handleInteraction(deps, interaction)
  })

  client.on(Events.Error, (err) => log(`Discord client error: ${err.name}`))

  let shuttingDown = false
  const shutdown = async (signal: string) => {
    if (shuttingDown) return
    shuttingDown = true
    log(`${signal} received, shutting down.`)
    server.close()
    monitor.stop()
    jobs.stop()
    digest.stop()
    // A scan that is posting alerts finishes and saves first, so the restart
    // does not post them again.
    const [scanIdle, jobsIdle] = await Promise.all([monitor.whenIdle(SHUTDOWN_WAIT_MS), jobs.whenIdle(SHUTDOWN_WAIT_MS)])
    if (!scanIdle) log('The running scan did not finish in time. Some alerts may post again after the restart.')
    if (!jobsIdle) log('A watch job did not finish in time.')
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
    server.close()
    await client.destroy().catch(() => {})
    throw err
  }
}

main().catch((err) => {
  console.error(`${new Date().toISOString()} Could not start: ${err instanceof Error ? err.message : String(err)}`)
  process.exitCode = 1
})
