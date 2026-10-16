/**
 * Settings that come from the environment. Everything else is set from Discord
 * with /cve commands and saved in the data folder.
 */
export interface Config {
  discordToken: string
  guildId: string
  githubToken: string
  dataDir: string
  /** Default scan interval for a fresh install; /cve settings can change it later. */
  intervalMinutes: number
}

export const MIN_INTERVAL_MINUTES = 15
export const MAX_INTERVAL_MINUTES = 24 * 60

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const missing: string[] = []
  const need = (name: string): string => {
    const v = (env[name] ?? '').trim()
    if (!v) missing.push(name)
    return v
  }
  const discordToken = need('DISCORD_TOKEN')
  const guildId = need('DISCORD_GUILD_ID')
  const githubToken = need('GITHUB_TOKEN')
  if (missing.length) {
    throw new Error(`Missing required setting${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}. See .env.example.`)
  }
  if (!/^\d{5,25}$/.test(guildId)) throw new Error('DISCORD_GUILD_ID must be a server ID (a number).')
  const interval = Number(env.SCAN_INTERVAL_MINUTES ?? 60)
  if (!Number.isInteger(interval) || interval < MIN_INTERVAL_MINUTES || interval > MAX_INTERVAL_MINUTES) {
    throw new Error(`SCAN_INTERVAL_MINUTES must be a whole number from ${MIN_INTERVAL_MINUTES} to ${MAX_INTERVAL_MINUTES}.`)
  }
  return {
    discordToken,
    guildId,
    githubToken,
    dataDir: (env.DATA_DIR ?? '').trim() || './data',
    intervalMinutes: interval,
  }
}
