/**
 * Settings that come from the environment. Everything else is set from Discord
 * with /nethersec commands and saved in the data folder.
 */
export interface Config {
  discordToken: string
  guildId: string
  /** null = repo scanning is off. */
  githubToken: string | null
  dataDir: string
  /** Default scan interval for a fresh install; /nethersec settings can change it later. */
  intervalMinutes: number
  /** Where the report server listens. */
  listen: { host: string; port: number }
  /** Bearer token for GET /v1/state. null = the state API is off. */
  apiToken: string | null
  /** The URL boxes use to reach the hub, shown in setup hints. null = not set. */
  publicUrl: string | null
}

export const MIN_INTERVAL_MINUTES = 15
export const MAX_INTERVAL_MINUTES = 24 * 60
export const DEFAULT_LISTEN = '127.0.0.1:8787'
/** A shorter state API token is refused at start. */
export const MIN_API_TOKEN_LENGTH = 24

/** `host:port`, `[v6]:port` or `:port` (all interfaces). null when it is not one. */
export function parseListen(raw: string): { host: string; port: number } | null {
  const m = /^(?:\[([0-9a-fA-F:.]+)\]|([A-Za-z0-9.-]*)):(\d{1,5})$/.exec(raw.trim())
  if (!m) return null
  const port = Number(m[3])
  if (!Number.isInteger(port) || port < 0 || port > 65535) return null
  const host = m[1] ?? (m[2] || '0.0.0.0')
  return { host, port }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const missing: string[] = []
  const need = (name: string): string => {
    const v = (env[name] ?? '').trim()
    if (!v) missing.push(name)
    return v
  }
  const discordToken = need('DISCORD_TOKEN')
  const guildId = need('DISCORD_GUILD_ID')
  if (missing.length) {
    throw new Error(`Missing required setting${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}. See .env.example.`)
  }
  if (!/^\d{5,25}$/.test(guildId)) throw new Error('DISCORD_GUILD_ID must be a server ID (a number).')
  const interval = Number(env.SCAN_INTERVAL_MINUTES ?? 60)
  if (!Number.isInteger(interval) || interval < MIN_INTERVAL_MINUTES || interval > MAX_INTERVAL_MINUTES) {
    throw new Error(`SCAN_INTERVAL_MINUTES must be a whole number from ${MIN_INTERVAL_MINUTES} to ${MAX_INTERVAL_MINUTES}.`)
  }
  const listenRaw = (env.NETHERSEC_LISTEN ?? '').trim() || DEFAULT_LISTEN
  const listen = parseListen(listenRaw)
  if (!listen) throw new Error('NETHERSEC_LISTEN must be host:port, like 127.0.0.1:8787.')
  const apiToken = (env.NETHERSEC_API_TOKEN ?? '').trim() || null
  if (apiToken && apiToken.length < MIN_API_TOKEN_LENGTH) {
    throw new Error(`NETHERSEC_API_TOKEN must be at least ${MIN_API_TOKEN_LENGTH} characters. Make one with: openssl rand -hex 32`)
  }
  const publicRaw = (env.NETHERSEC_PUBLIC_URL ?? '').trim()
  let publicUrl: string | null = null
  if (publicRaw) {
    let u: URL
    try {
      u = new URL(publicRaw)
    } catch {
      throw new Error('NETHERSEC_PUBLIC_URL must be a URL, like https://hub.example.com.')
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('NETHERSEC_PUBLIC_URL must start with https:// or http://.')
    publicUrl = publicRaw.replace(/\/+$/, '')
  }
  return {
    discordToken,
    guildId,
    githubToken: (env.GITHUB_TOKEN ?? '').trim() || null,
    dataDir: (env.DATA_DIR ?? '').trim() || './data',
    intervalMinutes: interval,
    listen,
    apiToken,
    publicUrl,
  }
}
