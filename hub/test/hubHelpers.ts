import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { OpsCards } from '../src/cards/ops.js'
import { MessageGone, type DiscordPort } from '../src/cards/port.js'
import type { Payload } from '../src/discord/cards.js'
import { ReportHandler } from '../src/reports/handler.js'
import { KEYS_FILE, KeyRing, sha256 } from '../src/reports/keys.js'
import { RateLimiter } from '../src/reports/ratelimit.js'
import { Store } from '../src/store.js'

export const SETUP = { categoryId: 'cat', criticalChannelId: 'crit', alertsChannelId: 'alerts', statusChannelId: 'status', roleId: '42', private: true }
export const GUILD = '2'.repeat(18)
/** A made-up Discord user ID, built at runtime. */
export const DM_USER = '1'.repeat(18)

/** A fake key: 64 hex characters made at runtime, never a literal that looks like a secret. */
export function fakeKey(seed: string): string {
  return sha256(`test-key-${seed}`).toString('hex')
}

export function fakePort() {
  const sent: Array<{ channelId: string; payload: Payload; id: string }> = []
  const edits: Array<{ channelId: string; messageId: string; payload: Payload }> = []
  const dms: Array<{ userId: string; payload: Payload }> = []
  const messages = new Map<string, Payload>()
  const fail = { send: false, edit: false, dm: false }
  const state = { ready: true }
  let n = 0
  const port: DiscordPort = {
    isReady: () => state.ready,
    async send(channelId, payload) {
      if (fail.send) throw new Error('Missing Access')
      const id = `m${++n}`
      sent.push({ channelId, payload, id })
      messages.set(id, payload)
      return id
    },
    async edit(channelId, messageId, payload) {
      if (!messages.has(messageId)) throw new MessageGone('gone')
      if (fail.edit) throw new Error('Service Unavailable')
      edits.push({ channelId, messageId, payload })
      messages.set(messageId, { ...messages.get(messageId)!, ...payload })
    },
    async dm(userId, payload) {
      if (fail.dm) throw new Error('Cannot send messages to this user')
      dms.push({ userId, payload })
    },
  }
  return { port, sent, edits, dms, messages, fail, state }
}

export async function tempDir(prefix = 'nethersec-'): Promise<string> {
  return mkdtemp(path.join(tmpdir(), prefix))
}

/** A hub with a fake Discord, a keys file and a store that is set up. */
export async function makeHub(opts: { keys?: string[]; setup?: boolean; now?: () => number } = {}) {
  const dir = await tempDir()
  const store = await Store.open(dir, 60)
  if (opts.setup !== false) store.state.setup = { ...SETUP }
  const discord = fakePort()
  const now = opts.now ?? Date.now
  const logs: string[] = []
  const log = (m: string) => logs.push(m)
  if (opts.keys) await writeFile(path.join(dir, KEYS_FILE), opts.keys.join('\n') + '\n', 'utf8')
  const keys = new KeyRing(path.join(dir, KEYS_FILE), { log, minCheckMs: 0 })
  const ops = new OpsCards({ store, port: discord.port, guildId: GUILD, now: () => new Date(now()), log })
  const reports = new ReportHandler({ store, keys, ops, port: discord.port, limiter: new RateLimiter(now), now, log })
  return { dir, store, discord, keys, ops, reports, logs }
}

/** A keys.txt line for a key made with fakeKey(seed). */
export function keyLineFor(source: string, seed: string, flag = ''): string {
  return `${source} ${sha256(fakeKey(seed)).toString('hex')}${flag ? ` ${flag}` : ''}`
}

export function auth(seed: string): string {
  return `Bearer ${fakeKey(seed)}`
}

export const titles = (sent: Array<{ channelId: string; payload: Payload }>) => sent.map((s) => `${s.channelId}: ${s.payload.embeds[0]?.title}`)
