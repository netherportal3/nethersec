/**
 * Report keys: `<DATA_DIR>/keys.txt`, one key per line:
 *
 *   <source> <sha256 hex of the key> [page | dm=<Discord user id>]
 *
 * `#` starts a comment. The hub keeps only the hashes, so a copy of its files
 * cannot send reports. A line that breaks a rule is refused (never trusted)
 * and logged by its line number only: never the hash or the user id.
 *
 * The ring checks the file at most once a second and reloads it when it
 * changed, so `key new` and `key revoke` (another process) take effect without
 * a restart. A file that cannot be read means no keys at all, so a revoked key
 * never comes back because of a read error.
 */
import { createHash, timingSafeEqual } from 'node:crypto'
import { readFile, rename, stat, writeFile, chmod } from 'node:fs/promises'
import { SOURCE_RE } from './protocol.js'

export const KEYS_FILE = 'keys.txt'
const HASH_RE = /^[0-9a-f]{64}$/
const DM_ID_RE = /^\d{17,20}$/

export interface Key {
  source: string
  /** 32 bytes. */
  hash: Buffer
  page: boolean
  /** Reports go to this Discord user by DM and nowhere else. Never logged. */
  dmUserId: string | null
  line: number
}

export interface Refusal {
  line: number
  reason: string
}

export interface ParsedKeys {
  keys: Key[]
  refused: Refusal[]
}

/** The flag part of a line, or why it is refused. */
function parseFlags(tokens: string[]): { page: boolean; dmUserId: string | null } | string {
  let page = false
  let dm: string | null = null
  for (const t of tokens) {
    if (t === 'page') {
      if (page) return 'page is listed twice'
      page = true
    } else if (t.startsWith('dm=')) {
      if (dm !== null) return 'dm= is listed twice'
      dm = t.slice(3)
    } else {
      return 'unknown flag (use page or dm=<Discord user id>)'
    }
  }
  if (page && dm !== null) return 'page and dm= cannot be combined'
  if (dm !== null && !DM_ID_RE.test(dm)) return 'dm= needs a Discord user ID (17 to 20 digits)'
  return { page, dmUserId: dm }
}

/** The text of a line without its comment. */
function stripComment(line: string): string {
  const at = line.indexOf('#')
  return (at >= 0 ? line.slice(0, at) : line).trim()
}

export function parseKeysFile(text: string): ParsedKeys {
  const keys: Key[] = []
  const refused: Refusal[] = []
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const body = stripComment(lines[i])
    if (!body) continue
    const line = i + 1
    const tokens = body.split(/\s+/)
    if (tokens.length < 2) {
      refused.push({ line, reason: 'expected <source> <sha256> [page | dm=<id>]' })
      continue
    }
    const [source, hashRaw, ...flagTokens] = tokens
    if (!SOURCE_RE.test(source)) {
      refused.push({ line, reason: 'the source must be lowercase letters, digits or dashes (at most 40)' })
      continue
    }
    const hash = hashRaw.toLowerCase()
    if (!HASH_RE.test(hash)) {
      refused.push({ line, reason: 'the hash is not 64 hex characters (a SHA-256)' })
      continue
    }
    const flags = parseFlags(flagTokens)
    if (typeof flags === 'string') {
      refused.push({ line, reason: flags })
      continue
    }
    keys.push({ source, hash: Buffer.from(hash, 'hex'), page: flags.page, dmUserId: flags.dmUserId, line })
  }
  // One key, one line. With a hash listed twice, the first line would decide
  // where its reports go, so every line with that hash is refused until fixed.
  const count = new Map<string, number>()
  for (const k of keys) count.set(k.hash.toString('hex'), (count.get(k.hash.toString('hex')) ?? 0) + 1)
  const unique: Key[] = []
  for (const k of keys) {
    if ((count.get(k.hash.toString('hex')) ?? 0) > 1) refused.push({ line: k.line, reason: 'the same key is listed on more than one line' })
    else unique.push(k)
  }
  refused.sort((a, b) => a.line - b.line)
  return { keys: unique, refused }
}

export function sha256(text: string): Buffer {
  return createHash('sha256').update(text, 'utf8').digest()
}

/**
 * The key a bearer token belongs to, or null. Compares the token's SHA-256 with
 * every key in constant time and never stops early, so the timing tells
 * nothing about which keys exist.
 */
export function matchKey(token: string, keys: Key[]): Key | null {
  const presented = sha256(token)
  let found: Key | null = null
  for (const k of keys) {
    if (timingSafeEqual(presented, k.hash) && !found) found = k
  }
  return found
}

/** The token from an `Authorization: Bearer <token>` header, or null. */
export function bearer(header: string | undefined): string | null {
  if (!header) return null
  const m = /^Bearer[ ]+(\S{1,512})$/.exec(header.trim())
  return m ? m[1] : null
}

export class KeyRing {
  private keys: Key[] = []
  private signature = ''
  private checkedAt = -Infinity
  private loading: Promise<void> | null = null
  private readonly log: (msg: string) => void
  private readonly now: () => number
  private readonly minCheckMs: number

  constructor(
    private readonly file: string,
    opts: { log?: (msg: string) => void; now?: () => number; minCheckMs?: number } = {},
  ) {
    this.log = opts.log ?? (() => {})
    this.now = opts.now ?? Date.now
    this.minCheckMs = opts.minCheckMs ?? 1_000
  }

  /** The current keys, reloading the file first when it changed. */
  async current(): Promise<Key[]> {
    if (this.now() - this.checkedAt >= this.minCheckMs) {
      if (!this.loading) {
        this.loading = this.reload().finally(() => {
          this.loading = null
        })
      }
      await this.loading
    }
    return this.keys
  }

  async match(header: string | undefined): Promise<Key | null> {
    const token = bearer(header)
    if (!token) return null
    return matchKey(token, await this.current())
  }

  private async reload(): Promise<void> {
    this.checkedAt = this.now()
    let sig: string
    try {
      const s = await stat(this.file)
      sig = `${s.ino}:${s.size}:${s.mtimeMs}`
    } catch (err: any) {
      sig = err?.code === 'ENOENT' ? 'missing' : 'unreadable'
    }
    if (sig === this.signature) return
    this.signature = sig
    if (sig === 'missing') {
      this.keys = []
      this.log(`No ${KEYS_FILE} yet, so no source can report. Make a key with: node dist/cli.js key new <source>`)
      return
    }
    let text: string
    try {
      text = await readFile(this.file, 'utf8')
    } catch {
      this.keys = []
      this.log(`${KEYS_FILE} could not be read, so no source can report until it can.`)
      return
    }
    const parsed = parseKeysFile(text)
    for (const r of parsed.refused) this.log(`${KEYS_FILE} line ${r.line}: refused, ${r.reason}.`)
    this.keys = parsed.keys
    const sources = new Set(parsed.keys.map((k) => k.source)).size
    this.log(`Loaded ${parsed.keys.length} ${parsed.keys.length === 1 ? 'key' : 'keys'} for ${sources} ${sources === 1 ? 'source' : 'sources'} from ${KEYS_FILE}.`)
  }
}

// ---- editing the file (the CLI) ------------------------------------------------

const HEADER = [
  '# nethersec hub report keys. One per line:',
  '#   <source> <sha256 of the key> [page | dm=<Discord user id>]',
  '# Manage them with `node dist/cli.js key ...`. The hub reloads this file when it changes.',
  '',
].join('\n')

export async function readKeysText(file: string): Promise<string> {
  try {
    return await readFile(file, 'utf8')
  } catch (err: any) {
    if (err?.code === 'ENOENT') return ''
    throw err
  }
}

/** Write the whole file: a temp file renamed over the old one, readable by its owner only. */
export async function writeKeysText(file: string, text: string): Promise<void> {
  const tmp = `${file}.tmp`
  await writeFile(tmp, text, { encoding: 'utf8', mode: 0o600 })
  await chmod(tmp, 0o600).catch(() => {})
  await rename(tmp, file)
}

export function keyLine(source: string, hashHex: string, flags: { page?: boolean; dmUserId?: string | null }, comment: string): string {
  const flag = flags.page ? ' page' : flags.dmUserId ? ` dm=${flags.dmUserId}` : ''
  return `${source} ${hashHex}${flag} # ${comment}`
}

/** The file with one more line. */
export function appendKeyLine(text: string, line: string): string {
  const base = text.trim() ? (text.endsWith('\n') ? text : `${text}\n`) : HEADER
  return `${base}${line}\n`
}

/**
 * The file without the keys of `source` (or only the one whose hash starts
 * with `hashPrefix`). Comments and other lines stay as they are.
 */
export function removeKeyLines(text: string, source: string, hashPrefix?: string): { text: string; removed: number } {
  let removed = 0
  const out: string[] = []
  for (const line of text.split('\n')) {
    const tokens = stripComment(line).split(/\s+/)
    const match = tokens[0] === source && tokens.length >= 2 && (!hashPrefix || tokens[1].toLowerCase().startsWith(hashPrefix.toLowerCase()))
    if (match) removed++
    else out.push(line)
  }
  return { text: out.join('\n'), removed }
}

export function isSha256Hex(s: string): boolean {
  return HASH_RE.test(s.toLowerCase())
}

export function isDmUserId(s: string): boolean {
  return DM_ID_RE.test(s)
}
