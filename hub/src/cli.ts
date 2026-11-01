/**
 * The hub's command line: report keys.
 *
 *   node dist/cli.js key new <source> [--page | --dm <Discord user id>]
 *   node dist/cli.js key add <source> <sha256> [--page | --dm <Discord user id>]
 *   node dist/cli.js key list
 *   node dist/cli.js key revoke <source> [<hash prefix>]
 *
 * `key new` prints the new key on stdout, once, and nothing else there, so
 * `KEY=$(node dist/cli.js key new web1)` works. Everything else goes to stderr.
 * The hub stores only the SHA-256 of a key; `key add` takes a hash made on the
 * box (`printf %s "$KEY" | sha256sum`), so the key itself never leaves it.
 *
 * Reads DATA_DIR (default ./data). In Docker: docker compose exec hub node dist/cli.js key ...
 */
import { randomBytes } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  KEYS_FILE,
  appendKeyLine,
  isDmUserId,
  isSha256Hex,
  keyLine,
  parseKeysFile,
  readKeysText,
  removeKeyLines,
  sha256,
  writeKeysText,
} from './reports/keys.js'
import { SOURCE_RE } from './reports/protocol.js'

export interface CliIo {
  out: (line: string) => void
  err: (line: string) => void
  env: NodeJS.ProcessEnv
  now?: () => Date
}

const USAGE = [
  'Usage:',
  '  key new <source> [--page | --dm <Discord user id>]   make a key, print it once, store its hash',
  '  key add <source> <sha256> [--page | --dm <id>]       store the hash of a key made elsewhere',
  '  key list                                             sources, flags and short hashes',
  '  key revoke <source> [<hash prefix>]                  remove the keys of a source (or one of them)',
  '',
  '--page: a critical report from this source pings the watcher role. For servers.',
  '--dm:   reports from this source go only to that person, by direct message. For a personal PC.',
].join('\n')

function flagsFrom(args: string[]): { page: boolean; dmUserId: string | null; rest: string[] } | string {
  let page = false
  let dmUserId: string | null = null
  const rest: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--page') page = true
    else if (a === '--dm') {
      const id = args[++i]
      if (!id || !isDmUserId(id)) return '--dm needs a Discord user ID (17 to 20 digits). Turn on Developer Mode in Discord, then right-click the user > Copy User ID.'
      dmUserId = id
    } else if (a.startsWith('--')) return `Unknown option ${a}.`
    else rest.push(a)
  }
  if (page && dmUserId) return '--page and --dm cannot be combined: a dm source never pings anyone.'
  return { page, dmUserId, rest }
}

export async function runCli(argv: string[], io: CliIo): Promise<number> {
  const [group, cmd, ...args] = argv
  if (group !== 'key' || !cmd || cmd === 'help' || cmd === '--help') {
    io.err(USAGE)
    return group === 'key' && (cmd === 'help' || cmd === '--help') ? 0 : 2
  }
  const dataDir = (io.env.DATA_DIR ?? '').trim() || './data'
  const file = path.join(dataDir, KEYS_FILE)
  const now = (io.now ?? (() => new Date()))()
  const flags = flagsFrom(args)
  if (typeof flags === 'string') {
    io.err(flags)
    return 2
  }
  const [source, second] = flags.rest

  if (cmd === 'list') {
    const text = await readKeysText(file)
    const parsed = parseKeysFile(text)
    if (!parsed.keys.length && !parsed.refused.length) {
      io.err(`No keys in ${file}. Make one with: key new <source>`)
      return 0
    }
    for (const k of parsed.keys) {
      const flag = k.page ? 'page' : k.dmUserId ? 'dm' : '-'
      io.out(`${k.source}\t${flag}\t${k.hash.toString('hex').slice(0, 12)}`)
    }
    for (const r of parsed.refused) io.err(`line ${r.line}: refused, ${r.reason}`)
    return 0
  }

  if (cmd !== 'new' && cmd !== 'add' && cmd !== 'revoke') {
    io.err(`Unknown command: key ${cmd}\n\n${USAGE}`)
    return 2
  }
  if (!source || !SOURCE_RE.test(source)) {
    io.err('Give a source: 1 to 40 lowercase letters, digits or dashes, like web1.')
    return 2
  }

  await mkdir(dataDir, { recursive: true })
  const text = await readKeysText(file)

  if (cmd === 'revoke') {
    if (flags.page || flags.dmUserId) {
      io.err('key revoke takes no flags.')
      return 2
    }
    if (second && !/^[0-9a-fA-F]{6,64}$/.test(second)) {
      io.err('The hash prefix must be at least 6 hex characters (see key list).')
      return 2
    }
    const { text: next, removed } = removeKeyLines(text, source, second)
    if (!removed) {
      io.err(`No key for ${source}${second ? ` starting with ${second}` : ''} in ${file}.`)
      return 1
    }
    await writeKeysText(file, next)
    io.err(`Revoked ${removed} ${removed === 1 ? 'key' : 'keys'} for ${source}. The hub stops taking ${removed === 1 ? 'it' : 'them'} within a second or two.`)
    return 0
  }

  let hashHex: string
  let key: string | null = null
  if (cmd === 'new') {
    if (second) {
      io.err('key new takes only a source (and --page or --dm <id>).')
      return 2
    }
    key = randomBytes(32).toString('hex')
    hashHex = sha256(key).toString('hex')
  } else {
    if (!second || !isSha256Hex(second)) {
      io.err('key add needs the SHA-256 of the key: 64 hex characters (printf %s "$KEY" | sha256sum).')
      return 2
    }
    hashHex = second.toLowerCase()
    if (parseKeysFile(text).keys.some((k) => k.hash.toString('hex') === hashHex)) {
      io.err('That key is already listed.')
      return 1
    }
  }

  const others = parseKeysFile(text).keys.filter((k) => k.source === source).length
  const line = keyLine(source, hashHex, flags, `added ${now.toISOString().slice(0, 10)}`)
  await writeKeysText(file, appendKeyLine(text, line))
  if (key) io.out(key)
  const how = flags.page ? ' Its critical reports ping the watcher role.' : flags.dmUserId ? ' Its reports go to that person by direct message only.' : ''
  io.err(`${cmd === 'new' ? 'Made' : 'Added'} a key for ${source} in ${file}.${how}`)
  if (key) io.err('Copy the key now: it is not shown again. Store it on the box in a file only its owner can read (mode 600).')
  if (others) io.err(`${source} now has ${others + 1} keys. Once the box uses the new one, remove the old one with: key revoke ${source} <hash prefix> (see key list).`)
  return 0
}

/** True when this file is the program being run (not imported by a test). */
function isMain(): boolean {
  const arg = process.argv[1]
  return !!arg && import.meta.url === pathToFileURL(path.resolve(arg)).href
}

if (isMain()) {
  runCli(process.argv.slice(2), { out: (l) => process.stdout.write(`${l}\n`), err: (l) => process.stderr.write(`${l}\n`), env: process.env })
    .then((code) => {
      process.exitCode = code
    })
    .catch((err) => {
      process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`)
      process.exitCode = 1
    })
}
