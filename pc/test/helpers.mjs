// Shared pieces for the scan tests: temp folders, mocked probes and fetch, and a
// stand-in for Windows PowerShell's DPAPI, so every test runs on any OS and no test
// ever starts a real Windows program. Keys and webhook URLs are built from pieces at
// runtime; none is real.
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import assert from 'node:assert/strict'
import * as lib from '../pc-security-lib.mjs'
import { runReport, SECRET_FILE } from '../pc-security-run.mjs'

export const NOW = Date.parse('2025-03-27T12:00:00Z')
export const DAY = lib.DAY
export const KEY = 'cd'.repeat(32)
export const WEBHOOK = ['https://discord.com/api/webhooks', '123456789012345678', `fake_${'y'.repeat(60)}`].join('/')

// ---------------------------------------------------------------------------
// A fake DPAPI. "Encrypted" text is tied to an account name, the way DPAPI ties it
// to a Windows account: text made for one account does not decrypt for another.
// It answers exactly as the scanner's PROTECT_PS and UNPROTECT_PS scripts do.
// ---------------------------------------------------------------------------

const accountTag = (user) => createHash('sha256').update(`account:${user}`).digest('hex').slice(0, 16)

/** Encrypt for `user` (fake). */
export function protect(plain, user = 'alice') {
  const body = Buffer.from(Buffer.from(plain, 'utf8').map((b) => b ^ 0x5a))
  return `0000feed${accountTag(user)}${body.toString('hex')}`
}

/** Decrypt as `user` (fake). Null when the text was made for another account or is damaged. */
export function unprotect(text, user = 'alice') {
  const head = `0000feed${accountTag(user)}`
  const hex = String(text).trim()
  if (!hex.startsWith(head) || !/^([0-9a-f]{2})+$/.test(hex.slice(head.length))) return null
  return Buffer.from(Buffer.from(hex.slice(head.length), 'hex').map((b) => b ^ 0x5a)).toString('utf8')
}

/** The script inside a powershell.exe -EncodedCommand argument list. */
export function decodePs(args) {
  const i = args.indexOf('-EncodedCommand')
  return i >= 0 ? Buffer.from(args[i + 1], 'base64').toString('utf16le') : ''
}

/**
 * A program runner with run()'s shape, for the scanner's `exec` dependency. It plays
 * powershell.exe for the two DPAPI scripts and records every call. Set `down` to an
 * error (such as 'timed out') to make PowerShell give no answer, `failProtect` to
 * make encryption fail, or `protectAs` to encrypt for another account by mistake.
 * @param {{ user?: string }} [opts]
 */
export function fakeDpapi({ user = 'alice' } = {}) {
  const calls = []
  const answer = (o) => ({ error: null, stdout: `${JSON.stringify(o)}\r\n`, stderr: '' })
  const exec = async (file, args, opts = {}) => {
    const script = file === 'powershell.exe' ? decodePs(args) : ''
    const kind = script.includes('ProtectedData]::Protect(') ? 'protect' : script.includes('ProtectedData]::Unprotect(') ? 'unprotect' : 'other'
    calls.push({ file, args, env: opts.env, input: opts.input, script, kind })
    if (exec.down) return { error: exec.down, stdout: '', stderr: '' }
    const input = String(opts.input ?? '').trim()
    if (kind === 'protect') {
      if (exec.failProtect) return { error: 'exit code 1', stdout: '', stderr: 'something went wrong' }
      return answer({ protected: protect(input, exec.protectAs ?? exec.user) })
    }
    if (kind === 'unprotect') {
      const plain = unprotect(input, exec.user)
      if (plain === null) return answer({ error: 'decrypt', hresult: '0x8009000B' })
      // The real script answers with the UTF-16 bytes as upper-case hex, and no newline.
      return { error: null, stdout: `{"secretHex":"${Buffer.from(plain, 'utf16le').toString('hex').toUpperCase()}"}`, stderr: '' }
    }
    return { error: 'not installed', stdout: '', stderr: '' }
  }
  exec.calls = calls
  exec.user = user
  exec.down = ''
  exec.failProtect = false
  exec.protectAs = undefined
  return exec
}

/**
 * Everything about the programs the scanner started that another process on the PC
 * could see: the program, its arguments (and the script they encode) and its
 * environment. stdin is not in it: that is the one way a secret may go in.
 */
export function visible(calls) {
  return JSON.stringify(calls.map((c) => [c.file, c.args, c.script, c.env ?? null]))
}

// ---------------------------------------------------------------------------
// Folders, probes, fetch and a whole scan
// ---------------------------------------------------------------------------

const dirs = []

/** A temp folder with this config.json (object or raw text) and, when given, a secret.dpapi holding `secret` for `user`. */
export function tempDir(config, secret, user = 'alice') {
  const d = mkdtempSync(path.join(tmpdir(), 'nethersec-pc-test-'))
  dirs.push(d)
  if (config !== undefined) writeFileSync(path.join(d, 'config.json'), typeof config === 'string' ? config : JSON.stringify(config, null, 2))
  if (secret !== undefined) writeFileSync(path.join(d, SECRET_FILE), `${protect(secret, user)}\n`)
  return d
}

export function removeTempDirs() {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
}

/** A file in a temp folder as text, or '' when it is not there. */
export function readIn(dir, file) {
  const f = path.join(dir, file)
  return existsSync(f) ? readFileSync(f, 'utf8') : ''
}

export const hubConfig = (over = {}) => ({ delivery: 'hub', hubUrl: 'https://hub.example.com', source: 'pc', kev: { enabled: false }, ...over })

/** Mocked probes: a healthy PC, with the firewall or Defender turned off on request. */
export function probes({ firewallOff = false, defenderOff = false, kev = null } = {}) {
  const table = 'No available upgrade found.'
  const read = { ...lib.parseWingetTable(table), ok: true, errors: [] }
  return {
    quick: async () => ({
      data: {
        os: { product: 'Windows 10 Pro', display: '24H2', build: '26100', ubr: '1000' },
        defender: {
          amServiceEnabled: true,
          antivirusEnabled: true,
          realTimeProtectionEnabled: !defenderOff,
          runningMode: 'Normal',
          signatureLastUpdated: new Date(NOW - DAY).toISOString(),
          signatureAgeDays: 1,
          signatureVersion: '1.400.7',
        },
        firewall: {
          profiles: [
            { name: 'Domain', enabled: 'True' },
            { name: 'Private', enabled: 'True' },
            { name: 'Public', enabled: firewallOff ? 'False' : 'True' },
          ],
        },
        reboot: { pending: false, sources: [] },
        pause: { until: '', quality: '' },
      },
    }),
    windowsUpdate: async () => ({ data: { resultCode: 2, updates: [] } }),
    winget: async () => ({ upgrade: read, list: read }),
    wsl: async () => ({ enabled: false }),
    runtimes: async () => ({ node: null, go: null, java: null }),
    kev: async () => kev ?? { data: { catalogVersion: 'test', vulnerabilities: [] }, from: 'network' },
  }
}

/** A fetch that records every call and answers with the given statuses in turn. */
export function fakeFetch(...statuses) {
  const calls = []
  const fn = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) })
    const status = statuses.length > 1 ? statuses.shift() : statuses[0]
    if (status === 'throw') throw new TypeError('fetch failed')
    return new Response(status === 204 ? null : '{}', { status })
  }
  fn.calls = calls
  return fn
}

/** One whole scan in `dir`, with a fake DPAPI unless the test passes its own `exec`. */
export async function scan(dir, { args = [], ...deps } = {}) {
  const out = []
  const exec = deps.exec ?? fakeDpapi()
  await runReport(
    { dir, dryRun: false, ignoreGrace: false, json: false, ...Object.fromEntries(args.map((a) => [a, true])) },
    { now: () => NOW, log: (s) => out.push(s), ...deps, exec },
  )
  const state = readIn(dir, 'state.json')
  return { out: out.join('\n'), state: state ? JSON.parse(state) : null, lastRunText: readIn(dir, 'last-run.json'), exec }
}

export function partial(actual, subset) {
  assert.ok(actual && typeof actual === 'object', `expected an object, got ${actual}`)
  for (const [k, v] of Object.entries(subset)) assert.deepEqual(actual[k], v, `field ${k}`)
}
