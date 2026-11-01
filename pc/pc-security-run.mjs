// The nethersec PC scanner's probes, glue and sending. pc-security-report.mjs (the
// file the scheduled task runs) only calls cli() from here. A scheduled task runs it
// every 6 hours and at logon. It reads Windows Update, Defender, the firewall, winget,
// Node/Go/Java, WSL and CISA's Known Exploited Vulnerabilities list, and sends a
// report to the nethersec hub or a Discord webhook only when something changes
// (see docs/pc/README.md).
//
// Node built-ins only: it runs from a copy in %USERPROFILE%\.nethersec-pc with no
// node_modules. All decisions live in pc-security-lib.mjs; this file only probes,
// glues and sends. It never installs, upgrades or removes anything. The one write
// outside its own folder is the WSL check refreshing a running distro's apt lists.
// runReport() takes its probes and fetch as arguments, so the tests can run a whole
// scan on any OS with mocked Windows commands.
//
// The whole run stays inside a time budget (14 minutes for the checks, 18 for the
// reports), under the scheduled task's 20-minute limit: a check that has no time
// left is skipped as unreadable, and a child that runs too long is killed with its
// whole process tree.
//
// The key and the webhook URL live in secret.dpapi, encrypted with DPAPI for the
// current Windows account, never in config.json. A PowerShell child decrypts it with
// the encrypted text on stdin and hands the plain text back on its stdout. Neither is
// ever printed, written to last-run.json, put in the environment or passed on a
// command line.

import { spawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as lib from './pc-security-lib.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SCANNER_VERSION = 1

const URLS = {
  nodeIndex: 'https://nodejs.org/dist/index.json',
  nodeEol: 'https://endoflife.date/api/nodejs.json',
  go: 'https://go.dev/dl/?mode=json&include=all',
  azul: (major) =>
    `https://api.azul.com/metadata/v1/zulu/packages/?java_version=${major}&os=windows&arch=x64&java_package_type=jdk&latest=true&release_status=ga`,
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
}

const DEFAULT_CONFIG = {
  delivery: 'hub',
  hubUrl: '',
  source: 'pc',
  disabled: false,
  checkBudgetMinutes: 14,
  reportBudgetMinutes: 18,
  wsl: { enabled: true, startStopped: false, skip: ['^docker-desktop'] },
  runtimes: { node: true, go: true, java: true },
  kev: { enabled: true },
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

export function parseArgs(argv) {
  const out = { dryRun: false, ignoreGrace: false, json: false, help: false, newKey: false, setWebhook: false }
  const named = { '--dir': 'dir', '--config': 'config', '--watch': 'watch', '--state': 'state', '--dm': 'dm', '--hub-url': 'hubUrl' }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--dry-run') out.dryRun = true
    else if (a === '--ignore-grace') out.ignoreGrace = true
    else if (a === '--json') out.json = true
    else if (a === '--help' || a === '-h') out.help = true
    else if (a === '--new-key') out.newKey = true
    else if (a === '--set-webhook') out.setWebhook = true
    else if (named[a]) {
      const v = argv[++i]
      if (v === undefined || v.startsWith('--')) throw new Error(`${a} needs a value`)
      out[named[a]] = v
    } else throw new Error(`unknown option: ${a}`)
  }
  return out
}

function readJson(file) {
  try {
    return { data: JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, '')) }
  } catch (e) {
    if (e && e.code === 'ENOENT') return { error: 'missing' }
    // A JSON error message can quote the text around the mistake. For config.json
    // that text can be the key or the webhook URL, so callers that print the error
    // use `safeError`: the line and column only.
    const where = /line \d+ column \d+|position \d+/.exec(String(e && e.message))
    const safeError =
      e instanceof SyntaxError
        ? `${path.basename(file)} is not valid JSON${where ? ` (${where[0]})` : ''}`
        : `${path.basename(file)} could not be opened (${(e && e.code) || 'error'})`
    return { error: `${path.basename(file)}: ${e && e.message ? e.message : e}`, safeError }
  }
}

function writeTextAtomic(file, text) {
  mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.tmp`
  writeFileSync(tmp, text)
  renameSync(tmp, file)
}

function writeJsonAtomic(file, data) {
  writeTextAtomic(file, JSON.stringify(data, null, 2))
}

function firstLine(s) {
  return String(s ?? '').split(/\r?\n/).map((l) => l.trim()).find(Boolean) ?? ''
}

/** Kill a child and everything it started. */
function killTree(child) {
  if (!child || !child.pid) return
  if (process.platform === 'win32') {
    try {
      spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }).on('error', () => {})
    } catch {}
  } else {
    try {
      child.kill('SIGKILL')
    } catch {}
  }
}

const MAX_OUTPUT = 64 * 1024 * 1024

/**
 * Run a program without a shell or a window. Never throws. Stops at `timeoutMs`
 * or at `deadline` (whichever comes first) by killing the process tree; with less
 * than 3 seconds left it does not start at all ("out of time"). `input`, when given,
 * is written to the child's stdin (the only way a secret ever reaches a child).
 */
function run(file, args, { timeoutMs = 120_000, deadline = Infinity, env, cwd, input } = {}) {
  return new Promise((resolve) => {
    const limit = lib.probeTimeout(timeoutMs, deadline, Date.now())
    if (!limit) {
      resolve({ error: 'out of time', stdout: '', stderr: '' })
      return
    }
    let done = false
    const out = []
    const err = []
    let size = 0
    let timedOut = false
    const finish = (error) => {
      if (done) return
      done = true
      clearTimeout(timer)
      clearTimeout(backstop)
      resolve({ error, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') })
    }
    let child
    try {
      child = spawn(file, args, {
        windowsHide: true,
        stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
        env: env ? { ...process.env, ...env } : process.env,
        cwd,
      })
    } catch (e) {
      resolve({ error: e && e.code === 'ENOENT' ? 'not installed' : 'could not start', stdout: '', stderr: '' })
      return
    }
    if (input !== undefined) {
      // A child that exits without reading must not crash the scan (EPIPE).
      child.stdin.on('error', () => {})
      child.stdin.end(input)
    }
    const keep = (list) => (d) => {
      if (size < MAX_OUTPUT) {
        list.push(d)
        size += d.length
      }
    }
    child.stdout.on('data', keep(out))
    child.stderr.on('data', keep(err))
    const timer = setTimeout(() => {
      timedOut = true
      killTree(child)
    }, limit)
    // If the kill does not bring a close event, give up waiting anyway.
    const backstop = setTimeout(() => finish('timed out'), limit + 15_000)
    child.on('error', (e) => finish(e && e.code === 'ENOENT' ? 'not installed' : 'could not start'))
    child.on('close', (code) => finish(timedOut ? 'timed out' : code === 0 ? null : `exit code ${code}`))
  })
}

// ---------------------------------------------------------------------------
// PowerShell probes (Windows PowerShell 5.1). Scripts go in as -EncodedCommand
// so no quoting can break them; output is one line of ASCII-only JSON.
// ---------------------------------------------------------------------------

const PS_PRELUDE = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Out-Json($o) {
  $j = ConvertTo-Json -InputObject $o -Depth 6 -Compress
  [regex]::Replace($j, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
}
`

function psArgs(script) {
  const encoded = Buffer.from(PS_PRELUDE + script, 'utf16le').toString('base64')
  return ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]
}

async function runPowerShell(script, timeoutMs, ctx) {
  const r = await run('powershell.exe', psArgs(script), { timeoutMs, deadline: ctx.deadline, cwd: ctx.cwd })
  const line = r.stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('{'))
    .pop()
  if (!line || r.error === 'timed out') return { error: r.error || firstLine(r.stderr).slice(0, 160) || 'no output' }
  try {
    return { data: JSON.parse(line) }
  } catch {
    return { error: 'output was not JSON' }
  }
}

const QUICK_PS = String.raw`
$r = [ordered]@{}
try {
  $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $r.os = [ordered]@{ product = [string]$cv.ProductName; display = [string]$cv.DisplayVersion; build = [string]$cv.CurrentBuild; ubr = [string]$cv.UBR }
} catch { $r.os = [ordered]@{ error = $_.Exception.Message } }
try {
  $s = Get-MpComputerStatus
  $sig = $null
  if ($s.AntivirusSignatureLastUpdated) { $sig = $s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') }
  $r.defender = [ordered]@{
    amServiceEnabled = [bool]$s.AMServiceEnabled
    antivirusEnabled = [bool]$s.AntivirusEnabled
    realTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
    runningMode = [string]$s.AMRunningMode
    signatureLastUpdated = $sig
    signatureAgeDays = [int]$s.AntivirusSignatureAge
    signatureVersion = [string]$s.AntivirusSignatureVersion
  }
} catch { $r.defender = [ordered]@{ error = $_.Exception.Message } }
try {
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [pscustomobject][ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled } })
  $r.firewall = [ordered]@{ profiles = $profiles }
} catch { $r.firewall = [ordered]@{ error = $_.Exception.Message } }
try {
  $why = @()
  if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $why += 'Windows Update' }
  if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $why += 'component servicing' }
  $r.reboot = [ordered]@{ pending = ($why.Count -gt 0); sources = $why }
} catch { $r.reboot = [ordered]@{ error = $_.Exception.Message } }
try {
  $ux = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue
  $r.pause = [ordered]@{ until = [string]$ux.PauseUpdatesExpiryTime; quality = [string]$ux.PauseQualityUpdatesEndTime }
} catch { $r.pause = [ordered]@{ error = $_.Exception.Message } }
Out-Json $r
`

const WU_PS = String.raw`
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'nethersec-pc'
  $searcher = $session.CreateUpdateSearcher()
  $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $list = @()
  foreach ($u in $res.Updates) {
    $cats = @(); foreach ($c in $u.Categories) { $cats += [string]$c.Name }
    $kbs = @(); foreach ($k in $u.KBArticleIDs) { $kbs += [string]$k }
    $rel = $null
    try { $rel = $u.LastDeploymentChangeTime.ToUniversalTime().ToString('o') } catch {}
    $list += [pscustomobject][ordered]@{ title = [string]$u.Title; kb = $kbs; severity = [string]$u.MsrcSeverity; categories = $cats; released = $rel; rebootRequired = [bool]$u.RebootRequired }
  }
  Out-Json ([ordered]@{ resultCode = [int]$res.ResultCode; updates = $list })
} catch {
  Out-Json ([ordered]@{ error = $_.Exception.Message; hresult = ('0x{0:X8}' -f $_.Exception.HResult) })
}
`

// ---------------------------------------------------------------------------
// Other probes
// ---------------------------------------------------------------------------

const WINGET_FLAGS = ['--accept-source-agreements', '--disable-interactivity']

/** winget upgrade and winget list. `runner` is run(), or a test's stand-in. */
export async function probeWinget(ctx, runner = run) {
  const up = await runner('winget.exe', ['upgrade', '--include-unknown', '--include-pinned', ...WINGET_FLAGS], {
    timeoutMs: 300_000,
    deadline: ctx.deadline,
    cwd: ctx.cwd,
  })
  const upgrade = lib.parseWingetTable(up.stdout)
  const upOk = lib.wingetReadable(upgrade, up.error, { expectFooter: true })
  const ls = await runner('winget.exe', ['list', ...WINGET_FLAGS], { timeoutMs: 300_000, deadline: ctx.deadline, cwd: ctx.cwd })
  const list = lib.parseWingetTable(ls.stdout)
  const lsOk = lib.wingetReadable(list, ls.error)
  return {
    upgrade: { ...upgrade, ok: upOk.ok, errors: upOk.ok ? upgrade.errors : [upOk.reason, ...upgrade.errors] },
    list: { ...list, ok: lsOk.ok, errors: lsOk.ok ? list.errors : [lsOk.reason, ...list.errors] },
  }
}

/** The apt check run inside a distro. The Linux side stops itself before the Windows side kills wsl.exe. */
function wslAptScript(seconds) {
  return (
    'if ! command -v apt-get >/dev/null 2>&1; then echo NETHERSEC_NOAPT; exit 0; fi; ' +
    `if command -v timeout >/dev/null 2>&1; then set -- timeout -k 10 ${seconds}; else set --; fi; ` +
    'export DEBIAN_FRONTEND=noninteractive LC_ALL=C; ' +
    '$@ apt-get update -qq >/dev/null 2>&1; echo NETHERSEC_UPDATE_RC=$?; ' +
    '$@ apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null; echo NETHERSEC_SIM_RC=$?'
  )
}

/** `wsl.exe -l -v`: the distros and their states. Listing starts no distro. */
async function listWsl(ctx, runner) {
  const listed = await runner('wsl.exe', ['-l', '-v'], { timeoutMs: 60_000, deadline: ctx.deadline, env: { WSL_UTF8: '1' }, cwd: ctx.cwd })
  const text = listed.stdout.replace(/\u0000/g, '')
  return { error: listed.error, none: /no installed distributions/i.test(text), distros: lib.parseWslList(text) }
}

/**
 * The WSL check. The distros are listed once to plan the run, and again right before
 * each one is checked: one that stopped in the meantime is left alone with its last
 * result, since `wsl.exe -d` would start it (unless wsl.startStopped is set). A distro
 * can still stop in the moment between that second look and the check. `runner` is
 * run(), or a test's stand-in.
 */
export async function probeWsl(ctx, state, config, wslSkip, runner = run) {
  if (config.wsl?.enabled === false) return { enabled: false }
  if (!wslSkip) return { enabled: true, ok: false, error: 'wsl.skip in config.json has a pattern that is not valid' }
  const listed = await listWsl(ctx, runner)
  if (listed.none) return { enabled: true, ok: true, distros: [], plan: [], results: [] }
  if (listed.error === 'not installed') return { enabled: true, ok: true, distros: [], plan: [], results: [] }
  const distros = listed.distros
  if (listed.error || !distros.length) return { enabled: true, ok: false, error: listed.error || 'could not list distros' }
  const startStopped = config.wsl?.startStopped === true
  const plan = lib.planWslChecks({
    distros,
    skip: wslSkip,
    startStopped,
    lastCheck: state.wsl?.lastCheck ?? {},
    now: ctx.now,
    intervalMs: (config.wslIntervalHours ?? lib.DEFAULTS.wslIntervalHours) * lib.HOUR,
  })
  const results = []
  const checkedAt = {}
  for (let i = 0; i < plan.length; i++) {
    const p = plan[i]
    if (p.action !== 'check') {
      results.push({ name: p.name, skipped: true })
      continue
    }
    if (!startStopped) {
      const again = await listWsl(ctx, runner)
      if (!again.none && (again.error || !again.distros.length)) {
        results.push({ name: p.name, ok: false, error: 'could not check that it is still running' })
        continue
      }
      const d = again.distros.find((x) => x.name === p.name)
      if (!d || !/^running$/i.test(d.state)) {
        plan[i] = { ...p, action: 'not-running' }
        results.push({ name: p.name, skipped: true })
        continue
      }
    }
    const limit = lib.probeTimeout(300_000, ctx.deadline, Date.now())
    const r = await runner('wsl.exe', ['-d', p.name, '-u', 'root', '--exec', 'sh', '-c', wslAptScript(Math.max(20, Math.floor(limit / 1000) - 20))], {
      timeoutMs: 300_000,
      deadline: ctx.deadline,
      cwd: ctx.cwd,
    })
    const apt = lib.parseAptSimulation(r.stdout)
    if (apt.noApt) {
      results.push({ name: p.name, ok: true, noApt: true })
      checkedAt[p.name] = ctx.now
    } else if (!apt.simOk || r.error === 'timed out' || r.error === 'out of time') {
      results.push({ name: p.name, ok: false, error: r.error || 'apt-get simulation failed' })
    } else {
      results.push({ name: p.name, ok: true, count: apt.count, packages: apt.packages, updateOk: apt.updateOk })
      checkedAt[p.name] = ctx.now
    }
  }
  return { enabled: true, ok: true, distros, plan, results, checkedAt }
}

/** JSON from a feed, cached on disk. A failed fetch falls back to a cache younger than `staleMs`. */
async function fetchJson(ctx, key, url, { maxAgeMs, staleMs, pick = (x) => x, timeoutMs = 30_000 }) {
  const file = path.join(ctx.cacheDir, `${key}.json`)
  const cached = readJson(file).data
  const age = cached && typeof cached.fetchedAt === 'number' ? ctx.now - cached.fetchedAt : Infinity
  if (age < maxAgeMs) return { data: cached.data, from: 'cache' }
  const limit = lib.probeTimeout(timeoutMs, ctx.deadline, Date.now())
  try {
    if (!limit) throw new Error('out of time')
    // Ask for gzip only, so Node never has to decode a Brotli body from the network
    // (a smaller decoder surface for data from outside).
    const res = await fetch(url, {
      signal: AbortSignal.timeout(limit),
      headers: { accept: 'application/json', 'accept-encoding': 'gzip', 'user-agent': 'nethersec-pc-scanner' },
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = pick(await res.json())
    if (!ctx.dryRun) writeJsonAtomic(file, { fetchedAt: ctx.now, url, data })
    return { data, from: 'network' }
  } catch (e) {
    const why = e && e.name === 'TimeoutError' ? 'timed out' : String(e && e.message ? e.message : e).slice(0, 120)
    if (cached && age < staleMs) return { data: cached.data, from: 'old cache', warning: why }
    return { error: `${new URL(url).host}: ${why}` }
  }
}

async function probeRuntimes(ctx, config) {
  const out = { node: null, go: null, java: null }
  const feed = { maxAgeMs: 3 * lib.HOUR, staleMs: 3 * lib.DAY }
  const opts = { timeoutMs: 20_000, deadline: ctx.deadline, cwd: ctx.cwd }

  if (config.runtimes?.node !== false) {
    const where = await run('where.exe', ['node'], opts)
    const paths = [...new Set(where.stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => /node\.exe$/i.test(l)))]
    const installed = []
    for (const p of paths) {
      const v = await run(p, ['--version'], opts)
      if (/^v\d+\.\d+\.\d+/.test(v.stdout.trim())) installed.push(v.stdout.trim().replace(/^v/, ''))
    }
    if (where.error === 'out of time') out.node = { installed: [], error: 'out of time' }
    else if (!installed.length) out.node = { installed: [] }
    else {
      const [index, eol] = await Promise.all([
        fetchJson(ctx, 'node-index', URLS.nodeIndex, {
          ...feed,
          pick: (j) => (Array.isArray(j) ? j.map((r) => ({ version: r.version, date: r.date, lts: r.lts, security: r.security })) : j),
        }),
        fetchJson(ctx, 'node-eol', URLS.nodeEol, feed),
      ])
      out.node = { installed: [...new Set(installed)], index, eol }
    }
  }

  if (config.runtimes?.go !== false) {
    const v = await run('go', ['version'], { ...opts, timeoutMs: 30_000, env: { GOTOOLCHAIN: 'local' } })
    const m = /go version go(\d+\.\d+(?:\.\d+)?)/.exec(v.stdout)
    if (!m) out.go = { installed: null, error: v.error === 'not installed' ? null : v.error }
    else {
      const releases = await fetchJson(ctx, 'go-releases', URLS.go, {
        ...feed,
        pick: (j) => (Array.isArray(j) ? j.map((r) => ({ version: r.version, stable: r.stable })) : j),
      })
      out.go = { installed: m[1], releases }
    }
  }

  if (config.runtimes?.java !== false) {
    const root = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Zulu')
    const installs = []
    let dirs = []
    try {
      dirs = readdirSync(root)
    } catch {}
    for (const d of dirs) {
      const rel = readFileSafe(path.join(root, d, 'release'))
      if (!rel || !/IMPLEMENTOR="Azul/i.test(rel)) continue
      const v = /^JAVA_VERSION="([^"]+)"/m.exec(rel)
      if (v) installs.push({ version: v[1], path: path.join(root, d) })
    }
    const packagesByMajor = {}
    const errors = []
    for (const major of [...new Set(installs.map((i) => lib.parseVersion(i.version).nums[0]))]) {
      const r = await fetchJson(ctx, `azul-${major}`, URLS.azul(major), {
        ...feed,
        pick: (j) => (Array.isArray(j) ? j.map((p) => ({ name: p.name, java_version: p.java_version })) : j),
      })
      if (r.error) errors.push(r.error)
      else packagesByMajor[String(major)] = r.data
    }
    out.java = { installs, packagesByMajor, errors }
  }
  return out
}

function readFileSafe(file) {
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/**
 * config.json, or the example when there is none. A config.json that cannot be read
 * runs the checks with the defaults and sends nothing (the defaults have no key or
 * webhook URL), and its error never quotes the file.
 */
function loadConfig(file) {
  const r = readJson(file)
  const fallback = r.error === 'missing' ? readJson(path.join(HERE, 'config.example.json')).data : null
  const raw = r.data && typeof r.data === 'object' && !Array.isArray(r.data) ? r.data : (fallback ?? {})
  const cfg = { ...lib.DEFAULTS, ...DEFAULT_CONFIG, ...raw }
  cfg.wsl = { ...DEFAULT_CONFIG.wsl, ...(raw.wsl ?? {}) }
  cfg.runtimes = { ...DEFAULT_CONFIG.runtimes, ...(raw.runtimes ?? {}) }
  cfg.kev = { ...DEFAULT_CONFIG.kev, ...(raw.kev ?? {}) }
  const error = r.error && r.error !== 'missing' ? r.safeError : r.data !== undefined && raw !== r.data ? 'config.json is not a JSON object' : null
  return { cfg, error, from: raw === r.data ? file : fallback ? 'config.example.json' : 'defaults' }
}

/**
 * watch.json, or the example when there is none. A file that exists but cannot be
 * read sets `unreadable`: the checks that use it then change nothing.
 */
function loadWatch(file) {
  let from = file
  let text = null
  for (const f of [file, path.join(HERE, 'watch.example.json')]) {
    try {
      text = readFileSync(f, 'utf8')
      from = f === file ? file : 'watch.example.json'
      break
    } catch (e) {
      if (!e || e.code !== 'ENOENT') {
        const why = `could not be opened (${e && e.code ? e.code : 'error'})`
        return { apps: [], eol: [], skipped: [], errors: [`watch list ${why}`], from: f, unreadable: why }
      }
    }
  }
  if (text === null) return { apps: [], eol: [], skipped: [], errors: ['no watch list found'], from, unreadable: 'missing' }
  return { ...lib.parseWatchJson(text), from }
}

// ---------------------------------------------------------------------------
// The key and the webhook URL: secret.dpapi, DPAPI for the current Windows account
// ---------------------------------------------------------------------------

export const SECRET_FILE = 'secret.dpapi'

// DPAPI for the current Windows account: ProtectedData with CurrentUser scope and no
// extra entropy, over the text as UTF-16, written as hex. That is the same format
// ConvertFrom-SecureString writes without -Key. The plain text only ever passes
// through .NET calls, stdin and [Console]::Out, never a PowerShell command's
// parameters or output: PowerShell's module logging records command parameters and
// a transcript records command output, so either would otherwise keep a copy.

// Encrypt. The plain text comes in on stdin; the encrypted hex goes out on stdout.
const PROTECT_PS = String.raw`
try {
  Add-Type -AssemblyName System.Security
  $plain = [Console]::In.ReadToEnd().Trim()
  if ($plain.Length -eq 0) { throw 'nothing on stdin' }
  $bytes = [Text.Encoding]::Unicode.GetBytes($plain)
  $plain = $null
  $enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
  [Array]::Clear($bytes, 0, $bytes.Length)
  Out-Json ([ordered]@{ protected = [BitConverter]::ToString($enc).Replace('-', '').ToLowerInvariant() })
} catch {
  Out-Json ([ordered]@{ error = 'encrypt'; hresult = ('0x{0:X8}' -f $_.Exception.HResult) })
}
`

// Decrypt. The encrypted hex comes in on stdin; the plain text goes out on stdout as
// hex of its UTF-16 bytes, which is a pipe to the scanner, not a console. Text made by
// another account, on another PC, or damaged does not decrypt, and the answer says so.
const UNPROTECT_PS = String.raw`
Add-Type -AssemblyName System.Security
try {
  $hex = [Console]::In.ReadToEnd().Trim()
  $enc = [byte[]]::new([int][Math]::Floor($hex.Length / 2))
  for ($i = 0; $i -lt $enc.Length; $i++) { $enc[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }
  $bytes = [Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
} catch {
  Out-Json ([ordered]@{ error = 'decrypt'; hresult = ('0x{0:X8}' -f $_.Exception.HResult) })
  exit 0
}
[Console]::Out.Write('{"secretHex":"' + [BitConverter]::ToString($bytes).Replace('-', '') + '"}')
[Console]::Out.Flush()
[Array]::Clear($bytes, 0, $bytes.Length)
`

/**
 * Run one of the DPAPI scripts with `input` on stdin. Returns its JSON answer (with
 * `secretHex` turned back into `secret`), or `{ reason }` with a fixed reason. Never
 * returns the child's stderr: nothing the child prints is trusted not to carry the
 * secret.
 */
async function dpapi(exec, script, input, deadline) {
  const r = await exec('powershell.exe', psArgs(script), { timeoutMs: 60_000, deadline, input })
  const line = String(r.stdout ?? '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('{'))
    .pop()
  try {
    const data = line ? JSON.parse(line) : null
    if (data && typeof data === 'object') {
      if (typeof data.secretHex === 'string' && /^([0-9a-fA-F]{4})+$/.test(data.secretHex)) {
        return { secret: Buffer.from(data.secretHex, 'hex').toString('utf16le') }
      }
      return data
    }
  } catch {}
  if (r.error === 'out of time' || r.error === 'timed out') return { reason: `PowerShell ${r.error}` }
  if (r.error === 'not installed') return { reason: 'powershell.exe was not found' }
  return { reason: 'PowerShell gave no answer' }
}

/** Would this secret work for this delivery mode? Plain ASCII only, so no code page can change it. */
function secretShapeOk(mode, value) {
  return mode === 'webhook' ? lib.isDiscordWebhookUrl(value) : lib.KEY_RE.test(value)
}

/**
 * Encrypt `plain` for the current Windows account, check that it decrypts back to the
 * same text, then write secret.dpapi in `home`. Throws with a reason that never
 * contains the secret. `exec` is run() or a test's mock.
 * @param {string} home
 * @param {string} plain
 * @param {{ exec?: typeof run, deadline?: number }} [opts]
 */
export async function saveSecret(home, plain, { exec = run, deadline = Infinity } = {}) {
  const enc = await dpapi(exec, PROTECT_PS, plain, deadline)
  const text = typeof enc.protected === 'string' ? enc.protected.trim() : ''
  if (!/^[0-9a-fA-F]{32,}$/.test(text)) throw new Error(`Windows could not encrypt it: ${enc.reason ?? 'no encrypted text came back'}`)
  const back = await dpapi(exec, UNPROTECT_PS, text, deadline)
  if (back.secret !== plain) {
    throw new Error(`the encrypted copy did not decrypt: ${back.reason ?? (back.error === 'decrypt' ? 'Windows refused it' : 'a different text came back')}`)
  }
  writeTextAtomic(path.join(home, SECRET_FILE), `${text}\n`)
}

const SECRET_NAME = { hub: 'key', webhook: 'webhook URL' }
const SECRET_FIX = { hub: 'install.ps1 -NewKey', webhook: 'install.ps1 -Webhook' }

/**
 * The secret this run sends with: the key (hub) or the webhook URL (webhook), from
 * secret.dpapi. Never throws. Only `value` holds the secret; no other field quotes it.
 *
 * Older versions kept it in config.json in plain text. One still there is used for
 * this run, and a run that is not a dry run moves it: encrypt it, check that it
 * decrypts, write secret.dpapi, then take `key` and `webhookUrl` out of config.json.
 * If that fails, config.json stays as it was and the next run tries again.
 *
 * `error` is a problem a person has to fix; `problem` is one that may pass by itself.
 * @param {{ home: string, configFile: string, config: any, mode: string, dryRun: boolean, exec?: typeof run, deadline?: number }} p
 * @returns {Promise<{ value?: string, from?: string, error?: string, problem?: string, note?: string, warning?: string }>}
 */
export async function loadSecret({ home, configFile, config, mode, dryRun, exec = run, deadline = Infinity }) {
  if (mode !== 'hub' && mode !== 'webhook') return {}
  const what = SECRET_NAME[mode]
  const field = mode === 'webhook' ? 'webhookUrl' : 'key'
  const other = mode === 'webhook' ? 'key' : 'webhookUrl'
  const legacy = String(config[field] ?? '').trim()
  const otherSet = String(config[other] ?? '').trim() !== ''
  if (legacy) {
    const found = { value: legacy, from: 'config.json' }
    // checkDelivery says what is wrong with it; it stays where it is.
    if (!secretShapeOk(mode, legacy)) return found
    if (dryRun) return { ...found, note: `the ${what} is still in config.json in plain text; the next run that is not a dry run moves it into ${SECRET_FILE}` }
    try {
      await saveSecret(home, legacy, { exec, deadline })
      const cfg = configForUpdate(configFile)
      delete cfg.key
      delete cfg.webhookUrl
      writeJsonAtomic(configFile, cfg)
      const extra = otherSet ? ` (the unused ${other} was taken out too)` : ''
      return { ...found, note: `moved the ${what} from config.json into ${SECRET_FILE}, encrypted for this Windows account${extra}` }
    } catch (e) {
      const why = e instanceof Error ? e.message : 'error'
      return { ...found, warning: `the ${what} is still in config.json in plain text: moving it into ${SECRET_FILE} failed (${why}); the next run tries again` }
    }
  }
  const warning = otherSet ? `config.json holds a ${other} in plain text that delivery "${mode}" does not use; delete it from config.json` : undefined
  const file = path.join(home, SECRET_FILE)
  let text
  try {
    text = readFileSync(file, 'utf8').trim()
  } catch (e) {
    if (e && e.code === 'ENOENT') return { warning }
    return { error: `${SECRET_FILE} could not be opened (${(e && e.code) || 'error'})`, warning }
  }
  if (!text) return { error: `${SECRET_FILE} is empty; run ${SECRET_FIX[mode]} again`, warning }
  const r = await dpapi(exec, UNPROTECT_PS, text, deadline)
  if (r.error === 'decrypt') {
    return {
      error: `the ${what} in ${SECRET_FILE} cannot be decrypted by this Windows account (it was made by another account or on another PC, or it is damaged); run ${SECRET_FIX[mode]} again`,
      warning,
    }
  }
  if (typeof r.secret !== 'string') return { problem: `${SECRET_FILE} could not be read this run (${r.reason ?? 'PowerShell gave no answer'})`, warning }
  return { value: r.secret.trim(), from: SECRET_FILE, warning }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function pausedUntil(pause, now) {
  const t = Date.parse(pause?.until ?? '')
  return Number.isFinite(t) && t > now ? new Date(t).toISOString().slice(0, 10) : ''
}

function usage() {
  return [
    'Usage: node pc-security-report.mjs [options]',
    '  --dry-run        run every check, print what would be sent, send and save nothing',
    '                   (the WSL check still runs apt-get update in a running distro,',
    '                   which refreshes its package lists)',
    '  --ignore-grace   report everything behind now, ignoring grace windows (implies --dry-run)',
    '  --json           print machine-readable findings',
    '  --dir <folder>   config and state folder (default %USERPROFILE%\\.nethersec-pc)',
    '  --config, --watch, --state <file>   override one file',
    '',
    'Setup (install.ps1 runs these for you):',
    '  --new-key [--hub-url <url>] [--dm <Discord user ID>]',
    '                   make a key, save it encrypted for this Windows account in',
    '                   secret.dpapi, set delivery "hub", and print the line for the hub',
    '                   (the key itself is never printed)',
    '  --set-webhook    read a Discord webhook URL from stdin, save it encrypted for this',
    '                   Windows account in secret.dpapi, and set delivery "webhook"',
  ].join('\n')
}

/** The real probes. The tests pass their own. */
export const realProbes = {
  quick: (ctx) => runPowerShell(QUICK_PS, 120_000, ctx),
  windowsUpdate: (ctx) => runPowerShell(WU_PS, 600_000, ctx),
  winget: (ctx) => probeWinget(ctx),
  wsl: (ctx, state, config, wslSkip) => probeWsl(ctx, state, config, wslSkip),
  runtimes: (ctx, config) => probeRuntimes(ctx, config),
  kev: (ctx) =>
    fetchJson(ctx, 'kev', URLS.kev, {
      maxAgeMs: 20 * lib.HOUR,
      staleMs: 7 * lib.DAY,
      timeoutMs: 60_000,
      pick: (j) => ({
        catalogVersion: j?.catalogVersion,
        vulnerabilities: (Array.isArray(j?.vulnerabilities) ? j.vulnerabilities : []).map((v) => ({
          cveID: v.cveID,
          vendorProject: v.vendorProject,
          product: v.product,
          dateAdded: v.dateAdded,
        })),
      }),
    }),
}

function homeDir(args) {
  return path.resolve(args.dir || path.join(homedir(), '.nethersec-pc'))
}

/**
 * One scan: run every check, decide, send, save. `deps` replaces the real probes,
 * fetch (for the reports), the program runner (for the DPAPI calls), the clock and
 * the console.
 * @param {ReturnType<typeof parseArgs>} args
 * @param {{ probes?: typeof realProbes, fetch?: typeof fetch, exec?: typeof run, now?: () => number, log?: (s: string) => void }} [deps]
 */
export async function runReport(args, deps = {}) {
  const probes = deps.probes ?? realProbes
  const send = deps.fetch ?? fetch
  const exec = deps.exec ?? run
  const log = deps.log ?? ((s) => console.log(s))
  const dryRun = args.dryRun || args.ignoreGrace
  const ignoreGrace = args.ignoreGrace
  const home = homeDir(args)
  const files = {
    config: args.config || path.join(home, 'config.json'),
    watch: args.watch || path.join(home, 'watch.json'),
    state: args.state || path.join(home, 'state.json'),
    lastRun: path.join(home, 'last-run.json'),
    cache: path.join(home, 'cache'),
    disabled: path.join(home, 'disabled'),
  }
  const { cfg: config, error: configError, from: configFrom } = loadConfig(files.config)
  if (config.disabled === true || existsSync(files.disabled)) {
    if (!args.json) log('PC security report is turned off (config "disabled" or a "disabled" file).')
    return
  }
  const watch = loadWatch(files.watch)
  const now = deps.now ? deps.now() : Date.now()
  const started = Date.now()
  const stateRead = readJson(files.state)
  let stateNote = ''
  if (stateRead.error && stateRead.error !== 'missing') {
    // A broken state file would stop every run. Keep it for a look and start fresh
    // (clocks restart, the exploited list re-baselines).
    stateNote = `state.json was unreadable (${stateRead.error})`
    if (!dryRun) {
      const aside = `${files.state}.bad-${new Date(now).toISOString().replace(/[:.]/g, '-')}`
      renameSync(files.state, aside)
      stateNote += `, moved to ${path.basename(aside)}`
    }
  }
  // A clock that jumped back must not leave clocks or reminders stuck in the future.
  const state = lib.clampFutureTimes(stateRead.data && typeof stateRead.data === 'object' ? stateRead.data : {}, now)
  const cwd = existsSync(home) ? home : HERE
  const ctx = {
    now,
    dryRun,
    cacheDir: files.cache,
    cwd,
    deadline: started + Number(config.checkBudgetMinutes) * 60_000,
  }
  const reportDeadline = started + Number(config.reportBudgetMinutes) * 60_000

  // The key or webhook URL, decrypted from secret.dpapi (or moved there from an older
  // config.json). Only `secret.value` holds it, and it goes nowhere but the request.
  const mode = lib.deliveryMode(config)
  const secret = await loadSecret({ home, configFile: files.config, config, mode, dryRun, exec, deadline: ctx.deadline })
  const checked = lib.validateConfig(config, secret)
  const deliveryNotes = secret.note ? [secret.note] : []

  const [quick, wu, winget, wsl, runtimes, kevFeed] = await Promise.all([
    probes.quick(ctx),
    probes.windowsUpdate(ctx),
    watch.unreadable ? Promise.resolve(null) : probes.winget(ctx),
    probes.wsl(ctx, state, config, checked.wslSkip),
    probes.runtimes(ctx, config),
    config.kev?.enabled === false ? Promise.resolve({ disabled: true }) : probes.kev(ctx),
  ])

  const next = {
    version: SCANNER_VERSION,
    events: { ...(state.events ?? {}) },
    checks: state.checks ?? {},
    apps: state.apps ?? {},
    eolItems: state.eolItems ?? [],
    windows: state.windows ?? {},
    runtimes: state.runtimes ?? {},
    wsl: state.wsl ?? {},
    kev: state.kev ?? {},
  }
  /** @type {Record<string, any>} */
  const findings = {}
  /** @type {Record<string, {readable: boolean, error?: string}>} */
  const readability = {}
  /** @type {Record<string, {status: string, line: string, notes: string[], pending?: string[]}>} */
  const summary = {}
  const graceNote = (it, days) => `${it} (alerts after ${days} days)`
  const frozenApps = watch.skipped.filter((s) => s.list === 'apps').map((s) => s.key)
  const frozenEol = watch.skipped.filter((s) => s.list === 'eol').map((s) => s.key)

  // --- windows-updates -----------------------------------------------------
  const q = quick.data ?? {}
  // The registry still says "Windows 10" on Windows 11 (build 22000 and later).
  if (q.os && !q.os.error && Number(q.os.build) >= 22000) q.os.product = String(q.os.product).replace(/Windows 10/, 'Windows 11')
  const wuData = wu.data
  const wuComplete = !!wuData && !wuData.error && wuData.resultCode === 2
  const wuPartial = !!wuData && !wuData.error && wuData.resultCode === 3
  let wuEval = null
  if (wuComplete || wuPartial) {
    wuEval = lib.evaluateWindowsUpdates({
      updates: wuData.updates,
      firstSeen: state.windows?.firstSeen,
      now,
      graceDays: config.windowsGraceDays,
      ignoreGrace,
    })
    // A partial search keeps the first-seen times of updates it did not return.
    next.windows = { ...next.windows, firstSeen: wuComplete ? wuEval.firstSeen : { ...(state.windows?.firstSeen ?? {}), ...wuEval.firstSeen } }
    const extra = {
      rebootPending: q.reboot?.pending === true,
      pausedUntil: pausedUntil(q.pause, now),
      graceDays: ignoreGrace ? 0 : config.windowsGraceDays,
    }
    const other = (wuData.updates ?? []).length - wuEval.active.length - wuEval.pending.length
    const notes = []
    if (extra.rebootPending) notes.push(`restart pending (${(q.reboot.sources ?? []).join(', ')})`)
    if (extra.pausedUntil) notes.push(`updates paused until ${extra.pausedUntil}`)
    if (other > 0) notes.push(`${other} other (non-security) ${other === 1 ? 'update' : 'updates'} waiting`)
    if (wuComplete || wuEval.active.length) {
      // A partial search can prove an update is waiting, never that none is.
      findings['windows-updates'] = { active: wuEval.active.length > 0, items: wuEval.active, severity: 'warning', extra }
      readability['windows-updates'] = { readable: true }
      if (wuPartial) notes.push('search finished with errors; only the updates it found count')
      summary['windows-updates'] = {
        status: '',
        line: wuEval.active.length ? '' : wuEval.pending.length ? 'security updates waiting, still within grace' : 'no security update waiting',
        pending: wuEval.pending.map((u) => graceNote(`${u.title} ${u.kb}`.trim(), config.windowsGraceDays)),
        notes,
      }
    } else {
      readability['windows-updates'] = { readable: false, error: 'Windows Update search finished with errors (partial result)' }
    }
  } else {
    readability['windows-updates'] = {
      readable: false,
      error: wu.error || wuData?.error || `result code ${wuData?.resultCode}`,
    }
  }

  // --- defender / firewall -------------------------------------------------
  if (q.defender && !q.defender.error) {
    const d = lib.evaluateDefender(q.defender, now, config.defenderSignatureMaxDays)
    findings.defender = { active: d.items.length > 0, items: d.items, severity: 'warning' }
    readability.defender = { readable: true }
    summary.defender = {
      status: '',
      line: d.items.length ? '' : `protection on, definitions ${d.ageDays ?? '?'} days old (${q.defender.signatureVersion})`,
      notes: d.notes,
    }
  } else readability.defender = { readable: false, error: q.defender?.error || quick.error || 'no answer' }

  if (q.firewall && Array.isArray(q.firewall.profiles) && q.firewall.profiles.length) {
    const off = lib.evaluateFirewall(q.firewall.profiles)
    findings.firewall = { active: off.length > 0, items: off, severity: 'warning' }
    readability.firewall = { readable: true }
    summary.firewall = { status: '', line: off.length ? '' : `on for ${q.firewall.profiles.map((p) => p.name).join(', ')}`, notes: [] }
  } else readability.firewall = { readable: false, error: q.firewall?.error || quick.error || 'no profiles' }

  // --- apps-behind / apps-eol ----------------------------------------------
  // A watch.json that cannot be read makes these checks (and exploited) unreadable:
  // an empty list must never read as "everything fixed".
  const up = winget ? winget.upgrade : null
  const ls = winget ? winget.list : null
  if (watch.unreadable) {
    for (const id of ['apps-behind', 'apps-eol']) readability[id] = { readable: false, error: `watch list: ${watch.unreadable}` }
  } else {
    if (up && up.ok) {
      const a = lib.evaluateAppsBehind({
        rows: up.rows,
        installedRows: ls && ls.ok ? ls.rows : null,
        failedSources: up.failedSources,
        entries: watch.apps,
        frozenKeys: frozenApps,
        appState: state.apps,
        now,
        graceDays: config.appGraceDays,
        ignoreGrace,
        tombstoneHours: config.appTombstoneHours,
      })
      next.apps = a.appState
      findings['apps-behind'] = { active: a.active.length > 0, items: a.active, severity: 'warning' }
      readability['apps-behind'] = { readable: true }
      const notes = [`winget lists ${up.rows.length} upgrades; ${watch.apps.length} watched apps`]
      const missingOnce = Object.entries(a.appState).filter(([, s]) => !s.goneSince && s.missing > 0).map(([k]) => k)
      if (missingOnce.length) notes.push(`not in this read, kept until a second read agrees: ${missingOnce.join(', ')}`)
      if (a.majorSkipped.length) notes.push(`newer major only, not counted: ${a.majorSkipped.map((m) => `${m.name} ${m.installed} -> ${m.available}`).join('; ')}`)
      if (a.unknown.length) notes.push(`installed version unknown: ${a.unknown.map((u) => u.name).join(', ')}`)
      if (up.failedSources.length) notes.push(`winget could not search: ${up.failedSources.join(', ')}`)
      notes.push(...up.notes.slice(0, 3))
      summary['apps-behind'] = {
        status: '',
        line: a.active.length ? '' : a.pending.length ? 'watched apps behind, still within grace' : 'no watched app is behind',
        pending: a.pending.map((i) => graceNote(`${i.name} ${i.installed} -> ${i.available}`, config.appGraceDays)),
        notes,
      }
    } else readability['apps-behind'] = { readable: false, error: (up && up.errors[0]) || 'winget upgrade failed' }

    if (ls && ls.ok) {
      const items = lib.evaluateEol({ rows: ls.rows, entries: watch.eol, prior: state.eolItems, frozenKeys: frozenEol })
      next.eolItems = items
      findings['apps-eol'] = { active: items.length > 0, items, severity: 'warning' }
      readability['apps-eol'] = { readable: true }
      summary['apps-eol'] = { status: '', line: items.length ? '' : `none of ${watch.eol.length} end-of-life entries installed`, notes: [] }
    } else readability['apps-eol'] = { readable: false, error: (ls && ls.errors[0]) || 'winget list failed' }
  }

  // --- runtimes -------------------------------------------------------------
  const subs = {}
  const rtNotes = []
  if (runtimes.node) {
    const n = runtimes.node
    if (n.error) subs.node = { readable: false, error: n.error }
    else if (!n.installed.length) subs.node = { readable: true, items: [] }
    else if (n.index.error) subs.node = { readable: false, error: n.index.error }
    else {
      if (n.eol?.error) rtNotes.push(`Node end-of-life dates not read (${n.eol.error})`)
      subs.node = { readable: true, items: lib.evaluateNode({ installed: n.installed, index: n.index.data, eolCycles: n.eol?.data ?? null, now }) }
      const newest = (Array.isArray(n.index.data) ? n.index.data : []).map((r) => r.version).filter(Boolean)[0]
      rtNotes.push(`Node ${n.installed.join(', ')}${newest ? ` (newest overall ${newest}; a newer major is not counted)` : ''}`)
    }
  }
  if (runtimes.go) {
    const g = runtimes.go
    if (!g.installed) subs.go = g.error ? { readable: false, error: `go version: ${g.error}` } : { readable: true, items: [] }
    else if (g.releases.error) subs.go = { readable: false, error: g.releases.error }
    else {
      subs.go = { readable: true, items: lib.evaluateGo({ installed: g.installed, releases: g.releases.data }) }
      rtNotes.push(`Go ${g.installed}`)
    }
  }
  if (runtimes.java) {
    const j = runtimes.java
    if (!j.installs.length) subs.java = { readable: true, items: [] }
    else if (j.errors.length) subs.java = { readable: false, error: j.errors[0] }
    else {
      subs.java = { readable: true, items: lib.evaluateJava({ installs: j.installs, packagesByMajor: j.packagesByMajor }) }
      rtNotes.push(`Java (Zulu) ${j.installs.map((i) => i.version).join(', ')}`)
    }
  }
  for (const [name, s] of Object.entries(subs)) readability[`runtimes.${name}`] = { readable: s.readable, error: s.error }
  if (Object.keys(subs).length) {
    const merged = lib.mergeSubResults(subs, state.runtimes?.last)
    const clock = lib.applyClock({
      items: merged.items,
      clocks: state.runtimes?.clocks,
      now,
      graceMs: config.runtimeGraceDays * lib.DAY,
      ignoreGrace,
    })
    next.runtimes = { last: merged.last, clocks: clock.clocks }
    if (!merged.allUnreadable) {
      findings.runtimes = { active: clock.active.length > 0, items: clock.active, severity: 'warning' }
      summary.runtimes = {
        status: '',
        line: clock.active.length ? '' : clock.pending.length ? 'behind, still within grace' : 'Node, Go and Java have their security fixes',
        pending: clock.pending.map((i) => graceNote(lib.describeActive('runtimes', { items: [i] }).detail.replace(/\. Download from:.*$/, ''), config.runtimeGraceDays)),
        notes: [
          `checked: ${rtNotes.join('; ') || 'none installed'}`,
          ...(merged.unreadable.length ? [`not read this run: ${merged.unreadable.join(', ')} (last result kept)`] : []),
          'the Java check covers Azul Zulu under Program Files\\Zulu only',
        ],
      }
    }
  }

  // --- wsl-updates ------------------------------------------------------------
  if (wsl.enabled === false) {
    summary['wsl-updates'] = { status: 'off', line: 'turned off in config', notes: [] }
  } else if (!wsl.ok) {
    readability['wsl-updates'] = { readable: false, error: wsl.error }
  } else {
    const w = lib.evaluateWsl({
      results: wsl.results,
      wslState: state.wsl?.distros,
      now,
      ignoreGrace,
      streakNeeded: config.wslStreak,
    })
    next.wsl = { distros: w.wslState, lastCheck: { ...(state.wsl?.lastCheck ?? {}), ...wsl.checkedAt } }
    for (const name of Object.keys(next.wsl.lastCheck)) if (!w.wslState[name]) delete next.wsl.lastCheck[name]
    findings['wsl-updates'] = { active: w.active.length > 0, items: w.active, severity: 'warning' }
    readability['wsl-updates'] = { readable: w.readable, error: w.errors[0] }
    const names = (action) => wsl.plan.filter((p) => p.action === action).map((p) => p.name)
    summary['wsl-updates'] = {
      status: '',
      line: w.active.length ? '' : w.pending.length ? 'security updates waiting, alerts on the second daily check' : 'no security update waiting',
      pending: w.pending.map((i) => `${i.name}: ${i.count} security ${i.count === 1 ? 'update' : 'updates'} (${i.packages.join(', ')}), seen on 1 daily check`),
      notes: [
        `distros: ${wsl.distros.map((d) => `${d.name} (${d.state})`).join(', ') || 'none'}`,
        ...(names('check').length ? [`checked now: ${names('check').join(', ')}`] : []),
        ...(names('not-due').length ? [`checked within the last day, not due: ${names('not-due').join(', ')}`] : []),
        ...(names('not-running').length
          ? [`not running, so not checked (set wsl.startStopped to start them): ${names('not-running').join(', ')}`]
          : []),
        ...w.errors,
      ],
    }
  }

  // --- exploited (CISA KEV) ---------------------------------------------------
  if (kevFeed.disabled) {
    summary.exploited = { status: 'off', line: 'turned off in config', notes: [] }
  } else if (kevFeed.error) {
    readability.exploited = { readable: false, error: kevFeed.error }
  } else if (watch.unreadable) {
    readability.exploited = { readable: false, error: `watch list: ${watch.unreadable}` }
  } else {
    const upOk = !!up && up.ok
    const lsOk = !!ls && ls.ok
    const targets = watch.apps
      .filter((e) => e.kev.length)
      .map((e) => {
        const row = lsOk ? ls.rows.find((r) => lib.entryMatchesRow(e, r)) : undefined
        const upRow = upOk ? up.rows.find((r) => lib.entryMatchesRow(e, r)) : undefined
        const fromWinget = !!row && !!row.source && !up.failedSources.includes(row.source)
        const newer = upRow && lib.compareVersions(upRow.version, upRow.available) === -1 ? upRow.available : ''
        return {
          key: e.key,
          label: e.name,
          kev: e.kev,
          installed: lsOk ? !!row : null,
          version: row ? row.version : '',
          updateAvailable: newer,
          updateKnown: upOk && fromWinget,
          upgradeReadable: upOk,
          update: e.update || (row && fromWinget ? `winget upgrade --id ${row.id}` : ''),
        }
      })
    const winBuild = q.os && !q.os.error ? `${q.os.build}.${q.os.ubr}` : ''
    const k = lib.evaluateKev({
      catalog: kevFeed.data,
      kevState: state.kev,
      targets,
      frozenKeys: frozenApps,
      // Only a complete Windows Update read can say a Windows flaw is fixed.
      windows: { readable: wuComplete, securityPending: !!wuEval?.securityPending, build: winBuild },
      now,
      lookbackDays: config.kevLookbackDays,
    })
    next.kev = k.kevState
    const items = Object.values(k.findings).map((f) => ({ ...f, key: f.cve }))
    const actionable = items.some((f) => f.actionable)
    findings.exploited = {
      active: items.length > 0,
      items,
      severity: actionable ? 'critical' : 'warning',
      actionable,
      quiet: !state.events?.exploited?.sentActionable,
    }
    readability.exploited = { readable: true }
    summary.exploited = {
      status: '',
      line: items.length
        ? ''
        : `no new exploited flaw matches (catalog ${kevFeed.data.catalogVersion ?? '?'}, ${kevFeed.data.vulnerabilities.length} entries${
            k.firstRun ? `, first run: baseline ${dryRun ? 'would be recorded' : 'recorded'}` : ''
          })`,
      notes: [
        `${targets.length} watched apps carry a matcher, plus Windows`,
        ...(kevFeed.from !== 'network' ? [`catalog from ${kevFeed.from}${kevFeed.warning ? ` (${kevFeed.warning})` : ''}`] : []),
        ...(k.treatedFixed.length ? [`Windows entries treated as fixed (no security update waiting): ${k.treatedFixed.join(', ')}`] : []),
        ...(k.closedNow.length ? [`closed now: ${k.closedNow.join(', ')}`] : []),
        ...(k.deferred.length ? [`waiting for a readable check: ${k.deferred.length} entries`] : []),
        ...(k.watching.length ? [`fixed earlier, watched for a return: ${k.watching.length} entries`] : []),
      ],
    }
  }

  // --- monitor-unreadable -----------------------------------------------------
  const tr = lib.trackReadability(state.checks, readability, now, config.unreadableAlertDays)
  next.checks = tr.checks
  findings['monitor-unreadable'] = {
    active: tr.items.length > 0,
    items: tr.items,
    severity: 'info',
    extra: { days: config.unreadableAlertDays },
  }

  // --- decide and send --------------------------------------------------------
  const decisions = []
  for (const event of lib.EVENTS) {
    const finding = findings[event] ?? null
    const decision = lib.decideReport(state.events?.[event], finding, now, { reminderDays: config.reminderDays })
    if (decision.shrink) next.events[event] = { ...(next.events[event] ?? {}), sentItems: decision.shrink }
    if (decision.action === 'quiet-clear') next.events[event] = lib.recordDelivered(next.events[event], decision, finding, now)
    decisions.push({ event, decision, finding })
  }
  const plan = lib.planReports(decisions, config.maxPostsPerRun)
  const opts = { titleMax: config.titleMax, detailMax: config.detailMax }
  const outgoing = plan.send.map((p) => ({
    ...p,
    body: lib.buildReport({ source: config.source, event: p.event, decision: p.decision, finding: p.finding, opts }),
  }))

  const sent = []
  if (!dryRun) {
    // Save clocks before sending, then again after each delivered report, so a run
    // killed partway never sends the same report twice.
    writeJsonAtomic(files.state, next)
    // Every result line below is safe to log: a status code or a fixed reason, never
    // the key, the webhook URL or an error message that could quote either.
    let stop = outgoing.length && !checked.sendOk ? `not sent: ${checked.sendProblem}` : ''
    for (const o of outgoing) {
      const left = lib.probeTimeout(20_000, reportDeadline, Date.now())
      if (!stop && !left) stop = 'not sent: out of time'
      if (stop) {
        sent.push({ event: o.event, state: o.body.state, reason: o.decision.reason, result: stop })
        continue
      }
      let result
      try {
        const req = lib.deliveryRequest(config, secret.value, o.body)
        const res = await send(req.url, {
          method: 'POST',
          redirect: 'error',
          signal: AbortSignal.timeout(left),
          headers: req.headers,
          body: req.body,
        })
        // Nothing in the reply is used; let the connection go.
        try {
          res.body?.cancel().catch(() => {})
        } catch {}
        const outcome = lib.responseOutcome(res.status, req.mode)
        result = `HTTP ${res.status}${outcome.stop ? ` (${outcome.stop})` : ''}`
        if (outcome.sent) {
          next.events[o.event] = lib.recordDelivered(next.events[o.event], o.decision, o.finding, now)
          if (o.event === 'exploited' && o.body.state === 'triggered') {
            for (const f of o.finding.items) if (f.notice && next.kev.findings?.[f.cve]) next.kev.findings[f.cve].delivered = true
          }
          writeJsonAtomic(files.state, next)
        }
        if (outcome.stop) stop = `not sent: ${outcome.stop}`
      } catch (e) {
        result = e && e.name === 'TimeoutError' ? 'timed out' : 'network error'
      }
      sent.push({ event: o.event, state: o.body.state, reason: o.decision.reason, result })
    }
  }

  // --- summary, state ---------------------------------------------------------
  for (const event of lib.EVENTS) {
    const s = summary[event] ?? { status: '', line: '', notes: [] }
    const f = findings[event]
    if (s.status === 'off') {
      summary[event] = s
      continue
    }
    if (f === undefined || f === null) {
      const errs = Object.entries(readability)
        .filter(([id, r]) => (id === event || id.startsWith(`${event}.`)) && !r.readable)
        .map(([id, r]) => `${id}: ${r.error}`)
      s.status = event === 'monitor-unreadable' ? 'ok' : 'CANNOT READ'
      s.line = errs.join('; ') || 'nothing to check'
    } else if (f.active) {
      const d = lib.describeActive(event, f, opts)
      s.status = 'ALERT'
      s.line = `${d.title}\n${d.detail}`
    } else {
      s.status = s.pending && s.pending.length ? 'waiting' : 'ok'
      if (event === 'monitor-unreadable') {
        const failing = Object.entries(tr.checks).filter(([, c]) => typeof c.failSince === 'number').map(([id]) => id)
        s.line = failing.length ? `not readable now (alerts after ${config.unreadableAlertDays} days): ${failing.join(', ')}` : 'every check could read'
      }
    }
    summary[event] = s
  }

  const lastRun = {
    at: new Date(now).toISOString(),
    durationMs: Date.now() - started,
    dryRun,
    ignoreGrace,
    os: q.os ?? null,
    configFrom,
    watchFrom: watch.from,
    configErrors: [
      ...(configError ? [configError] : []),
      ...checked.errors,
      ...(secret.warning ? [secret.warning] : []),
      ...watch.errors,
      ...(stateNote ? [stateNote] : []),
    ],
    deliveryNotes,
    skippedWatchEntries: watch.skipped,
    checks: Object.fromEntries(
      lib.EVENTS.map((e) => [e, { status: summary[e].status, active: findings[e]?.items?.length ?? 0 }]),
    ),
    unreadable: Object.fromEntries(Object.entries(readability).filter(([, r]) => !r.readable).map(([id, r]) => [id, r.error])),
    reports: dryRun
      ? outgoing.map((o) => ({ event: o.event, state: o.body.state, reason: o.decision.reason, result: 'dry run' }))
      : sent,
    deferred: plan.deferred.map((d) => d.event),
  }
  if (!dryRun) {
    writeJsonAtomic(files.state, next)
    writeJsonAtomic(files.lastRun, lastRun)
  }

  if (args.json) {
    log(
      JSON.stringify(
        {
          ...lastRun,
          findings,
          decisions: decisions.map((d) => ({ event: d.event, ...d.decision })),
          wouldSend: outgoing.map((o) => o.body),
        },
        null,
        2,
      ),
    )
    return
  }
  printSummary({ lastRun, summary, outgoing, plan, dryRun, ignoreGrace, q, watch, checked, log })
}

function printSummary({ lastRun, summary, outgoing, plan, dryRun, ignoreGrace, q, watch, checked, log }) {
  const out = []
  const mode = [dryRun ? 'dry run' : '', ignoreGrace ? 'grace ignored' : ''].filter(Boolean).join(', ')
  out.push(`PC security report${mode ? ` (${mode})` : ''} at ${lastRun.at}, ${Math.round(lastRun.durationMs / 1000)}s`)
  if (q.os && !q.os.error) out.push(`${q.os.product} ${q.os.display}, build ${q.os.build}.${q.os.ubr}`)
  const target = checked.mode === 'webhook' ? 'Discord webhook' : checked.mode === 'hub' ? 'hub' : checked.mode
  out.push(`delivery: ${target}, ${checked.sendOk ? 'ready' : `not ready: ${checked.sendProblem}`}`)
  for (const n of lastRun.deliveryNotes) out.push(`delivery note: ${n}`)
  out.push(
    watch.unreadable
      ? `watch list: ${watch.from} could not be read, so app checks change nothing this run`
      : `watch list: ${watch.from} (${watch.apps.length} apps, ${watch.eol.length} end-of-life entries${watch.skipped.length ? `, ${watch.skipped.length} skipped` : ''})`,
  )
  for (const e of lastRun.configErrors) out.push(`config problem: ${e}`)
  out.push('')
  for (const event of lib.EVENTS) {
    const s = summary[event]
    const head = `${s.status.padEnd(11)} ${event}`
    const lines = String(s.line || '').split('\n')
    out.push(`${head}: ${lines[0]}`)
    for (const l of lines.slice(1)) out.push(`${' '.repeat(14)}${l}`)
    for (const p of s.pending ?? []) out.push(`${' '.repeat(14)}within grace: ${p}`)
    for (const n of s.notes ?? []) out.push(`${' '.repeat(14)}note: ${n}`)
  }
  out.push('')
  if (dryRun) {
    out.push(`Would send ${outgoing.length} ${outgoing.length === 1 ? 'report' : 'reports'}${plan.deferred.length ? ` (${plan.deferred.length} more next run)` : ''}:`)
    out.push(JSON.stringify(outgoing.map((o) => o.body), null, 2))
  } else {
    out.push(`Sent: ${lastRun.reports.length ? lastRun.reports.map((r) => `${r.event} ${r.state} ${r.result}`).join('; ') : 'nothing'}`)
  }
  log(out.join('\n'))
}

// ---------------------------------------------------------------------------
// Setup: the key and the webhook URL
// ---------------------------------------------------------------------------

/** config.json as an object to update, or the example when there is none. Throws on a broken file. */
function configForUpdate(file) {
  const r = readJson(file)
  if (r.error && r.error !== 'missing') throw new Error(`${r.safeError}; fix or delete it first`)
  if (r.data !== undefined && (!r.data || typeof r.data !== 'object' || Array.isArray(r.data))) {
    throw new Error('config.json is not a JSON object; fix or delete it first')
  }
  return r.data ?? readJson(path.join(HERE, 'config.example.json')).data ?? {}
}

/**
 * Make a key for the hub: 32 random bytes as 64 hex characters. It goes into
 * secret.dpapi, encrypted for the current Windows account, and config.json gets
 * delivery "hub" and no key or webhook URL. Returns the hub's keys.txt line (source,
 * SHA-256 of the key text, dm= flag). The key itself is never returned or printed.
 * @param {{ home: string, dm?: string, hubUrl?: string, exec?: typeof run }} p
 */
export async function newKey({ home, dm, hubUrl, exec = run }) {
  if (dm !== undefined && !/^\d{17,20}$/.test(dm)) throw new Error('--dm takes a Discord user ID (17 to 20 digits)')
  const file = path.join(home, 'config.json')
  const cfg = configForUpdate(file)
  const source = cfg.source === undefined ? 'pc' : String(cfg.source)
  if (!lib.SOURCE_RE.test(source)) throw new Error('source in config.json must be 1 to 40 lowercase letters, digits or dashes')
  if (hubUrl !== undefined) {
    const probe = lib.checkDelivery({ source, delivery: 'hub', hubUrl, allowHttp: cfg.allowHttp }, { value: '0'.repeat(64) })
    if (!probe.ok) throw new Error(probe.problem)
    cfg.hubUrl = hubUrl
  }
  const key = randomBytes(32).toString('hex')
  await saveSecret(home, key, { exec })
  cfg.delivery = 'hub'
  delete cfg.key
  delete cfg.webhookUrl
  writeJsonAtomic(file, cfg)
  const hash = createHash('sha256').update(key, 'utf8').digest('hex')
  return { line: `${source} ${hash} dm=${dm ?? '<your Discord user ID>'}`, source, hash, hubUrlSet: !!String(cfg.hubUrl ?? '').trim() }
}

/**
 * Save a Discord webhook URL in secret.dpapi, encrypted for the current Windows
 * account, and set delivery "webhook" in config.json (with no key or webhook URL).
 * @param {{ home: string, url: string, exec?: typeof run }} p
 */
export async function setWebhook({ home, url, exec = run }) {
  const clean = String(url ?? '').trim()
  // The message never repeats what was given: it may be a real webhook URL.
  if (!lib.isDiscordWebhookUrl(clean)) throw new Error('that is not a Discord webhook URL (https://discord.com/api/webhooks/...)')
  const file = path.join(home, 'config.json')
  const cfg = configForUpdate(file)
  await saveSecret(home, clean, { exec })
  cfg.delivery = 'webhook'
  delete cfg.key
  delete cfg.webhookUrl
  writeJsonAtomic(file, cfg)
}

function readStdin() {
  try {
    return readFileSync(0, 'utf8')
  } catch {
    return ''
  }
}

/**
 * The command line. Returns the exit code: 0 even when checks find problems, 1 for
 * a setup command that could not finish.
 * @param {string[]} argv
 * @param {Parameters<typeof runReport>[1] & { stdin?: () => string, err?: (s: string) => void }} [deps]
 */
export async function cli(argv, deps = {}) {
  const log = deps.log ?? ((s) => console.log(s))
  const err = deps.err ?? ((s) => console.error(s))
  let args
  try {
    args = parseArgs(argv)
  } catch (e) {
    err(`${e instanceof Error ? e.message : e}\n\n${usage()}`)
    return 1
  }
  if (args.help) {
    log(usage())
    return 0
  }
  const home = homeDir(args)
  if (args.newKey || args.setWebhook) {
    try {
      mkdirSync(home, { recursive: true })
      if (args.newKey) {
        const r = await newKey({ home, dm: args.dm, hubUrl: args.hubUrl, exec: deps.exec })
        log(`Saved a new key in ${SECRET_FILE}, encrypted for this Windows account (delivery "hub"). It replaces any older key or webhook URL.`)
        if (!r.hubUrlSet) log('Set hubUrl in config.json to your hub address before reports can go out.')
        log(`Add this line to the hub's keys file, replacing any older line for "${r.source}":`)
        log(r.line)
      } else {
        if (!deps.stdin && process.stdin.isTTY) throw new Error('pipe the URL in on stdin (install.ps1 -Webhook does this for you)')
        await setWebhook({ home, url: (deps.stdin ?? readStdin)(), exec: deps.exec })
        log(`Saved the webhook URL in ${SECRET_FILE}, encrypted for this Windows account (delivery "webhook").`)
      }
      return 0
    } catch (e) {
      err(`Not saved: ${e instanceof Error ? e.message : e}`)
      return 1
    }
  }
  await runReport(args, deps)
  return 0
}
