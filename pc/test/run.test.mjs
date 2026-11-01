// A whole scan (runReport) with every Windows probe and PowerShell's DPAPI mocked, so it
// runs on any OS: what gets sent, to where, what counts as sent, and that the key and
// the webhook URL never reach a log. Also the setup commands (--new-key, --set-webhook).
// Keys and webhook URLs are built from pieces at runtime; none is real.
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { cli, probeWinget, probeWsl, SECRET_FILE } from '../pc-security-run.mjs'
import {
  DAY,
  KEY,
  NOW,
  WEBHOOK,
  fakeDpapi,
  fakeFetch,
  hubConfig,
  partial,
  probes,
  readIn,
  removeTempDirs,
  scan,
  tempDir,
  unprotect,
  visible,
} from './helpers.mjs'

const PC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const ENTRY = path.join(PC_DIR, 'pc-security-report.mjs')

after(removeTempDirs)

describe('a scan that finds a problem, sent to the hub', () => {
  it('posts one protocol report with the key as a bearer token, and records it as sent', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 1)
    const c = fetch.calls[0]
    assert.equal(c.url, 'https://hub.example.com/v1/report')
    assert.equal(c.init.method, 'POST')
    assert.equal(c.init.redirect, 'error')
    assert.equal(c.init.headers.authorization, `Bearer ${KEY}`)
    assert.deepEqual(c.body, {
      v: 1,
      kind: 'security',
      source: 'pc',
      event: 'firewall',
      state: 'triggered',
      severity: 'warning',
      title: 'Windows Firewall is off',
      detail: 'Off for: Public network. Turn it on in Windows Security > Firewall & network protection.',
    })
    assert.equal(r.state.events.firewall.sent, 'active')
    const lastRun = JSON.parse(r.lastRunText)
    assert.deepEqual(lastRun.reports, [{ event: 'firewall', state: 'triggered', reason: 'new', result: 'HTTP 202' }])
    assert.match(r.out, /delivery: hub, ready/)
    for (const text of [r.out, r.lastRunText, JSON.stringify(r.state)]) assert.equal(text.includes(KEY), false)
  })

  it('sends nothing while the problem stays the same, then one resolved report when it is fixed', async () => {
    const dir = tempDir(hubConfig(), KEY)
    await scan(dir, { probes: probes({ firewallOff: true }), fetch: fakeFetch(202) })
    const again = fakeFetch(202)
    await scan(dir, { probes: probes({ firewallOff: true }), fetch: again })
    assert.equal(again.calls.length, 0)
    const fixed = fakeFetch(202)
    const r = await scan(dir, { probes: probes(), fetch: fixed })
    assert.equal(fixed.calls.length, 1)
    partial(fixed.calls[0].body, { event: 'firewall', state: 'resolved', title: 'Windows Firewall is on' })
    assert.equal(fixed.calls[0].body.severity, undefined)
    assert.equal(r.state.events.firewall.sent, 'ok')
  })

  it('a report that was not accepted stays pending and goes again on the next run', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const down = fakeFetch(503)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch: down })
    assert.equal(down.calls.length, 1)
    assert.equal(r.state.events.firewall, undefined)
    assert.equal(JSON.parse(r.lastRunText).reports[0].result, 'HTTP 503 (the hub could not deliver it now)')
    const back = fakeFetch(202)
    await scan(dir, { probes: probes({ firewallOff: true }), fetch: back })
    assert.equal(back.calls.length, 1)
  })

  it('a network error leaves the report pending and logs no detail', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch: fakeFetch('throw') })
    assert.equal(r.state.events.firewall, undefined)
    assert.equal(JSON.parse(r.lastRunText).reports[0].result, 'network error')
  })

  it('a refused key stops the run; a refused body does not', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const refused = fakeFetch(401)
    const r = await scan(dir, { probes: probes({ firewallOff: true, defenderOff: true }), fetch: refused })
    assert.equal(refused.calls.length, 1)
    assert.deepEqual(
      JSON.parse(r.lastRunText).reports.map((x) => x.result),
      ['HTTP 401 (the hub did not accept the key)', 'not sent: the hub did not accept the key'],
    )
    const dir2 = tempDir(hubConfig(), KEY)
    const badBody = fakeFetch(400, 202)
    const r2 = await scan(dir2, { probes: probes({ firewallOff: true, defenderOff: true }), fetch: badBody })
    assert.equal(badBody.calls.length, 2)
    assert.deepEqual(JSON.parse(r2.lastRunText).reports.map((x) => x.result), ['HTTP 400', 'HTTP 202'])
  })

  it('without a key or hub address it sends nothing and says why', async () => {
    for (const [cfg, secret, why] of [
      [hubConfig(), undefined, 'not sent: no key yet (run install.ps1 -NewKey)'],
      [hubConfig({ hubUrl: '' }), KEY, 'not sent: hubUrl is not set in config.json'],
      [hubConfig({ hubUrl: 'http://hub.example.com' }), KEY, 'not sent: hubUrl must start with https:// (or http:// to a private address)'],
    ]) {
      const dir = tempDir(cfg, secret)
      const fetch = fakeFetch(202)
      const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
      assert.equal(fetch.calls.length, 0)
      assert.equal(JSON.parse(r.lastRunText).reports[0].result, why)
      assert.equal(r.state.events.firewall, undefined)
    }
  })

  it('a dry run sends and saves nothing', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const fetch = fakeFetch(202)
    const r = await scan(dir, { args: ['dryRun'], probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 0)
    assert.equal(r.state, null)
    assert.equal(r.lastRunText, '')
    assert.match(r.out, /Would send 1 report/)
    assert.match(r.out, /delivery: hub, ready/)
    assert.equal(r.out.includes(KEY), false)
  })
})

describe('a scan sent to a Discord webhook', () => {
  it('posts one embed to the webhook, with no key, and never logs the URL', async () => {
    const dir = tempDir({ delivery: 'webhook', source: 'pc', kev: { enabled: false } }, WEBHOOK)
    const fetch = fakeFetch(204)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 1)
    const c = fetch.calls[0]
    assert.equal(c.url, WEBHOOK)
    assert.equal(c.init.redirect, 'error')
    assert.equal(c.init.headers.authorization, undefined)
    assert.deepEqual(c.body.allowed_mentions, { parse: [] })
    partial(c.body.embeds[0], { title: 'Windows Firewall is off', footer: { text: 'pc firewall warning' } })
    assert.equal(r.state.events.firewall.sent, 'active')
    assert.match(r.out, /delivery: Discord webhook, ready/)
    for (const text of [r.out, r.lastRunText, JSON.stringify(r.state)]) assert.equal(text.includes('fake_'), false)
  })

  it('a deleted webhook stops the run with a fix', async () => {
    const dir = tempDir({ delivery: 'webhook', source: 'pc', kev: { enabled: false } }, WEBHOOK)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch: fakeFetch(404) })
    assert.match(JSON.parse(r.lastRunText).reports[0].result, /^HTTP 404 \(the webhook no longer exists/)
  })
})

describe('the real fetch, against a hub on loopback', () => {
  async function withServer(handler, fn) {
    const server = createServer(handler)
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      return await fn(`http://127.0.0.1:${server.address().port}`)
    } finally {
      server.closeAllConnections?.()
      await new Promise((resolve) => server.close(resolve))
    }
  }

  it('sends over plain http to a private address with the bearer key and a JSON body', async () => {
    const seen = []
    await withServer(
      (req, res) => {
        let data = ''
        req.on('data', (d) => (data += d))
        req.on('end', () => {
          seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, type: req.headers['content-type'], body: JSON.parse(data) })
          res.writeHead(202).end()
        })
      },
      async (base) => {
        const dir = tempDir(hubConfig({ hubUrl: base }), KEY)
        const r = await scan(dir, { probes: probes({ firewallOff: true }) })
        assert.equal(JSON.parse(r.lastRunText).reports[0].result, 'HTTP 202')
      },
    )
    assert.equal(seen.length, 1)
    partial(seen[0], { method: 'POST', url: '/v1/report', auth: `Bearer ${KEY}`, type: 'application/json' })
    assert.equal(seen[0].body.event, 'firewall')
  })

  it('does not follow a redirect (the key would go with it)', async () => {
    let hits = 0
    await withServer(
      (req, res) => {
        hits++
        req.resume()
        res.writeHead(307, { location: '/elsewhere' }).end()
      },
      async (base) => {
        const dir = tempDir(hubConfig({ hubUrl: base }), KEY)
        const r = await scan(dir, { probes: probes({ firewallOff: true }) })
        assert.equal(JSON.parse(r.lastRunText).reports[0].result, 'network error')
        assert.equal(r.state.events.firewall, undefined)
      },
    )
    assert.equal(hits, 1)
  })
})

describe('files that cannot be read', () => {
  it('a broken config.json sends nothing and its error never quotes the file', async () => {
    const broken = `{"key": x"${KEY}", "delivery": "hub", "hubUrl": "https://hub.example.com"}`
    // The JavaScript error for this text quotes the start of the file, key included.
    assert.throws(() => JSON.parse(broken), (e) => e.message.includes(KEY.slice(0, 8)))
    const dir = tempDir(broken)
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 0)
    const lastRun = JSON.parse(r.lastRunText)
    assert.match(lastRun.configErrors[0], /^config\.json is not valid JSON/)
    for (const text of [r.out, r.lastRunText]) assert.equal(text.includes(KEY.slice(0, 8)), false)
    // It is not moved anywhere either: the file cannot be read.
    assert.equal(readIn(dir, 'config.json'), broken)
    assert.equal(readIn(dir, SECRET_FILE), '')
  })

  it('a watch.json that is not valid JSON makes the app checks unreadable, never clears them', async () => {
    const dir = tempDir(hubConfig({ kev: { enabled: true } }), KEY)
    writeState(dir, { events: { 'apps-behind': { sent: 'active', sentItems: ['Git.Git'], sentAt: NOW - DAY } } })
    writeText(dir, 'watch.json', '{ "apps": [ ')
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes(), fetch })
    assert.equal(fetch.calls.length, 0)
    const lastRun = JSON.parse(r.lastRunText)
    for (const id of ['apps-behind', 'apps-eol', 'exploited']) assert.match(lastRun.unreadable[id], /^watch list: not valid JSON/)
    assert.equal(r.state.events['apps-behind'].sent, 'active')
  })
})

// winget tables as winget prints them to a pipe, with made-up apps and versions.
const WG = { name: 24, id: 22, version: 10, available: 10 }
const wgRow = (name, id, version, available = '', source = 'winget') =>
  name.padEnd(WG.name) + id.padEnd(WG.id) + version.padEnd(WG.version) + available.padEnd(WG.available) + source
function wgTable(rows, footer = []) {
  const header = wgRow('Name', 'Id', 'Version', 'Available', 'Source')
  return [header, '-'.repeat(header.length), ...rows, ...footer, ''].join('\r\n')
}
const ARCHIVER = wgRow('Archiver 12.40 (x64)', 'Contoso.Archiver', '12.40', '13.15')
const VIEWER = wgRow('Old Viewer', 'Contoso.OldViewer', '1.0')
const GIT = wgRow('Git', 'Git.Git', '2.40.0')
const WINGET = {
  upgradeBehind: wgTable([ARCHIVER], ['1 upgrades available.']),
  upgradeNone: 'No available upgrade found.\r\n',
  list: wgTable([ARCHIVER, VIEWER, GIT]),
  // The same two apps, in rows the parser cannot read (an id cannot hold spaces).
  listUnreadable: wgTable([wgRow('Archiver 12.40 (x64)', 'Contoso Archiver x64', '12.40', '13.15'), wgRow('Old Viewer', 'Contoso Old Viewer', '1.0'), GIT]),
  listGone: wgTable([GIT]),
}

/** A stand-in for winget.exe that prints `tables.upgrade` or `tables.list`. */
function fakeWinget(tables) {
  return async (file, args) => ({ error: null, stdout: tables[args[0]], stderr: '' })
}

describe('winget rows the scanner cannot read', () => {
  const ctx = () => ({ now: NOW, deadline: Date.now() + 600_000, cwd: process.cwd() })

  it('make that winget read unreadable', async () => {
    const w = await probeWinget(ctx(), fakeWinget({ upgrade: WINGET.upgradeBehind, list: WINGET.listUnreadable }))
    assert.equal(w.upgrade.ok, true)
    assert.equal(w.list.ok, false)
    assert.equal(w.list.errors[0], 'could not read a row: Archiver 12.40 (x64) Contoso Archiver x64 12.40 13.15 winget (and 1 more)')
  })

  it('never clear apps-eol or an exploited flaw, however many runs see them', async () => {
    const dir = tempDir(hubConfig({ kev: { enabled: true } }), KEY)
    writeText(
      dir,
      'watch.json',
      JSON.stringify({
        apps: [{ id: 'Contoso.Archiver', name: 'Archiver', kev: [{ vendorProject: '^Contoso$', product: '^Archiver' }] }],
        eol: [{ id: 'Contoso.OldViewer', name: 'Old Viewer' }],
      }),
    )
    const kev = { data: { catalogVersion: 'test', vulnerabilities: [{ cveID: 'CVE-2026-1000', vendorProject: 'Contoso', product: 'Archiver', dateAdded: '2025-03-20' }] }, from: 'network' }
    const tables = { upgrade: WINGET.upgradeBehind, list: WINGET.list }
    const withWinget = { ...probes({ kev }), winget: (c) => probeWinget(c, fakeWinget(tables)) }
    const sent = async () => {
      const fetch = fakeFetch(202)
      const r = await scan(dir, { probes: withWinget, fetch })
      return { ...r, reports: fetch.calls.map((c) => `${c.body.event} ${c.body.state}`).sort() }
    }
    assert.deepEqual((await sent()).reports, ['apps-eol triggered', 'exploited triggered'])

    tables.list = WINGET.listUnreadable
    for (let run = 0; run < 3; run++) {
      const r = await sent()
      assert.deepEqual(r.reports, [])
      assert.match(JSON.parse(r.lastRunText).unreadable['apps-eol'], /^could not read a row: /)
      assert.deepEqual(r.state.eolItems.map((i) => i.id), ['Contoso.OldViewer'])
      assert.deepEqual(Object.keys(r.state.kev.findings), ['CVE-2026-1000'])
      assert.equal(r.state.kev.findings['CVE-2026-1000'].absent ?? 0, 0)
    }

    // Good reads that show both apps gone do clear them: the flaw after 2 reads in a row.
    tables.list = WINGET.listGone
    tables.upgrade = WINGET.upgradeNone
    assert.deepEqual((await sent()).reports, ['apps-eol resolved'])
    const last = await sent()
    assert.deepEqual(last.reports, ['exploited resolved'])
    assert.deepEqual(last.state.kev.findings, {})
  })
})

/**
 * A stand-in for wsl.exe. `states` maps each distro to Running or Stopped and can
 * change while a scan runs; `onCheck` runs when a distro is checked, and `listFails`
 * makes a listing time out. `calls` records every argument list.
 */
function fakeWsl(states, { onCheck = () => {}, listFails = () => false } = {}) {
  const calls = []
  const runner = async (file, args) => {
    calls.push(args)
    if (args[0] === '-l') {
      if (listFails(calls.length)) return { error: 'timed out', stdout: '', stderr: '' }
      const rows = Object.entries(states).map(([name, state], i) => `${i ? ' ' : '*'} ${name.padEnd(10)}${state.padEnd(11)}2`)
      return { error: null, stdout: ['  NAME      STATE      VERSION', ...rows, ''].join('\r\n'), stderr: '' }
    }
    onCheck(args[1])
    return { error: null, stdout: 'NETHERSEC_UPDATE_RC=0\nNETHERSEC_SIM_RC=0\n', stderr: '' }
  }
  runner.calls = calls
  return runner
}

describe('the WSL check never starts a distro that stopped', () => {
  const ctx = () => ({ now: NOW, deadline: Date.now() + 600_000, cwd: process.cwd() })
  const wslConfig = (wsl = {}) => ({ wsl: { enabled: true, startStopped: false, ...wsl } })
  const checked = (runner) => runner.calls.filter((a) => a[0] === '-d').map((a) => a[1])

  it('looks again right before each distro, and leaves one that stopped since the list with its last result', async () => {
    const states = { Alpha: 'Running', Beta: 'Running' }
    const runner = fakeWsl(states, { onCheck: (name) => name === 'Alpha' && (states.Beta = 'Stopped') })
    const dir = tempDir(hubConfig({ wsl: { enabled: true } }), KEY)
    const beta = { count: 3, streak: 1, packages: ['openssl'], checkedAt: NOW - 2 * DAY }
    writeState(dir, { wsl: { distros: { Beta: beta }, lastCheck: { Beta: NOW - 2 * DAY } } })
    const r = await scan(dir, { probes: { ...probes(), wsl: (c, s, cfg, skip) => probeWsl(c, s, cfg, skip, runner) }, fetch: fakeFetch(202) })
    assert.deepEqual(checked(runner), ['Alpha'])
    assert.deepEqual(r.state.wsl.distros.Beta, beta)
    assert.deepEqual(r.state.wsl.lastCheck, { Alpha: NOW, Beta: NOW - 2 * DAY })
    assert.match(r.out, /not running, so not checked \(set wsl\.startStopped to start them\): Beta/)
  })

  it('starts nothing when it cannot tell whether a distro still runs', async () => {
    const runner = fakeWsl({ Alpha: 'Running' }, { listFails: (n) => n > 1 })
    const r = await probeWsl(ctx(), {}, wslConfig(), [], runner)
    assert.deepEqual(checked(runner), [])
    assert.deepEqual(r.results, [{ name: 'Alpha', ok: false, error: 'could not check that it is still running' }])
  })

  it('with wsl.startStopped, checks a stopped distro and does not look again', async () => {
    const runner = fakeWsl({ Alpha: 'Running', Beta: 'Stopped' })
    await probeWsl(ctx(), {}, wslConfig({ startStopped: true }), [], runner)
    assert.deepEqual(checked(runner), ['Alpha', 'Beta'])
    assert.equal(runner.calls.filter((a) => a[0] === '-l').length, 1)
  })
})

describe('setup commands', () => {
  const node = (args, opts = {}) => spawnSync(process.execPath, [ENTRY, ...args], { encoding: 'utf8', ...opts })

  /** cli() with the fake DPAPI: no real PowerShell runs. */
  async function setup(argv, { stdin, exec = fakeDpapi() } = {}) {
    const out = []
    const errs = []
    const deps = { log: (s) => out.push(s), err: (s) => errs.push(s), exec, ...(stdin === undefined ? {} : { stdin: () => stdin }) }
    const code = await cli(argv, deps)
    return { code, stdout: out.join('\n'), stderr: errs.join('\n'), exec }
  }
  const config = (dir) => JSON.parse(readIn(dir, 'config.json'))

  it('--new-key saves the key encrypted in secret.dpapi, keeps the other settings, and prints only the hub line', async () => {
    const dir = tempDir({ source: 'laptop', appGraceDays: 3, delivery: 'webhook', webhookUrl: WEBHOOK })
    const r = await setup(['--new-key', '--dir', dir, '--hub-url', 'https://hub.example.com', '--dm', '123456789012345678'])
    assert.equal(r.code, 0, r.stderr)
    const cfg = config(dir)
    partial(cfg, { source: 'laptop', appGraceDays: 3, delivery: 'hub', hubUrl: 'https://hub.example.com' })
    // Neither the new key nor the old webhook URL is left in config.json.
    assert.equal('key' in cfg, false)
    assert.equal('webhookUrl' in cfg, false)
    const key = unprotect(readIn(dir, SECRET_FILE))
    assert.match(key, /^[0-9a-f]{64}$/)
    assert.equal(readIn(dir, SECRET_FILE).includes(key), false)
    const hash = createHash('sha256').update(key).digest('hex')
    assert.ok(r.stdout.split('\n').includes(`laptop ${hash} dm=123456789012345678`), r.stdout)
    assert.match(r.stdout, /encrypted for this Windows account/)
    for (const text of [r.stdout, r.stderr, readIn(dir, 'config.json'), visible(r.exec.calls)]) assert.equal(text.includes(key), false)
    // It went to PowerShell on stdin only, and was read back once to check it.
    assert.deepEqual(r.exec.calls.map((c) => c.kind), ['protect', 'unprotect'])
    assert.equal(r.exec.calls[0].input, key)
    const second = await setup(['--new-key', '--dir', dir])
    assert.equal(second.code, 0)
    assert.notEqual(unprotect(readIn(dir, SECRET_FILE)), key)
    assert.match(second.stdout, /dm=<your Discord user ID>/)
  })

  it('--new-key refuses a bad Discord ID or hub address and changes nothing', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const before = readIn(dir, 'config.json')
    const secretBefore = readIn(dir, SECRET_FILE)
    // The real entry point: both fail before anything reaches PowerShell.
    assert.equal(node(['--new-key', '--dir', dir, '--dm', '12345']).status, 1)
    assert.equal(node(['--new-key', '--dir', dir, '--hub-url', 'http://hub.example.com']).status, 1)
    const r = await setup(['--new-key', '--dir', dir, '--dm', '12345'])
    assert.equal(r.code, 1)
    assert.equal(r.exec.calls.length, 0)
    assert.equal(readIn(dir, 'config.json'), before)
    assert.equal(readIn(dir, SECRET_FILE), secretBefore)
  })

  it('--new-key in a new folder starts from the example config', async () => {
    const dir = tempDir()
    const r = await setup(['--new-key', '--dir', dir])
    assert.equal(r.code, 0, r.stderr)
    const cfg = config(dir)
    partial(cfg, { delivery: 'hub', source: 'pc', hubUrl: '', maxPostsPerRun: 5 })
    assert.equal('key' in cfg, false)
    assert.match(unprotect(readIn(dir, SECRET_FILE)), /^[0-9a-f]{64}$/)
    assert.match(r.stdout, /Set hubUrl in config\.json/)
  })

  it('--set-webhook reads the URL from stdin, saves it encrypted, and never prints it', async () => {
    const dir = tempDir({ ...hubConfig(), key: KEY })
    const r = await setup(['--set-webhook', '--dir', dir], { stdin: `${WEBHOOK}\r\n` })
    assert.equal(r.code, 0, r.stderr)
    const cfg = config(dir)
    partial(cfg, { delivery: 'webhook', hubUrl: 'https://hub.example.com' })
    assert.equal('webhookUrl' in cfg, false)
    assert.equal('key' in cfg, false)
    assert.equal(unprotect(readIn(dir, SECRET_FILE)), WEBHOOK)
    for (const text of [r.stdout, r.stderr, readIn(dir, 'config.json'), readIn(dir, SECRET_FILE), visible(r.exec.calls)]) {
      assert.equal(text.includes('fake_'), false)
    }
  })

  it('--set-webhook refuses something that is not a webhook URL without echoing it', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const r = await setup(['--set-webhook', '--dir', dir], { stdin: 'https://example.com/secret-looking-value\n' })
    assert.equal(r.code, 1)
    assert.equal(`${r.stdout}${r.stderr}`.includes('secret-looking-value'), false)
    assert.equal(r.exec.calls.length, 0)
    assert.equal(config(dir).delivery, 'hub')
    assert.equal(unprotect(readIn(dir, SECRET_FILE)), KEY)
  })

  it('when Windows cannot encrypt, or the encrypted copy does not decrypt, nothing is saved', async () => {
    for (const breakIt of [(e) => (e.failProtect = true), (e) => (e.protectAs = 'someone-else'), (e) => (e.down = 'timed out')]) {
      const dir = tempDir(hubConfig())
      const before = readIn(dir, 'config.json')
      const exec = fakeDpapi()
      breakIt(exec)
      const r = await setup(['--new-key', '--dir', dir], { exec })
      assert.equal(r.code, 1)
      assert.match(r.stderr, /^Not saved: (Windows could not encrypt it|the encrypted copy did not decrypt)/)
      assert.equal(readIn(dir, SECRET_FILE), '')
      assert.equal(readIn(dir, 'config.json'), before)
      for (const c of exec.calls.filter((x) => x.kind === 'protect')) assert.equal(r.stderr.includes(c.input), false)
    }
  })

  it('--help works and an unknown option fails', async () => {
    const out = []
    assert.equal(await cli(['--help'], { log: (s) => out.push(s) }), 0)
    assert.match(out.join('\n'), /--new-key/)
    assert.equal(await cli(['--bogus'], { err: () => {} }), 1)
    assert.equal(await cli(['--dir'], { err: () => {} }), 1)
    const real = node(['--help'])
    assert.equal(real.status, 0)
    assert.match(real.stdout, /secret\.dpapi/)
  })
})

function writeState(dir, state) {
  writeText(dir, 'state.json', JSON.stringify(state))
}

function writeText(dir, file, text) {
  writeFileSync(path.join(dir, file), text)
}
