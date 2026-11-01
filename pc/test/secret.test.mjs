// The key and the webhook URL in secret.dpapi: a scan decrypts it through PowerShell's
// DPAPI (mocked here, so no Windows program runs), a file this account cannot decrypt
// sends nothing and names the fix, a key or URL that an older version left in
// config.json is moved into secret.dpapi, and none of it ever reaches a command line,
// the environment, the console, last-run.json or state.json.
// Keys and webhook URLs are built from pieces at runtime; none is real.
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import path from 'node:path'
import { SECRET_FILE } from '../pc-security-run.mjs'
import { KEY, WEBHOOK, fakeDpapi, fakeFetch, hubConfig, probes, protect, readIn, removeTempDirs, scan, tempDir, unprotect, visible } from './helpers.mjs'

after(removeTempDirs)

const webhookConfig = (over = {}) => ({ delivery: 'webhook', source: 'pc', kev: { enabled: false }, ...over })

/** Every place a scan could leave the secret, besides the request itself. */
function leaks(dir, r) {
  return [r.out, r.lastRunText, JSON.stringify(r.state), readIn(dir, 'config.json'), readIn(dir, SECRET_FILE), visible(r.exec.calls)]
}

describe('reading the secret at run time', () => {
  it('decrypts the key from secret.dpapi on stdin and sends with it; the key is on no command line and in no output', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const encrypted = readIn(dir, SECRET_FILE).trim()
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 1)
    assert.equal(fetch.calls[0].init.headers.authorization, `Bearer ${KEY}`)
    assert.match(r.out, /delivery: hub, ready/)
    // One PowerShell child: the encrypted text in on stdin, no arguments that carry it.
    assert.equal(r.exec.calls.length, 1)
    const c = r.exec.calls[0]
    assert.equal(c.file, 'powershell.exe')
    assert.equal(c.kind, 'unprotect')
    assert.equal(c.input, encrypted)
    assert.deepEqual(c.args.slice(0, -1), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand'])
    assert.equal(c.env, undefined)
    for (const text of leaks(dir, r)) assert.equal(text.includes(KEY), false)
    // config.json is not touched.
    assert.deepEqual(JSON.parse(readIn(dir, 'config.json')), hubConfig())
  })

  it('does the same for a webhook URL', async () => {
    const dir = tempDir(webhookConfig(), WEBHOOK)
    const fetch = fakeFetch(204)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 1)
    assert.equal(fetch.calls[0].url, WEBHOOK)
    assert.match(r.out, /delivery: Discord webhook, ready/)
    for (const text of leaks(dir, r)) assert.equal(text.includes('fake_'), false)
  })

  it('a dry run decrypts it too, so it shows whether reports can go out, and prints none of it', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const r = await scan(dir, { args: ['dryRun'], probes: probes({ firewallOff: true }), fetch: fakeFetch(202) })
    assert.match(r.out, /delivery: hub, ready/)
    assert.equal(r.out.includes(KEY), false)
    const json = await scan(dir, { args: ['dryRun', 'json'], probes: probes({ firewallOff: true }), fetch: fakeFetch(202) })
    assert.equal(json.out.includes(KEY), false)
    assert.equal(JSON.parse(json.out).wouldSend.length, 1)
  })

  it('reads nothing and runs nothing when the scanner is turned off', async () => {
    const dir = tempDir(hubConfig({ disabled: true }), KEY)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch: fakeFetch(202) })
    assert.equal(r.exec.calls.length, 0)
  })
})

describe('a secret.dpapi that cannot be decrypted', () => {
  it('made by another account: nothing is sent, the run says why and names -NewKey, and the report waits', async () => {
    const dir = tempDir(hubConfig(), KEY, 'someone-else')
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 0)
    const why =
      'the key in secret.dpapi cannot be decrypted by this Windows account (it was made by another account or on another PC, or it is damaged); run install.ps1 -NewKey again'
    assert.match(r.out, new RegExp(`delivery: hub, not ready: ${escape(why)}`))
    assert.match(r.out, new RegExp(`config problem: ${escape(why)} \\(nothing is sent until it is fixed\\)`))
    const lastRun = JSON.parse(r.lastRunText)
    assert.deepEqual(lastRun.reports, [{ event: 'firewall', state: 'triggered', reason: 'new', result: `not sent: ${why}` }])
    assert.ok(lastRun.configErrors.includes(`${why} (nothing is sent until it is fixed)`))
    assert.equal(r.state.events.firewall, undefined)
    // Once it is fixed, the waiting report goes out.
    writeFileSync(path.join(dir, SECRET_FILE), `${protect(KEY)}\n`)
    const fetch2 = fakeFetch(202)
    await scan(dir, { probes: probes({ firewallOff: true }), fetch: fetch2 })
    assert.equal(fetch2.calls.length, 1)
  })

  it('for a webhook it names -Webhook', async () => {
    const dir = tempDir(webhookConfig(), WEBHOOK, 'someone-else')
    const fetch = fakeFetch(204)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 0)
    assert.match(JSON.parse(r.lastRunText).reports[0].result, /^not sent: the webhook URL in secret\.dpapi cannot be decrypted by this Windows account .*run install\.ps1 -Webhook again$/)
  })

  it('a damaged or empty file is refused the same way, never sent', async () => {
    for (const [text, why] of [
      ['0000feed-not-what-was-written\n', /cannot be decrypted by this Windows account/],
      ['\n', /^not sent: secret\.dpapi is empty; run install\.ps1 -NewKey again$/],
    ]) {
      const dir = tempDir(hubConfig())
      writeFileSync(path.join(dir, SECRET_FILE), text)
      const fetch = fakeFetch(202)
      const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
      assert.equal(fetch.calls.length, 0)
      assert.match(JSON.parse(r.lastRunText).reports[0].result, why)
    }
  })

  it('a key file used for a webhook (or the other way round) is not sent anywhere', async () => {
    const dir = tempDir(webhookConfig(), KEY)
    const fetch = fakeFetch(204)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 0)
    assert.match(JSON.parse(r.lastRunText).reports[0].result, /^not sent: the webhook URL in secret\.dpapi is not a Discord webhook URL/)
    assert.equal(r.out.includes(KEY), false)
  })

  it('PowerShell that gives no answer leaves the report waiting, without a config problem line', async () => {
    const dir = tempDir(hubConfig(), KEY)
    const exec = fakeDpapi()
    exec.down = 'timed out'
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch, exec })
    assert.equal(fetch.calls.length, 0)
    const lastRun = JSON.parse(r.lastRunText)
    assert.equal(lastRun.reports[0].result, 'not sent: secret.dpapi could not be read this run (PowerShell timed out)')
    assert.deepEqual(lastRun.configErrors, [])
    assert.equal(r.state.events.firewall, undefined)
  })
})

describe('moving a key or URL out of an older config.json', () => {
  it('a key in config.json still sends, and the run moves it into secret.dpapi and out of config.json', async () => {
    const dir = tempDir({ ...hubConfig(), key: KEY, webhookUrl: '', appGraceDays: 3 })
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 1)
    assert.equal(fetch.calls[0].init.headers.authorization, `Bearer ${KEY}`)
    const cfg = JSON.parse(readIn(dir, 'config.json'))
    assert.deepEqual(cfg, { ...hubConfig(), appGraceDays: 3 })
    assert.equal(unprotect(readIn(dir, SECRET_FILE)), KEY)
    // Encrypted on stdin, then decrypted once to check it, before config.json changed.
    assert.deepEqual(r.exec.calls.map((c) => c.kind), ['protect', 'unprotect'])
    assert.equal(r.exec.calls[0].input, KEY)
    const note = 'moved the key from config.json into secret.dpapi, encrypted for this Windows account'
    assert.match(r.out, new RegExp(`delivery note: ${escape(note)}`))
    assert.deepEqual(JSON.parse(r.lastRunText).deliveryNotes, [note])
    for (const text of leaks(dir, r)) assert.equal(text.includes(KEY), false)
    // The next run reads it from secret.dpapi.
    const fixed = fakeFetch(202)
    const r2 = await scan(dir, { probes: probes(), fetch: fixed })
    assert.equal(fixed.calls[0].init.headers.authorization, `Bearer ${KEY}`)
    assert.deepEqual(r2.exec.calls.map((c) => c.kind), ['unprotect'])
    assert.deepEqual(JSON.parse(r2.lastRunText).deliveryNotes, [])
  })

  it('a webhook URL moves the same way, and an unused old key goes with it', async () => {
    const dir = tempDir(webhookConfig({ webhookUrl: WEBHOOK, key: KEY }))
    const fetch = fakeFetch(204)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls[0].url, WEBHOOK)
    assert.deepEqual(JSON.parse(readIn(dir, 'config.json')), webhookConfig())
    assert.equal(unprotect(readIn(dir, SECRET_FILE)), WEBHOOK)
    assert.match(r.out, /delivery note: moved the webhook URL from config\.json into secret\.dpapi, encrypted for this Windows account \(the unused key was taken out too\)/)
    for (const text of leaks(dir, r)) {
      assert.equal(text.includes('fake_'), false)
      assert.equal(text.includes(KEY), false)
    }
  })

  it('a dry run leaves config.json as it is and says the next run moves it', async () => {
    const before = { ...hubConfig(), key: KEY }
    const dir = tempDir(before)
    const r = await scan(dir, { args: ['dryRun'], probes: probes({ firewallOff: true }), fetch: fakeFetch(202) })
    assert.deepEqual(JSON.parse(readIn(dir, 'config.json')), before)
    assert.equal(readIn(dir, SECRET_FILE), '')
    assert.equal(r.exec.calls.length, 0)
    assert.match(r.out, /delivery: hub, ready/)
    assert.match(r.out, /delivery note: the key is still in config\.json in plain text; the next run that is not a dry run moves it into secret\.dpapi/)
    assert.equal(r.out.includes(KEY), false)
  })

  it('when the move fails, config.json keeps the key, the report still goes, and the run says why', async () => {
    for (const breakIt of [(e) => (e.failProtect = true), (e) => (e.protectAs = 'someone-else'), (e) => (e.down = 'timed out')]) {
      const before = { ...hubConfig(), key: KEY }
      const dir = tempDir(before)
      const exec = fakeDpapi()
      breakIt(exec)
      const fetch = fakeFetch(202)
      const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch, exec })
      assert.equal(fetch.calls.length, 1)
      assert.equal(fetch.calls[0].init.headers.authorization, `Bearer ${KEY}`)
      assert.deepEqual(JSON.parse(readIn(dir, 'config.json')), before)
      // A file that does not decrypt is never written.
      assert.equal(readIn(dir, SECRET_FILE), '')
      const lastRun = JSON.parse(r.lastRunText)
      assert.equal(lastRun.configErrors.length, 1)
      assert.match(lastRun.configErrors[0], /^the key is still in config\.json in plain text: moving it into secret\.dpapi failed \((Windows could not encrypt it|the encrypted copy did not decrypt): .*\); the next run tries again$/)
      for (const text of [r.out, r.lastRunText, visible(exec.calls)]) assert.equal(text.includes(KEY), false)
    }
  })

  it('a key in config.json that is not a key is not moved, and the run says what is wrong', async () => {
    const dir = tempDir({ ...hubConfig(), key: 'ab' })
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls.length, 0)
    assert.equal(r.exec.calls.length, 0)
    assert.equal(readIn(dir, SECRET_FILE), '')
    assert.equal(JSON.parse(r.lastRunText).reports[0].result, 'not sent: the key in config.json is not 64 lowercase hex characters (run install.ps1 -NewKey)')
  })

  it('a plain-text secret that the delivery mode does not use is flagged, never moved or printed', async () => {
    const dir = tempDir({ ...hubConfig(), webhookUrl: WEBHOOK }, KEY)
    const fetch = fakeFetch(202)
    const r = await scan(dir, { probes: probes({ firewallOff: true }), fetch })
    assert.equal(fetch.calls[0].init.headers.authorization, `Bearer ${KEY}`)
    assert.deepEqual(JSON.parse(r.lastRunText).configErrors, ['config.json holds a webhookUrl in plain text that delivery "hub" does not use; delete it from config.json'])
    assert.equal(JSON.parse(readIn(dir, 'config.json')).webhookUrl, WEBHOOK)
    for (const text of [r.out, r.lastRunText, visible(r.exec.calls)]) assert.equal(text.includes('fake_'), false)
  })
})

function escape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
