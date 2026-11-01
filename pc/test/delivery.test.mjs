// Delivery settings and requests: the hub (docs/report-protocol.md) or a Discord webhook.
// Keys and webhook URLs here are built from pieces at runtime; none is real.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as lib from '../pc-security-lib.mjs'

const KEY = 'ab'.repeat(32)
const WEBHOOK = ['https://discord.com/api/webhooks', '123456789012345678', `fake_${'x'.repeat(60)}`].join('/')
const hub = (over = {}) => ({ delivery: 'hub', hubUrl: 'https://hub.example.com', source: 'pc', ...over })
// What the run read from secret.dpapi (or, from an older version, config.json).
const key = (value = KEY, from = 'secret.dpapi') => ({ value, from })
const hook = (value = WEBHOOK, from = 'secret.dpapi') => ({ value, from })
const body = { v: 1, kind: 'security', source: 'pc', event: 'firewall', state: 'triggered', severity: 'warning', title: 'Windows Firewall is off', detail: 'Off for: Public network.' }

describe('delivery settings', () => {
  it('a hub with https, a key and a valid source is ready', () => {
    assert.deepEqual(lib.checkDelivery(hub(), key()), { mode: 'hub', ok: true, problem: '', errors: [] })
    assert.equal(lib.checkDelivery(hub({ delivery: undefined }), key()).mode, 'hub')
    assert.equal(lib.deliveryMode({ delivery: '' }), 'hub')
    assert.equal(lib.deliveryMode({ delivery: 'webhook' }), 'webhook')
  })

  it('a fresh install is not ready and says what is missing, without an error', () => {
    const fresh = lib.checkDelivery({ delivery: 'hub', hubUrl: '', source: 'pc' }, {})
    assert.equal(fresh.ok, false)
    assert.equal(fresh.problem, 'hubUrl is not set in config.json')
    assert.deepEqual(fresh.errors, [])
    assert.equal(lib.checkDelivery(hub(), {}).problem, 'no key yet (run install.ps1 -NewKey)')
    assert.equal(lib.checkDelivery(hub()).problem, 'no key yet (run install.ps1 -NewKey)')
    assert.equal(lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, {}).problem, 'no webhook URL yet (run install.ps1 -Webhook)')
  })

  it('plain http only to a loopback or private address, or with allowHttp', () => {
    assert.equal(lib.checkDelivery(hub({ hubUrl: 'http://hub.example.com' }), key()).ok, false)
    assert.match(lib.checkDelivery(hub({ hubUrl: 'http://hub.example.com' }), key()).errors[0], /must start with https/)
    assert.equal(lib.checkDelivery(hub({ hubUrl: 'http://hub.example.com', allowHttp: true }), key()).ok, true)
    for (const u of ['http://127.0.0.1:8787', 'http://10.20.30.40:8787', 'http://172.20.0.5', 'http://192.168.200.7:8787', 'http://100.64.7.9:8787', 'http://[::1]:8787', 'http://[fd12:3456::1]/']) {
      assert.equal(lib.checkDelivery(hub({ hubUrl: u }), key()).ok, true, u)
    }
    for (const u of ['http://203.0.113.10:8787', 'http://172.32.0.1', 'http://100.128.0.1', 'http://localhost.example.com']) {
      assert.equal(lib.checkDelivery(hub({ hubUrl: u }), key()).ok, false, u)
    }
  })

  it('refuses a bad key, a bad source, a URL with a password, and an unknown mode', () => {
    assert.equal(lib.checkDelivery(hub(), key('AB'.repeat(32))).problem, 'the key in secret.dpapi is not 64 lowercase hex characters (run install.ps1 -NewKey)')
    assert.equal(lib.checkDelivery(hub(), key('ab', 'config.json')).problem, 'the key in config.json is not 64 lowercase hex characters (run install.ps1 -NewKey)')
    assert.match(lib.checkDelivery(hub({ source: 'My PC' }), key()).problem, /^source must be/)
    assert.match(lib.checkDelivery(hub({ source: 'x'.repeat(41) }), key()).problem, /^source must be/)
    assert.match(lib.checkDelivery(hub({ hubUrl: 'https://user:pw@hub.example.com' }), key()).problem, /user name or password/)
    assert.match(lib.checkDelivery(hub({ hubUrl: 'not a url' }), key()).problem, /not a usable URL/)
    assert.match(lib.checkDelivery(hub({ delivery: 'email' }), key()).problem, /delivery must be/)
  })

  it('a secret that cannot be read is an error that stops sending; one that may pass is only a problem', () => {
    const cannot = lib.checkDelivery(hub(), { error: 'the key in secret.dpapi cannot be decrypted by this Windows account' })
    assert.equal(cannot.ok, false)
    assert.equal(cannot.problem, 'the key in secret.dpapi cannot be decrypted by this Windows account')
    assert.deepEqual(cannot.errors, ['the key in secret.dpapi cannot be decrypted by this Windows account (nothing is sent until it is fixed)'])
    const later = lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, { problem: 'secret.dpapi could not be read this run (PowerShell timed out)' })
    assert.equal(later.ok, false)
    assert.equal(later.problem, 'secret.dpapi could not be read this run (PowerShell timed out)')
    assert.deepEqual(later.errors, [])
  })

  it('a webhook needs a Discord webhook URL', () => {
    assert.equal(lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, hook()).ok, true)
    assert.match(lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, hook('')).problem, /^no webhook URL yet/)
    const bad = lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, hook(WEBHOOK.replace('https:', 'http:')))
    assert.match(bad.problem, /^the webhook URL in secret[.]dpapi is not a Discord webhook URL/)
    // A key cannot be used as a webhook URL, or the other way round.
    assert.equal(lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, hook(KEY)).ok, false)
    assert.equal(lib.checkDelivery(hub(), key(WEBHOOK)).ok, false)
  })

  it('recognizes Discord webhook URLs and nothing else', () => {
    assert.equal(lib.isDiscordWebhookUrl(WEBHOOK), true)
    assert.equal(lib.isDiscordWebhookUrl(WEBHOOK.replace('discord.com', 'canary.discord.com')), true)
    assert.equal(lib.isDiscordWebhookUrl(WEBHOOK.replace('/api/', '/api/v10/')), true)
    assert.equal(lib.isDiscordWebhookUrl(WEBHOOK.replace('discord.com', 'discord.com.example.com')), false)
    assert.equal(lib.isDiscordWebhookUrl(WEBHOOK.replace('discord.com', 'discord.com:8443')), false)
    assert.equal(lib.isDiscordWebhookUrl('https://discord.com/api/webhooks/123456789012345678'), false)
    assert.equal(lib.isDiscordWebhookUrl('https://example.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz'), false)
    assert.equal(lib.isDiscordWebhookUrl(undefined), false)
  })

  it('no problem or error line ever contains the key or the webhook URL', () => {
    const lines = [
      ...Object.values(lib.checkDelivery(hub(), key(`${KEY}0`))),
      ...Object.values(lib.checkDelivery(hub(), key(WEBHOOK))),
      ...Object.values(lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, hook(WEBHOOK.replace('https:', 'http:')))),
      ...Object.values(lib.checkDelivery({ delivery: 'webhook', source: 'pc' }, hook(KEY))),
      ...Object.values(lib.validateConfig(hub({ wsl: { skip: ['(['] } }), key(`${KEY}0`))),
    ].flat()
    for (const l of lines) {
      if (typeof l !== 'string') continue
      assert.equal(l.includes(KEY), false)
      assert.equal(l.includes('fake_'), false)
    }
  })

  it('validateConfig carries the delivery result and the wsl.skip check', () => {
    const v = lib.validateConfig(hub({ wsl: { skip: ['^docker-desktop'] } }), key())
    assert.equal(v.sendOk, true)
    assert.equal(v.mode, 'hub')
    assert.deepEqual(v.wslSkip.map((r) => r.source), ['^docker-desktop'])
    const broken = lib.validateConfig(hub({ wsl: { skip: ['^docker-desktop', '(['] } }), key())
    assert.equal(broken.wslSkip, null)
    assert.match(broken.errors[0], /^wsl\.skip has a pattern that is not valid/)
    assert.equal(lib.validateConfig({ ...hub(), hubUrl: '' }, key()).sendProblem, 'hubUrl is not set in config.json')
  })
})

describe('hub endpoint', () => {
  it('appends /v1/report to the hub address, keeping a path prefix', () => {
    assert.equal(lib.hubReportUrl('https://hub.example.com').href, 'https://hub.example.com/v1/report')
    assert.equal(lib.hubReportUrl('https://hub.example.com/').href, 'https://hub.example.com/v1/report')
    assert.equal(lib.hubReportUrl('https://example.com/nethersec/').href, 'https://example.com/nethersec/v1/report')
    assert.equal(lib.hubReportUrl('https://hub.example.com/v1/report').href, 'https://hub.example.com/v1/report')
    assert.equal(lib.hubReportUrl('http://127.0.0.1:8787?x=1#y').href, 'http://127.0.0.1:8787/v1/report')
  })

  it('knows private addresses by IP literal only', () => {
    assert.equal(lib.isPrivateHost('localhost'), true)
    assert.equal(lib.isPrivateHost('[::1]'), true)
    assert.equal(lib.isPrivateHost('192.168.77.1'), true)
    assert.equal(lib.isPrivateHost('999.168.0.1'), false)
    assert.equal(lib.isPrivateHost('hub.lan'), false)
    assert.equal(lib.isPrivateHost('198.51.100.7'), false)
  })
})

describe('requests', () => {
  it('a hub request posts the protocol body with the key as a bearer token', () => {
    const r = lib.deliveryRequest(hub(), KEY, body)
    assert.equal(r.mode, 'hub')
    assert.equal(r.url, 'https://hub.example.com/v1/report')
    assert.deepEqual(r.headers, { 'content-type': 'application/json', authorization: `Bearer ${KEY}` })
    assert.deepEqual(JSON.parse(r.body), body)
  })

  it('a webhook request posts one embed, with no key and no way to ping', () => {
    const r = lib.deliveryRequest({ delivery: 'webhook', source: 'pc' }, WEBHOOK, body)
    assert.equal(r.mode, 'webhook')
    assert.equal(r.url, WEBHOOK)
    assert.deepEqual(r.headers, { 'content-type': 'application/json' })
    const p = JSON.parse(r.body)
    assert.deepEqual(p.allowed_mentions, { parse: [] })
    assert.equal(p.content, undefined)
    assert.equal(p.embeds.length, 1)
    assert.deepEqual(p.embeds[0], { title: body.title, description: body.detail, color: 0xf57c00, footer: { text: 'pc firewall warning' } })
  })

  it('colors follow the severity, and a resolved report is green', () => {
    assert.equal(lib.discordPayload({ ...body, severity: 'critical' }).embeds[0].color, 0xd32f2f)
    assert.equal(lib.discordPayload({ ...body, severity: 'info' }).embeds[0].color, 0x1976d2)
    const done = lib.discordPayload({ ...body, state: 'resolved', severity: undefined })
    assert.equal(done.embeds[0].color, 0x388e3c)
    assert.equal(done.embeds[0].footer.text, 'pc firewall resolved')
  })

  it('names from the PC cannot format the Discord message or hide a link', () => {
    assert.equal(lib.discordText('a *b* _c_ ~~d~~ `e` ||f|| [g](h) <@1> \\'), 'a \\*b\\* \\_c\\_ \\~\\~d\\~\\~ \\`e\\` \\|\\|f\\|\\| \\[g\\](h) \\<@1\\> \\\\')
    assert.equal(lib.discordText('# Head\n- item\nok'), '\\# Head\n\\- item\nok')
    assert.equal(lib.discordText(`a${String.fromCharCode(7)}b`), 'ab')
    const p = lib.discordPayload({ ...body, title: `x_${String.fromCharCode(10)}y`, detail: 'z'.repeat(5000) })
    assert.equal(p.embeds[0].title, 'x\\_y')
    assert.ok(p.embeds[0].description.length <= 4000)
  })
})

describe('responses', () => {
  it('only a 2xx counts as sent', () => {
    for (const s of [200, 202, 204]) assert.deepEqual(lib.responseOutcome(s, 'hub'), { sent: true, stop: '' })
    for (const s of [301, 400, 413, 418]) assert.deepEqual(lib.responseOutcome(s, 'hub'), { sent: false, stop: '' })
  })

  it('stops the run when the next reports would fail the same way', () => {
    assert.equal(lib.responseOutcome(401, 'hub').stop, 'the hub did not accept the key')
    assert.equal(lib.responseOutcome(403, 'hub').stop, 'the hub refused this key for this source')
    assert.equal(lib.responseOutcome(404, 'hub').stop, 'no report endpoint at hubUrl')
    assert.equal(lib.responseOutcome(429, 'hub').stop, 'the hub asked to slow down')
    assert.equal(lib.responseOutcome(503, 'hub').stop, 'the hub could not deliver it now')
    assert.equal(lib.responseOutcome(429, 'webhook').stop, 'Discord asked to slow down')
    assert.match(lib.responseOutcome(404, 'webhook').stop, /^the webhook no longer exists/)
    for (const s of [401, 403, 404, 429, 500, 503]) assert.equal(lib.responseOutcome(s, 'webhook').sent, false)
  })
})
