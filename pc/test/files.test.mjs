// The files that get installed: no dependencies, examples that work, and an installer
// that copies everything the scanner needs.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as lib from '../pc-security-lib.mjs'

const PC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (f) => readFileSync(path.join(PC_DIR, f), 'utf8')
const MODULES = ['pc-security-report.mjs', 'pc-security-run.mjs', 'pc-security-lib.mjs']

describe('shipped files', () => {
  it('the scanner imports only Node built-ins and its own modules', () => {
    for (const f of MODULES) {
      const specs = [...read(f).matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)].map((m) => m[1])
      for (const s of specs) assert.ok(s.startsWith('node:') || MODULES.includes(s.replace(/^\.\//, '')), `${f} imports ${s}`)
    }
  })

  it('install.ps1 copies every module and example the scanner loads', () => {
    const m = /\$files = @\(([^)]*)\)/.exec(read('install.ps1'))
    assert.ok(m, 'no $files list in install.ps1')
    const copied = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1])
    for (const f of [...MODULES, 'config.example.json', 'watch.example.json']) assert.ok(copied.includes(f), `install.ps1 does not copy ${f}`)
  })

  it('the example config is valid, sends nowhere until set up, and its budgets fit the 20-minute task limit', () => {
    const cfg = JSON.parse(read('config.example.json'))
    const v = lib.validateConfig(cfg)
    assert.deepEqual(v.errors, [])
    assert.equal(v.sendOk, false)
    assert.deepEqual({ delivery: cfg.delivery, hubUrl: cfg.hubUrl, source: cfg.source }, { delivery: 'hub', hubUrl: '', source: 'pc' })
    // The key and the webhook URL live in secret.dpapi, never in config.json.
    assert.equal('key' in cfg, false)
    assert.equal('webhookUrl' in cfg, false)
    assert.deepEqual(v.wslSkip.map((r) => r.source), ['^docker-desktop'])
    assert.equal(cfg.wsl.startStopped, false)
    assert.ok(cfg.checkBudgetMinutes < cfg.reportBudgetMinutes)
    assert.ok(cfg.reportBudgetMinutes < 20)
    assert.match(read('install.ps1'), /-ExecutionTimeLimit \(New-TimeSpan -Minutes 20\)/)
  })

  it('the example watch list is a clean generic starting point', () => {
    const raw = JSON.parse(read('watch.example.json'))
    const w = lib.normalizeWatch(raw)
    assert.deepEqual(w.errors, [])
    assert.deepEqual(w.skipped, [])
    assert.equal(w.apps.length, raw.apps.length)
    assert.equal(w.eol.length, raw.eol.length)
    for (const e of [...w.apps, ...w.eol]) assert.ok(e.name && e.name !== e.id, `${e.key} needs a readable name`)
    assert.equal(new Set(w.apps.map((e) => e.key)).size, w.apps.length)
  })

  it('things only Windows can run keep their safety details', () => {
    const src = read('pc-security-run.mjs')
    // A timed-out child is killed with everything it started.
    assert.ok(src.includes("spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F']"))
    // The Linux side of the WSL check stops itself before the Windows side gives up.
    assert.ok(src.includes('set -- timeout -k 10'))
    // The check budget starts when the run starts.
    assert.ok(src.includes('deadline: started + Number(config.checkBudgetMinutes) * 60_000'))
  })

  it('the installer limits the install folder, config.json and secret.dpapi to the current account', () => {
    const ps = read('install.ps1')
    assert.match(ps, /SetAccessRuleProtection\(\$true, \$false\)/)
    assert.match(ps, /Set-OwnerOnlyAccess \$dest/)
    assert.match(ps, /Set-OwnerOnlyAccess \$cfgPath/)
    assert.match(ps, /\$secretPath = Join-Path \$dest 'secret\.dpapi'/)
    assert.match(ps, /Set-OwnerOnlyAccess \$secretPath/)
    // The key is made by node and the webhook URL goes in on stdin, never as an argument.
    assert.match(ps, /\$plain \| & \$node \$script '--set-webhook'/)
    assert.doesNotMatch(ps, /--set-webhook'[^\n]*\$plain/)
    // The installer never decrypts or prints the secret itself.
    assert.doesNotMatch(ps, /ConvertTo-SecureString|ConvertFrom-SecureString|ProtectedData/)
  })

  it('the DPAPI PowerShell uses the current account, and the secret passes no command, log or transcript', () => {
    const src = read('pc-security-run.mjs')
    const block = (name) => new RegExp(`const ${name} = String\\.raw\`([^\`]*)\``).exec(src)?.[1] ?? ''
    const protect = block('PROTECT_PS')
    const unprotect = block('UNPROTECT_PS')
    for (const s of [protect, unprotect]) {
      assert.match(s, /\$hex = \[Console\]::In\.ReadToEnd\(\)|\$plain = \[Console\]::In\.ReadToEnd\(\)/)
      assert.match(s, /\[Security\.Cryptography\.DataProtectionScope\]::CurrentUser/)
      // No cmdlet that takes the plain text as a parameter (module logging records those),
      // and no environment variables.
      assert.doesNotMatch(s, /SecureString|-AsPlainText|\$env:/)
    }
    assert.match(protect, /ProtectedData\]::Protect\(\$bytes, \$null,/)
    assert.match(unprotect, /ProtectedData\]::Unprotect\(\$enc, \$null,/)
    // The plain text goes straight to stdout, not through PowerShell's output (a transcript
    // records that). Only the error answer, which holds no secret, uses Out-Json.
    assert.match(unprotect, /\[Console\]::Out\.Write\('\{"secretHex":"' \+ \[BitConverter\]::ToString\(\$bytes\)/)
    assert.deepEqual([...unprotect.matchAll(/Out-Json \(\[ordered\]@\{ (\w+)/g)].map((m) => m[1]), ['error'])
  })
})
