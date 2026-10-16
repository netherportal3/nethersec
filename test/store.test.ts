import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { loadConfig } from '../src/config.js'
import { normalizeState } from '../src/state.js'
import { Store } from '../src/store.js'

describe('Store', () => {
  it('starts empty, saves, and loads back', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cve-store-'))
    const store = await Store.open(dir, 60)
    expect(store.state.setup).toBeNull()
    store.state.settings.minSeverity = 'critical'
    await store.save()
    await store.save()
    const again = await Store.open(dir, 60)
    expect(again.state.settings.minSeverity).toBe('critical')
    expect(JSON.parse(await readFile(path.join(dir, 'state.json.bak'), 'utf8')).settings.minSeverity).toBe('critical')
  })

  it('falls back to the backup when the main file is damaged, and refuses to silently start over', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cve-store-'))
    const store = await Store.open(dir, 60)
    store.state.settings.paused = true
    await store.save()
    await store.save()
    await writeFile(path.join(dir, 'state.json'), '{ broken', 'utf8')
    expect((await Store.open(dir, 60)).state.settings.paused).toBe(true)
    await writeFile(path.join(dir, 'state.json.bak'), 'also broken', 'utf8')
    await expect(Store.open(dir, 60)).rejects.toThrow(/could not be read/)
  })

  it('fills in defaults for missing fields', () => {
    const s = normalizeState({ settings: { minSeverity: 'low', repos: 'nope' } }, 30)
    expect(s.settings.minSeverity).toBe('low')
    expect(s.settings.repos).toEqual([])
    expect(s.settings.intervalMinutes).toBe(30)
    expect(s.mutes).toEqual([])
  })

  it('moves an older one-flag baseline to per-ecosystem flags, and drops broken repo entries', () => {
    const repo = (baselined: unknown) => ({ name: 'me/a', baselined, findings: {}, unreadableRuns: 0, unreadableNotified: false, lockfiles: 1, skipped: [] })
    const s = normalizeState({ repos: { 'me/a': repo(true), 'me/b': { ...repo(false), name: 'me/b' }, 'me/c': { ...repo({ npm: true }), name: 'me/c' }, bad: 'x' } }, 60)
    expect(s.repos['me/a'].baselined).toEqual({ npm: true, PyPI: true })
    expect(s.repos['me/b'].baselined).toEqual({})
    expect(s.repos['me/c'].baselined).toEqual({ npm: true })
    expect(s.repos.bad).toBeUndefined()
  })
})

describe('loadConfig', () => {
  const env = { DISCORD_TOKEN: 'x', DISCORD_GUILD_ID: '1234567890', GITHUB_TOKEN: 'y' }
  it('reads the required settings and defaults the rest', () => {
    expect(loadConfig(env)).toEqual({ discordToken: 'x', guildId: '1234567890', githubToken: 'y', dataDir: './data', intervalMinutes: 60 })
  })
  it('names what is missing or wrong', () => {
    expect(() => loadConfig({})).toThrow('DISCORD_TOKEN, DISCORD_GUILD_ID, GITHUB_TOKEN')
    expect(() => loadConfig({ ...env, DISCORD_GUILD_ID: 'my server' })).toThrow('server ID')
    expect(() => loadConfig({ ...env, SCAN_INTERVAL_MINUTES: '5' })).toThrow('15 to 1440')
  })
})
