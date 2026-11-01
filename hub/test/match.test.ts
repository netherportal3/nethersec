import { describe, expect, it } from 'vitest'
import { buildAdvisoryIndex } from '../src/scanner/advisories.js'
import type { ParsedLockfile } from '../src/scanner/lockfiles.js'
import { applyGlobalFixes, fixLookupGhsa, matchRepo } from '../src/scanner/match.js'
import { advisory } from './helpers.js'

function lock(path: string, pkgs: Array<[string, string, boolean | null]>, ecosystem: 'npm' | 'PyPI' = 'npm'): ParsedLockfile {
  return {
    path,
    kind: ecosystem === 'npm' ? 'npm' : 'pip',
    ecosystem,
    packages: pkgs.map(([name, version, dev]) => ({ name, version, dev })),
    unpinned: 0,
  }
}

describe('matchRepo', () => {
  it('collapses one advisory across lockfiles and sources into one finding with the highest known severity', () => {
    const idx = buildAdvisoryIndex([
      advisory({ id: 'GHSA-aaaa-aaaa-aaaa', packageName: 'lodash', range: '<4.17.21', severity: 'moderate' }),
      advisory({ id: 'GHSA-aaaa-aaaa-aaaa', packageName: 'lodash', range: '<4.17.21', severity: 'high', source: 'github', patched: ['4.17.21'] }),
    ])
    const out = matchRepo('me/app', [lock('a/package-lock.json', [['lodash', '4.17.20', true]]), lock('b/package-lock.json', [['lodash', '4.17.19', false]])], idx)
    expect(out).toHaveLength(1)
    expect(out[0]).toMatchObject({
      repo: 'me/app',
      key: 'GHSA-aaaa-aaaa-aaaa:lodash',
      severity: 'high',
      installed: ['4.17.20', '4.17.19'],
      lockfiles: ['a/package-lock.json', 'b/package-lock.json'],
      devOnly: false,
      sources: ['npm', 'github'],
    })
    expect(out[0].fixes.map((f) => f.to)).toEqual(['4.17.21', '4.17.21'])
  })

  it('dev-only only when every matched copy is dev; versions outside the range do not match', () => {
    const idx = buildAdvisoryIndex([advisory({ id: 'GHSA-bbbb-bbbb-bbbb', packageName: 'x', range: '<2.0.0' })])
    const out = matchRepo('me/app', [lock('package-lock.json', [['x', '1.0.0', true], ['x', '2.0.0', false]])], idx)
    expect(out).toHaveLength(1)
    expect(out[0].devOnly).toBe(true)
    expect(out[0].installed).toEqual(['1.0.0'])
  })

  it('malware is always critical', () => {
    const idx = buildAdvisoryIndex([advisory({ id: 'GHSA-cccc-cccc-cccc', packageName: 'evil', severity: 'low', malware: true })])
    expect(matchRepo('me/app', [lock('package-lock.json', [['evil', '1.0.0', true]])], idx)[0]).toMatchObject({ severity: 'critical', malware: true })
  })

  it('a PyPI name matches across spellings', () => {
    const idx = buildAdvisoryIndex([advisory({ id: 'GHSA-dddd-dddd-dddd', packageName: 'flask-cors', ecosystem: 'PyPI', range: null, versions: ['3.0.0'], source: 'osv' })])
    const out = matchRepo('me/api', [lock('requirements.txt', [['flask-cors', '3.0.0', false]], 'PyPI')], idx)
    expect(out).toHaveLength(1)
  })
})

describe('fix versions from the global DB', () => {
  it('asks for a GHSA only when the npm range does not name the fix, and fills it in', () => {
    const idx = buildAdvisoryIndex([advisory({ id: 'GHSA-eeee-eeee-eeee', packageName: 'y', range: '<=2.3.4' })])
    const [f] = matchRepo('me/app', [lock('package-lock.json', [['y', '2.0.0', false]])], idx)
    expect(f.fixes[0].to).toBeNull()
    expect(fixLookupGhsa(f)).toBe('GHSA-eeee-eeee-eeee')
    const changed = applyGlobalFixes(f, [advisory({ id: 'GHSA-eeee-eeee-eeee', packageName: 'y', range: '<= 2.3.4', source: 'github', patched: ['2.3.5'] })])
    expect(changed).toBe(true)
    expect(f.fixes[0].to).toBe('2.3.5')
    expect(fixLookupGhsa(f)).toBeNull()
  })
})
