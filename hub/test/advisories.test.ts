import semver from 'semver'
import { describe, expect, it } from 'vitest'
import {
  advisoryMatchesVersion,
  buildAdvisoryIndex,
  canonSeverity,
  ghsaFrom,
  normalizeRange,
  parseGlobalAdvisory,
  parseNpmBulk,
  parseOsvVuln,
  type Advisory,
} from '../src/scanner/advisories.js'

const sat = (range: string, v: string) => {
  const r = normalizeRange(range)
  return r !== null && semver.satisfies(v, r, { includePrerelease: true })
}

describe('range handling', () => {
  it('reads GitHub comma-joined comparators as ONE range', () => {
    expect(sat('>= 13.0.0, < 15.5.8', '14.1.0')).toBe(true)
    expect(sat('>= 13.0.0, < 15.5.8', '15.5.8')).toBe(false)
    expect(sat('>= 13.0.0, < 15.5.8', '12.0.0')).toBe(false)
    expect(sat('>=1.0.0 <1.2.0 || >=2.0.0 <2.1.0', '2.0.5')).toBe(true)
    expect(sat('>=1.0.0 <1.2.0 || >=2.0.0 <2.1.0', '1.5.0')).toBe(false)
  })

  it('reads two bounded ranges joined by a comma as OR', () => {
    const r = '>=13.0.0 < 15.5.15, >= 16.0 < 16.2.3'
    expect(sat(r, '15.5.14')).toBe(true)
    expect(sat(r, '16.2.2')).toBe(true)
    expect(sat(r, '15.5.15')).toBe(false)
    expect(sat(r, '16.2.3')).toBe(false)
  })

  it('reads a list of exact versions as OR, with or without commas', () => {
    const list = '19.0.0, 19.1.0, 19.1.1, 19.2.0'
    expect(sat(list, '19.1.0')).toBe(true)
    expect(sat(list, '19.1.2')).toBe(false)
    expect(sat('19.1.4, 19.1.5 , 19.1.6', '19.1.5')).toBe(true)
    expect(sat('19.1.5 19.2.0', '19.2.0')).toBe(true)
  })

  it('fixes the "=>" typo and falls back to semver for caret, tilde and hyphen forms', () => {
    expect(sat('=>0.31.1', '0.31.2')).toBe(true)
    expect(sat('^1.2.0', '1.9.0')).toBe(true)
    expect(sat('1.0.0 - 1.4.0', '1.3.0')).toBe(true)
    expect(normalizeRange('not a range')).toBeNull()
  })
})

describe('parseNpmBulk', () => {
  it('reads entries, keys them by GHSA, and marks malware critical', () => {
    const body = {
      lodash: [
        {
          id: 1106913,
          url: 'https://github.com/advisories/GHSA-35JH-R3H4-6JHM',
          title: 'Command Injection in lodash',
          severity: 'high',
          vulnerable_versions: '<4.17.21',
        },
      ],
      'evil-pkg': [
        { id: 2, url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', title: 'Malware in evil-pkg', severity: 'low', vulnerable_versions: '>=0', cwe: ['CWE-506'] },
      ],
      weird: [{ id: 3, url: 'javascript:alert(1)', title: 'x', severity: 'medium', vulnerable_versions: '<1.0.0' }],
      empty: [{ id: 4, title: 'no range' }],
    }
    const out = parseNpmBulk(body)
    expect(out).toHaveLength(3)
    expect(out[0]).toMatchObject({ id: 'GHSA-35jh-r3h4-6jhm', packageName: 'lodash', severity: 'high', range: '<4.17.21', source: 'npm' })
    expect(out[0].url).toBe('https://github.com/advisories/GHSA-35jh-r3h4-6jhm')
    expect(out[1]).toMatchObject({ severity: 'critical', malware: true })
    // A non-https link is dropped, and an unknown id falls back to NPM-<n>.
    expect(out[2]).toMatchObject({ id: 'NPM-3', url: '', severity: 'moderate' })
    expect(parseNpmBulk({})).toEqual([])
    expect(parseNpmBulk(null)).toEqual([])
    expect(parseNpmBulk([1, 2])).toEqual([])
  })
})

describe('advisoryMatchesVersion', () => {
  const base: Advisory = {
    id: 'GHSA-xxxx-xxxx-xxxx',
    cveId: null,
    ecosystem: 'npm',
    packageName: 'next',
    severity: 'high',
    severityKnown: true,
    range: '>=16.2.0 <16.3.6',
    patched: [],
    title: 't',
    url: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx',
    source: 'npm',
  }
  it('matches inside the range, prereleases included, and never on a bad range', () => {
    expect(advisoryMatchesVersion(base, '16.3.0')).toBe(true)
    expect(advisoryMatchesVersion(base, '16.3.0-canary.3')).toBe(true)
    expect(advisoryMatchesVersion(base, '16.3.6')).toBe(false)
    expect(advisoryMatchesVersion({ ...base, range: 'nonsense' }, '16.3.0')).toBe(false)
    expect(advisoryMatchesVersion({ ...base, range: null }, '16.3.0')).toBe(false)
  })
  it('reads a GitHub-written range for the global DB source', () => {
    expect(advisoryMatchesVersion({ ...base, source: 'github', range: '>= 16.0.0, < 16.3.3' }, '16.1.0')).toBe(true)
  })
  it('OSV advisories match exactly the versions OSV named', () => {
    const osv = { ...base, ecosystem: 'PyPI' as const, range: null, versions: ['2.0.0'] }
    expect(advisoryMatchesVersion(osv, '2.0.0')).toBe(true)
    expect(advisoryMatchesVersion(osv, '2.0.1')).toBe(false)
  })
})

describe('parseOsvVuln', () => {
  it('prefers the GHSA alias, keeps the CVE, reads ECOSYSTEM fixed versions only', () => {
    const record = {
      id: 'PYSEC-2023-74',
      aliases: ['CVE-2023-32681', 'GHSA-J8R2-6X86-Q33Q'],
      summary: 'Requests leaks Proxy-Authorization headers',
      database_specific: { severity: 'MODERATE' },
      affected: [
        {
          package: { ecosystem: 'PyPI', name: 'requests' },
          ranges: [
            { type: 'GIT', events: [{ introduced: '0' }, { fixed: '74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5' }] },
            { type: 'ECOSYSTEM', events: [{ introduced: '2.3.0' }, { fixed: '2.31.0' }] },
          ],
        },
      ],
    }
    const adv = parseOsvVuln(record, 'Requests', ['2.30.0'])!
    expect(adv).toMatchObject({
      id: 'GHSA-j8r2-6x86-q33q',
      cveId: 'CVE-2023-32681',
      packageName: 'requests',
      severity: 'moderate',
      severityKnown: true,
      versions: ['2.30.0'],
      patched: ['2.31.0'],
      source: 'osv',
    })
    expect(adv.noFixListed).toBeUndefined()
  })

  it('a MAL-* report is critical malware; a record with no fix says so', () => {
    const mal = parseOsvVuln({ id: 'MAL-2024-1234', affected: [{ package: { ecosystem: 'PyPI', name: 'bad' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }] }] }, 'bad', ['1.0'])!
    expect(mal).toMatchObject({ id: 'MAL-2024-1234', severity: 'critical', malware: true, noFixListed: true })
    expect(mal.url).toBe('https://osv.dev/vulnerability/MAL-2024-1234')
    expect(parseOsvVuln({ id: 'PYSEC-1' }, 'x', ['1'])?.severityKnown).toBe(false)
    expect(parseOsvVuln(null, 'x', [])).toBeNull()
  })
})

describe('parseGlobalAdvisory', () => {
  it('trusts only reviewed records, and reads first_patched_version', () => {
    const body = {
      ghsa_id: 'GHSA-aaaa-bbbb-cccc',
      type: 'reviewed',
      severity: 'critical',
      summary: 's',
      vulnerabilities: [
        { package: { ecosystem: 'npm', name: 'x' }, vulnerable_version_range: '<= 2.3.4', first_patched_version: '2.3.5' },
        { package: { ecosystem: 'pip', name: 'y' }, vulnerable_version_range: '<1', first_patched_version: '1.0' },
      ],
    }
    const l = parseGlobalAdvisory(body, 'GHSA-aaaa-bbbb-cccc')
    expect(l.status).toBe('reviewed')
    if (l.status === 'reviewed') {
      expect(l.advisories).toHaveLength(1)
      expect(l.advisories[0]).toMatchObject({ packageName: 'x', patched: ['2.3.5'], source: 'github' })
    }
    expect(parseGlobalAdvisory({ ...body, type: 'unreviewed' }, 'GHSA-aaaa-bbbb-cccc')).toEqual({ status: 'missing' })
    expect(parseGlobalAdvisory(body, 'GHSA-zzzz-zzzz-zzzz')).toEqual({ status: 'failed' })
  })
})

describe('helpers', () => {
  it('canonSeverity maps medium to moderate and unknown to moderate', () => {
    expect(canonSeverity('CRITICAL')).toBe('critical')
    expect(canonSeverity('medium')).toBe('moderate')
    expect(canonSeverity(undefined)).toBe('moderate')
  })
  it('ghsaFrom finds and canonicalizes an id', () => {
    expect(ghsaFrom('see GHSA-AbCd-1234-efGH now')).toBe('GHSA-abcd-1234-efgh')
    expect(ghsaFrom('nothing')).toBeNull()
  })
  it('the index normalizes PyPI names', () => {
    const idx = buildAdvisoryIndex([
      { id: 'A', cveId: null, ecosystem: 'PyPI', packageName: 'Flask_Cors', severity: 'high', severityKnown: true, range: null, patched: [], title: '', url: '', source: 'osv' },
    ])
    expect(idx.get('PyPI:flask-cors')).toHaveLength(1)
  })
})
