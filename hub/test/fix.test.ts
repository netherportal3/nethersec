import semver from 'semver'
import { describe, expect, it } from 'vitest'
import { ELLIPSIS } from '../src/scanner/advisories.js'
import { computeFixLine } from '../src/scanner/fix.js'

const npm = (installed: string, src: { vulnerableRanges?: string[]; patched?: string[] }) => computeFixLine('npm', installed, src)
const pypi = (installed: string, patched: string[], noFixListed = false) => computeFixLine('PyPI', installed, { patched, noFixListed })

describe('computeFixLine (npm)', () => {
  it('an exact list: 19.1.0 is fixed by 19.1.2, not 19.0.1 or 19.2.1', () => {
    expect(npm('19.1.0', { patched: ['19.0.1, 19.1.2, 19.2.1'] })).toEqual({ from: '19.1.0', to: '19.1.2', crossesLine: false })
  })

  it('crosses the line only when the line has no fix', () => {
    expect(npm('0.30.1', { patched: ['>=1.15.2'] })).toEqual({ from: '0.30.1', to: '1.15.2', crossesLine: true })
    expect(npm('0.30.1', { patched: ['>=1.15.2', '>=0.30.3'] })).toEqual({ from: '0.30.1', to: '0.30.3', crossesLine: false })
  })

  it('the exclusive upper bound of the matching range is the fix', () => {
    expect(npm('16.3.0', { vulnerableRanges: ['>=16.2.0 <16.3.6'] })).toEqual({ from: '16.3.0', to: '16.3.6', crossesLine: false })
    expect(npm('16.3.0', { vulnerableRanges: ['>=16.2.0 <16.3.6'], patched: ['16.3.3'] }).to).toBe('16.3.6')
    const ranges = ['<14.2.35 || >=15.0.0 <15.1.3']
    expect(npm('15.0.5', { vulnerableRanges: ranges }).to).toBe('15.1.3')
    expect(npm('14.1.0', { vulnerableRanges: ranges }).to).toBe('14.2.35')
  })

  it('a bound on another line lets a backport on this line win', () => {
    expect(npm('15.5.20', { vulnerableRanges: ['<16.3.3'], patched: ['16.3.3', '15.5.24'] })).toEqual({
      from: '15.5.20',
      to: '15.5.24',
      crossesLine: false,
    })
  })

  it('a desugared bound means the release, not the -0 prerelease', () => {
    expect(npm('1.5.0', { vulnerableRanges: ['^1.2.3'] })).toEqual({ from: '1.5.0', to: '2.0.0', crossesLine: true })
    expect(npm('1.9.0', { vulnerableRanges: ['<2'] })).toEqual({ from: '1.9.0', to: '2.0.0', crossesLine: true })
  })

  it('open-ended means unfixed; an inclusive <= bound only means "not listed"', () => {
    expect(npm('2.0.0', { vulnerableRanges: ['<=2.3.4'] })).toEqual({ from: '2.0.0', to: null, crossesLine: false })
    expect(npm('2.0.0', { vulnerableRanges: ['>=0.0.0'] }).unfixed).toBe(true)
    expect(npm('2.0.0', { vulnerableRanges: ['*'] }).unfixed).toBe(true)
    expect(npm('2.0.0', { vulnerableRanges: ['>=1.0.0 <=2.3.4 <2.1.0'] }).to).toBe('2.1.0')
  })

  it('prereleases: a stable install prefers a stable fix, and says when only a prerelease exists', () => {
    expect(npm('15.5.7', { patched: ['15.5.8, 15.6.0-canary.58'] }).to).toBe('15.5.8')
    expect(npm('15.5.7', { patched: ['15.6.0-canary.58'] })).toEqual({
      from: '15.5.7',
      to: '15.6.0-canary.58',
      crossesLine: false,
      prereleaseOnly: true,
    })
  })

  it('ignores capped values, shas and bound tokens', () => {
    expect(npm('19.1.0', { patched: [`19.2.${ELLIPSIS}`] }).to).toBeNull()
    expect(npm('19.1.0', { patched: ['19.0.1, 19.2...'] }).to).toBeNull()
    expect(npm('1.0.0', { patched: ['74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5'] }).to).toBeNull()
    expect(npm('15.0.0', { patched: ['>16.0.0', '<17.0.0', '<=18.0.0'] }).to).toBeNull()
  })

  it('never returns a version at or below the install, and never throws', () => {
    const installs = ['0.30.1', '1.14.0', '14.2.10', '15.5.26', '16.1.6', '19.1.0', '15.6.0-canary.40']
    const specs = [
      { patched: ['19.0.1, 19.1.2, 19.2.1'] },
      { patched: ['>=1.15.2', '>=0.30.3'] },
      { patched: ['15.5.26', '16.3.6', '14.2.35'] },
      { vulnerableRanges: ['<16.3.3'], patched: ['16.3.3', '15.5.24'] },
    ]
    for (const v of installs) {
      for (const s of specs) {
        const line = npm(v, s)
        if (line.to !== null) expect(semver.gt(line.to, v)).toBe(true)
      }
    }
    expect(npm('1.0.0', { vulnerableRanges: ['>=abc <<<'], patched: ['???'] }).to).toBeNull()
    expect(npm('1.0.0', { patched: [null, 42, {}] as unknown as string[] }).to).toBeNull()
    expect(computeFixLine('npm', '1.0.0', null as unknown as { patched?: string[] }).to).toBeNull()
  })
})

describe('computeFixLine (PyPI)', () => {
  it('takes the smallest fixed version above the install', () => {
    expect(pypi('2.30.0', ['2.31.0'])).toEqual({ from: '2.30.0', to: '2.31.0', crossesLine: false })
    expect(pypi('1.26.5', ['2.2.2', '1.26.19'])).toEqual({ from: '1.26.5', to: '1.26.19', crossesLine: false })
    expect(pypi('0.9.0', ['1.0.0'])).toEqual({ from: '0.9.0', to: '1.0.0', crossesLine: true })
  })
  it('no fix listed is unfixed; an older fix is never a downgrade', () => {
    expect(pypi('3.0.0', [], true)).toEqual({ from: '3.0.0', to: null, crossesLine: false, unfixed: true })
    expect(pypi('3.0.0', ['2.9.0']).to).toBeNull()
  })
})
