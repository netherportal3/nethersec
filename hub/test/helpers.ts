import type { Advisory } from '../src/scanner/advisories.js'
import type { Finding } from '../src/scanner/match.js'
import type { RepoScan, ScanResult } from '../src/scanner/scan.js'
import { defaultSettings, type Settings } from '../src/state.js'

export function advisory(p: Partial<Advisory> & { id: string; packageName: string }): Advisory {
  return {
    cveId: null,
    ecosystem: 'npm',
    severity: 'high',
    severityKnown: true,
    range: '<99.0.0',
    patched: [],
    title: 'An advisory',
    url: `https://github.com/advisories/${p.id}`,
    source: 'npm',
    ...p,
  }
}

export function finding(p: Partial<Finding> & { repo: string; advisoryId: string }): Finding {
  const packageName = p.packageName ?? 'pkg'
  return {
    key: `${p.advisoryId}:${packageName}`,
    cveId: null,
    ecosystem: 'npm',
    packageName,
    severity: 'high',
    severityKnown: true,
    installed: ['1.0.0'],
    lockfiles: ['package-lock.json'],
    devOnly: false,
    sources: ['npm'],
    title: 'An advisory',
    url: `https://github.com/advisories/${p.advisoryId}`,
    fixes: [{ from: '1.0.0', to: '1.0.1', crossesLine: false }],
    ...p,
  }
}

export function okRepo(repo: string, findings: Finding[]): RepoScan {
  return { repo, status: 'ok', lockfiles: [{ path: 'package-lock.json', kind: 'npm', packages: 10, unpinned: 0 }], skipped: [], treeTruncated: false, findings }
}

export function scanOf(repos: RepoScan[], ecosystemsOk = { npm: true, PyPI: true }): ScanResult {
  return { repos, ecosystemsOk, errors: [] }
}

export function settings(over: Partial<Settings> = {}): Settings {
  return { ...defaultSettings(60), ...over }
}
