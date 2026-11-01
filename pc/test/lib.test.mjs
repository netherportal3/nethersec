// The pure decisions of the PC scanner (pc-security-lib.mjs). No Windows needed.
// Special characters are built with String.fromCharCode so this file stays ASCII.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as lib from '../pc-security-lib.mjs'

const DAY = lib.DAY
const NOW = Date.parse('2025-03-27T12:00:00Z')
const ELL = String.fromCharCode(0x2026)
const BAR = String.fromCharCode(0x2588).repeat(8) + String.fromCharCode(0x2592).repeat(4)
const CJK = String.fromCharCode(0x793a, 0x4f8b) // two characters that each take 2 terminal cells
const EM_DASH = String.fromCharCode(0x2014)
// winget counts the first as 2 terminal cells and the scanner 1; the second the other way round.
const ROCKET = String.fromCodePoint(0x1f680)
const THERMOMETER = String.fromCodePoint(0x1f321)

/** assert that `actual` has every field of `subset` (like a partial match). */
function partial(actual, subset) {
  assert.ok(actual && typeof actual === 'object', `expected an object, got ${actual}`)
  for (const [k, v] of Object.entries(subset)) assert.deepEqual(actual[k], v, `field ${k}`)
}

// winget pads columns to these widths when its output goes to a pipe.
const W = { name: 61, id: 45, version: 25, available: 15 }
function row(name, id, version, available, source = 'winget', nameCells = name.length) {
  return name + ' '.repeat(Math.max(1, W.name - nameCells)) + id.padEnd(W.id) + version.padEnd(W.version) + available.padEnd(W.available) + source
}
const HEADER = 'Name'.padEnd(W.name) + 'Id'.padEnd(W.id) + 'Version'.padEnd(W.version) + 'Available'.padEnd(W.available) + 'Source'
const DASHES = '-'.repeat(HEADER.length)
const LONG_ID = `SomeVendor.SomeVeryLongProductIdThatGetsCu${ELL}`

const UPGRADE_OUTPUT = [
  // spinner frames and a progress bar winget draws before the table
  '\r   - \r   \\ \r   | \r   / \r          \r',
  `  ${BAR}  1.24 MB / 2.48 MB`,
  '\r   - \r' + HEADER,
  DASHES,
  row('Git', 'Git.Git', '2.40.0', '2.41.0.2'),
  row('Archiver 12.40 (x64)', 'Contoso.Archiver', '12.40', '13.15'),
  row('Example Framework 3.1 SDK', 'Contoso.Framework.DevPack.3.2', '< 3.2.1', '3.2.1'),
  row(`Example C++ Redistributable (x64) - 12.3${ELL}`, 'Contoso.Redist.2015+.x64', '12.30.4100.0', '12.34.5200.0'),
  row('Some Very Long Vendor Tool', LONG_ID, '1.0', '1.1'),
  row('Example Game Player', 'Contoso.GamePlayer', 'Unknown', '0.512'),
  row('Example Build Tools 2020', 'Contoso.BuildTools.2020', '15.2.3 (January 2020)', '15.2.9'),
  row('Example Meetings', 'Contoso.Meetings.EXE', '3.1.0 (1001)', '3.2.0 (1007)'),
  row(`${CJK} Chat`, 'Contoso.CjkChat', '2.4.10', '2.4.12', 'winget', 4 + ' Chat'.length),
  row('Node.js', 'OpenJS.NodeJS.LTS', '24.6.1', '26.3.0'),
  '10 upgrades available.',
  '',
  '1 package(s) have version numbers that cannot be determined. Use --include-unknown to see all results.',
  'The following packages have an upgrade available, but require explicit targeting for upgrade:',
  'Name'.padEnd(10) + 'Id'.padEnd(17) + 'Version'.padEnd(8) + 'Available'.padEnd(10) + 'Source',
  '-'.repeat(50),
  'Chat App'.padEnd(10) + 'Contoso.Chat'.padEnd(17) + '2.1.3'.padEnd(8) + '2.1.3407'.padEnd(10) + 'winget',
  '',
].join('\r\n')

describe('winget table parsing', () => {
  const parsed = lib.parseWingetTable(UPGRADE_OUTPUT)

  it('reads every row through spinner junk, the footer and the explicit-targeting table', () => {
    assert.equal(parsed.ok, true)
    assert.equal(parsed.footerCount, 10)
    assert.deepEqual(parsed.notes, [])
    assert.deepEqual(parsed.unread, [])
    assert.deepEqual(
      parsed.rows.map((r) => r.id),
      [
        'Git.Git',
        'Contoso.Archiver',
        'Contoso.Framework.DevPack.3.2',
        'Contoso.Redist.2015+.x64',
        LONG_ID,
        'Contoso.GamePlayer',
        'Contoso.BuildTools.2020',
        'Contoso.Meetings.EXE',
        'Contoso.CjkChat',
        'OpenJS.NodeJS.LTS',
        'Contoso.Chat',
      ],
    )
    partial(
      parsed.rows.find((r) => r.id === 'Contoso.Chat'),
      { explicit: true, version: '2.1.3', available: '2.1.3407', source: 'winget' },
    )
    assert.equal(parsed.rows.filter((r) => r.explicit).length, 1)
  })

  it('keeps versions with spaces and markers, and flags names and ids cut short', () => {
    const by = (id) => parsed.rows.find((r) => r.id === id)
    assert.equal(by('Contoso.BuildTools.2020').version, '15.2.3 (January 2020)')
    assert.equal(by('Contoso.Meetings.EXE').available, '3.2.0 (1007)')
    assert.equal(by('Contoso.Framework.DevPack.3.2').version, '< 3.2.1')
    assert.equal(by('Contoso.GamePlayer').version, 'Unknown')
    assert.equal(by('Contoso.Redist.2015+.x64').nameTruncated, true)
    assert.equal(by(LONG_ID).idTruncated, true)
  })

  it('aligns columns after wide characters', () => {
    partial(
      parsed.rows.find((r) => r.id === 'Contoso.CjkChat'),
      { name: `${CJK} Chat`, version: '2.4.10', available: '2.4.12' },
    )
  })

  it('reads "nothing to upgrade" as a good, empty read', () => {
    const r = lib.parseWingetTable('   - \r\nNo installed package found matching input criteria.\r\n')
    assert.equal(r.ok, true)
    assert.deepEqual(r.rows, [])
  })

  it('treats junk, a crash or a failed winget source as unreadable', () => {
    assert.equal(lib.parseWingetTable('').ok, false)
    assert.equal(lib.parseWingetTable('An unexpected error occurred while executing the command:\r\n0x8a15000f').ok, false)
    const noWinget = lib.parseWingetTable(`Failed when searching source: winget\r\n${HEADER}\r\n${DASHES}\r\n${row('Git', 'Git.Git', '2.40.0', '2.41.0.2')}\r\n`)
    assert.equal(noWinget.ok, false)
    const noStore = lib.parseWingetTable(`Failed when searching source: msstore\r\n${HEADER}\r\n${DASHES}\r\n${row('Git', 'Git.Git', '2.40.0', '2.41.0.2')}\r\n`)
    assert.equal(noStore.ok, true)
    assert.deepEqual(noStore.failedSources, ['msstore'])
  })

  it('keeps local ARP ids that contain spaces (winget list)', () => {
    const r = lib.parseWingetTable([HEADER, DASHES, row('Example Game', 'ARP\\Machine\\X64\\Example App 123456', 'Unknown', '', '')].join('\n'))
    partial(r.rows[0], { id: 'ARP\\Machine\\X64\\Example App 123456', version: 'Unknown', available: '' })
  })

  it('follows a row whose name winget measures a cell wider or narrower than the scanner does', () => {
    const narrow = row(`Example ${ROCKET} Tool`, 'Contoso.RocketTool', '1.2.0', '1.3.0', 'winget', 'Example '.length + 2 + ' Tool'.length)
    const wide = row(`Example ${THERMOMETER} Meter`, 'Contoso.Meter', '2.0', '2.1', 'winget', 'Example '.length + 1 + ' Meter'.length)
    const r = lib.parseWingetTable([HEADER, DASHES, narrow, wide].join('\n'))
    assert.deepEqual(r.unread, [])
    partial(r.rows[0], { name: `Example ${ROCKET} Tool`, id: 'Contoso.RocketTool', version: '1.2.0', available: '1.3.0', source: 'winget' })
    partial(r.rows[1], { name: `Example ${THERMOMETER} Meter`, id: 'Contoso.Meter', version: '2.0', available: '2.1', source: 'winget' })
  })

  it('lists the rows it cannot read, and a read with one is not good', () => {
    const noId = row('Example Tool', 'Not A Winget Id', '1.0', '')
    const shiftedTooFar = row(`Example ${ROCKET.repeat(3)} Tool`, 'Contoso.Tool', '1.0', '', 'winget', 'Example '.length + 6 + ' Tool'.length)
    const list = lib.parseWingetTable([HEADER, DASHES, row('Git', 'Git.Git', '2.40.0', ''), noId, shiftedTooFar].join('\n'))
    assert.equal(list.ok, true)
    assert.deepEqual(list.rows.map((r) => r.id), ['Git.Git'])
    assert.equal(list.unread.length, 2)
    assert.deepEqual(lib.wingetReadable(list, null), { ok: false, reason: 'could not read a row: Example Tool Not A Winget Id 1.0 winget (and 1 more)' })
    // The footer of winget upgrade counts only its first table, so it cannot catch a row lost from the second.
    const upgrade = lib.parseWingetTable(
      [
        HEADER,
        DASHES,
        row('Git', 'Git.Git', '2.40.0', '2.41.0.2'),
        '1 upgrades available.',
        '',
        'The following packages have an upgrade available, but require explicit targeting for upgrade:',
        HEADER,
        DASHES,
        row('Chat App', 'Contoso Chat', '2.1.3', '2.1.4'),
        '',
      ].join('\n'),
    )
    assert.equal(upgrade.footerCount, 1)
    assert.match(lib.wingetReadable(upgrade, null, { expectFooter: true }).reason, /^could not read a row: Chat App Contoso Chat/)
  })

  it('applies carriage returns and backspaces the way a console would', () => {
    assert.deepEqual(lib.cleanConsoleLines('abc\b\bX\r\n  -\rHeader  \n'), ['aX', 'Header', ''])
  })
})

describe('winget read checks', () => {
  const table = (n, footer) =>
    [HEADER, DASHES, ...Array.from({ length: n }, (_, i) => row(`App ${i}`, `Vendor.App${i}`, '1.0', '1.1')), ...(footer === null ? [] : [`${footer} upgrades available.`])].join('\n')

  it('accepts a complete read', () => {
    assert.deepEqual(lib.wingetReadable(lib.parseWingetTable(table(3, 3)), null, { expectFooter: true }), { ok: true, reason: '' })
  })

  it('rejects a timeout even with output, a footer that disagrees, and upgrade rows with no footer', () => {
    assert.equal(lib.wingetReadable(lib.parseWingetTable(table(3, 3)), 'timed out', { expectFooter: true }).ok, false)
    assert.equal(lib.wingetReadable(lib.parseWingetTable(table(2, 3)), null, { expectFooter: true }).reason, 'winget said 3 upgrades but listed 2')
    assert.equal(lib.wingetReadable(lib.parseWingetTable(table(2, null)), null, { expectFooter: true }).reason, 'winget output ended before its summary line')
  })

  it('counts a non-zero exit only with a complete answer', () => {
    assert.equal(lib.wingetReadable(lib.parseWingetTable(table(3, 3)), 'exit code 1', { expectFooter: true }).ok, true)
    assert.equal(lib.wingetReadable(lib.parseWingetTable('No installed package found matching input criteria.'), 'exit code 1', { expectFooter: true }).ok, true)
    assert.equal(lib.wingetReadable(lib.parseWingetTable(table(3, null)), 'exit code 1').ok, false)
    assert.equal(lib.wingetReadable(lib.parseWingetTable(table(3, null)), null).ok, true)
  })
})

describe('WSL distro choice', () => {
  const distros = [
    { name: 'Ubuntu-24.04', state: 'Stopped' },
    { name: 'Debian', state: 'Running' },
    { name: 'docker-desktop', state: 'Running' },
  ]
  const base = { distros, skip: [/^docker-desktop/i], now: NOW, intervalMs: 20 * 3_600_000 }

  it('checks only running distros unless startStopped is set, and never docker-desktop', () => {
    assert.deepEqual(lib.planWslChecks(base), [
      { name: 'Ubuntu-24.04', action: 'not-running' },
      { name: 'Debian', action: 'check' },
    ])
    assert.deepEqual(lib.planWslChecks({ ...base, startStopped: true }), [
      { name: 'Ubuntu-24.04', action: 'check' },
      { name: 'Debian', action: 'check' },
    ])
  })

  it('checks a distro at most once per interval', () => {
    assert.deepEqual(lib.planWslChecks({ ...base, lastCheck: { Debian: NOW - 3_600_000 } })[1], { name: 'Debian', action: 'not-due' })
    assert.deepEqual(lib.planWslChecks({ ...base, lastCheck: { Debian: NOW - 21 * 3_600_000 } })[1], { name: 'Debian', action: 'check' })
  })

  it('a stopped distro that is not checked keeps its last result', () => {
    const hit = { name: 'Ubuntu-24.04', ok: true, count: 2, packages: ['openssl'], updateOk: true }
    const day1 = lib.evaluateWsl({ results: [hit], now: NOW, ignoreGrace: true })
    const notRunning = lib.evaluateWsl({ results: [{ name: 'Ubuntu-24.04', skipped: true }], wslState: day1.wslState, now: NOW + DAY, ignoreGrace: true })
    assert.equal(notRunning.readable, true)
    assert.equal(notRunning.active.length, 1)
  })
})

describe('version comparison', () => {
  const cases = [
    ['2.40.0', '2.41.0.2', -1],
    ['2.41.0.2', '2.41.0', 1],
    ['1.30.2', '1.30.4', -1],
    ['go1.21.9', 'go1.21.10', -1],
    ['v24.6.1', '24.6.1', 0],
    ['< 3.2.1', '3.2.1', -1],
    ['> 5.10.20.30', '5.10.20.30', 1],
    ['3.1.0 (1001)', '3.1.0 (1007)', -1],
    ['15.2.3 (January 2020)', '15.2.9', -1],
    ['1.0.0-beta.2', '1.0.0', -1],
    ['go1.22rc1', 'go1.22.0', -1],
    ['2023.4.1', '2024.11.5', -1],
  ]
  for (const [a, b, want] of cases) {
    it(`${a} vs ${b}`, () => {
      assert.equal(lib.compareVersions(a, b), want)
    })
  }

  it('cannot compare an unknown version', () => {
    assert.equal(lib.compareVersions('Unknown', '0.512'), null)
    assert.equal(lib.parseVersion('Unknown').unknown, true)
  })

  it('tells a newer major (or Go-style minor line) apart', () => {
    assert.equal(lib.isNewerLine('24.6.1', '26.3.0'), true)
    assert.equal(lib.isNewerLine('2.40.0', '2.41.0.2'), false)
    assert.equal(lib.isNewerLine('12.40', '13.15'), true)
    assert.equal(lib.isNewerLine('1.21.5', '1.22.0'), false)
    assert.equal(lib.isNewerLine('1.21.5', '1.22.0', 2), true)
    assert.equal(lib.isNewerLine('1.21.5', '1.21.10', 2), false)
  })
})

describe('apps-behind', () => {
  const watch = lib.normalizeWatch({
    apps: [
      { id: 'Git.Git', name: 'Git' },
      { id: 'Contoso.Archiver', name: 'Archiver', followsMajor: true },
      { id: 'OpenJS.NodeJS.LTS', name: 'Node.js', check: 'runtimes' },
      { id: 'Contoso.Meetings.EXE', name: 'Meetings' },
      { id: 'Contoso.GamePlayer', name: 'Game Player' },
      { id: 'SomeVendor.SomeVeryLongProductIdThatGetsCutShort', name: 'Vendor Tool' },
      { idPattern: '^Contoso\\.(Runtime|WebCore)\\.8$', name: 'Runtime 8' },
      { id: 'Docker.DockerDesktop', name: 'Docker Desktop' },
    ],
  })
  const rows = lib.parseWingetTable(UPGRADE_OUTPUT).rows
  const evalAt = (now, appState, extra = {}) => lib.evaluateAppsBehind({ rows, entries: watch.apps, appState, now, ...extra })
  const r0 = (o) => ({ source: 'winget', explicit: false, nameTruncated: false, idTruncated: false, ...o })

  it('holds a newly behind app inside the 7-day grace, then alerts', () => {
    const first = evalAt(NOW)
    assert.deepEqual(first.active, [])
    assert.deepEqual(first.pending.map((i) => i.id).sort(), ['Contoso.Archiver', 'Contoso.Meetings.EXE', 'Git.Git', LONG_ID])
    const later = evalAt(NOW + 7 * DAY + 1, first.appState)
    assert.deepEqual(later.active.map((i) => i.name), ['Archiver', 'Git', 'Meetings', 'Vendor Tool'])
    partial(
      later.active.find((i) => i.id === 'Git.Git'),
      { installed: '2.40.0', available: '2.41.0.2', update: 'winget upgrade --id Git.Git' },
    )
  })

  it('reports everything behind at once with ignoreGrace', () => {
    assert.equal(evalAt(NOW, undefined, { ignoreGrace: true }).active.length, 4)
  })

  it('does not count a newer major unless the entry follows majors, and leaves runtimes to their own check', () => {
    const r = lib.evaluateAppsBehind({
      rows: [
        r0({ name: 'Archiver', id: 'Contoso.Archiver', version: '12.40', available: '13.15' }),
        r0({ name: 'Docker Desktop', id: 'Docker.DockerDesktop', version: '4.10.0', available: '5.0.0' }),
        r0({ name: 'Node.js', id: 'OpenJS.NodeJS.LTS', version: '24.6.1', available: '24.6.5' }),
      ],
      entries: watch.apps,
      now: NOW,
      ignoreGrace: true,
    })
    assert.deepEqual(r.active.map((i) => i.id), ['Contoso.Archiver'])
    assert.deepEqual(r.majorSkipped.map((i) => i.id), ['Docker.DockerDesktop'])
  })

  it('lists an unknown installed version instead of guessing', () => {
    assert.deepEqual(evalAt(NOW).unknown, [{ id: 'Contoso.GamePlayer', name: 'Game Player' }])
  })

  it('does not restart the clock when an even newer version appears', () => {
    const first = evalAt(NOW)
    const newer = rows.map((r) => (r.id === 'Git.Git' ? { ...r, available: '2.42.0' } : r))
    const r = lib.evaluateAppsBehind({ rows: newer, entries: watch.apps, appState: first.appState, now: NOW + 8 * DAY })
    const git = r.active.find((i) => i.id === 'Git.Git')
    assert.equal(git.firstBehind, NOW)
    assert.equal(git.available, '2.42.0')
  })

  const withoutGit = rows.filter((r) => r.id !== 'Git.Git')

  it('keeps an app that drops out of one read, and clears it only on the second miss in a row', () => {
    const first = evalAt(NOW, undefined, { ignoreGrace: true })
    const once = lib.evaluateAppsBehind({ rows: withoutGit, entries: watch.apps, appState: first.appState, now: NOW + DAY, ignoreGrace: true })
    assert.equal(once.active.some((i) => i.id === 'Git.Git'), true)
    partial(once.appState['Git.Git'], { missing: 1, firstBehind: NOW })
    const back = lib.evaluateAppsBehind({ rows, entries: watch.apps, appState: once.appState, now: NOW + 2 * DAY, ignoreGrace: true })
    partial(back.appState['Git.Git'], { missing: 0, firstBehind: NOW })
    const twice = lib.evaluateAppsBehind({ rows: withoutGit, entries: watch.apps, appState: once.appState, now: NOW + 2 * DAY, ignoreGrace: true })
    assert.equal(twice.active.some((i) => i.id === 'Git.Git'), false)
    assert.equal(twice.appState['Git.Git'].goneSince, NOW + 2 * DAY)
  })

  it('clears an app at once when winget list shows its installed version changed', () => {
    const first = evalAt(NOW)
    const updated = lib.evaluateAppsBehind({
      rows: withoutGit,
      installedRows: [{ id: 'Git.Git', version: '2.41.0.2' }],
      entries: watch.apps,
      appState: first.appState,
      now: NOW + DAY,
    })
    assert.equal(updated.appState['Git.Git'].goneSince, NOW + DAY)
    const same = lib.evaluateAppsBehind({
      rows: withoutGit,
      installedRows: [{ id: 'Git.Git', version: '2.40.0' }],
      entries: watch.apps,
      appState: first.appState,
      now: NOW + DAY,
    })
    assert.equal(same.appState['Git.Git'].goneSince, undefined)
    assert.equal(same.pending.some((i) => i.id === 'Git.Git'), true)
  })

  it('resumes the old clock when a cleared app is back at the same version within a day, else starts fresh', () => {
    const first = evalAt(NOW)
    const once = lib.evaluateAppsBehind({ rows: withoutGit, entries: watch.apps, appState: first.appState, now: NOW + DAY })
    const gone = lib.evaluateAppsBehind({ rows: withoutGit, entries: watch.apps, appState: once.appState, now: NOW + DAY + 1000 })
    assert.equal(evalAt(NOW + DAY + 3_600_000, gone.appState).appState['Git.Git'].firstBehind, NOW)
    const newVersion = rows.map((r) => (r.id === 'Git.Git' ? { ...r, version: '2.40.1' } : r))
    const fresh = lib.evaluateAppsBehind({ rows: newVersion, entries: watch.apps, appState: gone.appState, now: NOW + DAY + 2000 })
    assert.equal(fresh.appState['Git.Git'].firstBehind, NOW + DAY + 2000)
    const later = lib.evaluateAppsBehind({ rows: [], entries: watch.apps, appState: gone.appState, now: NOW + 3 * DAY })
    assert.equal(later.appState['Git.Git'], undefined)
  })

  it('leaves the state of an entry skipped for a bad pattern untouched', () => {
    const first = evalAt(NOW, undefined, { ignoreGrace: true })
    const broken = lib.normalizeWatch({ apps: [{ id: 'Git.Git', name: 'Git', kev: [{ vendorProject: '([' }] }] })
    assert.deepEqual(broken.apps, [])
    assert.equal(broken.skipped.length, 1)
    partial(broken.skipped[0], { list: 'apps', key: 'Git.Git' })
    assert.match(broken.errors[0], /entry skipped, its last result kept/)
    const r = lib.evaluateAppsBehind({
      rows: [],
      entries: broken.apps,
      frozenKeys: broken.skipped.map((s) => s.key),
      appState: first.appState,
      now: NOW + DAY,
      ignoreGrace: true,
    })
    assert.deepEqual(r.appState['Git.Git'], first.appState['Git.Git'])
    assert.deepEqual(r.active.map((i) => i.id), ['Git.Git'])
  })

  it('carries a package whose source winget could not search', () => {
    const storeRow = { ...rows.find((r) => r.id === 'Contoso.Meetings.EXE'), source: 'msstore' }
    const first = lib.evaluateAppsBehind({ rows: [storeRow], entries: watch.apps, now: NOW })
    const blind = lib.evaluateAppsBehind({ rows: [], failedSources: ['msstore'], entries: watch.apps, appState: first.appState, now: NOW + 8 * DAY })
    assert.deepEqual(blind.active.map((i) => i.id), ['Contoso.Meetings.EXE'])
    assert.equal(blind.appState['Contoso.Meetings.EXE'].firstBehind, NOW)
  })

  it('matches an id cut short with an ellipsis by prefix', () => {
    assert.equal(lib.entryMatchesRow(watch.apps[5], { id: LONG_ID, name: 'x' }), true)
    assert.equal(lib.entryMatchesRow(watch.apps[0], { id: `Gi${ELL}`, name: 'x' }), false)
  })

  it('names pattern matches by their own row, without version numbers', () => {
    const r = lib.evaluateAppsBehind({
      rows: [
        r0({ name: 'Contoso Runtime - 8.0.4 (x64)', id: 'Contoso.Runtime.8', version: '8.0.4', available: '8.0.12' }),
        r0({ name: 'Contoso Web Core 8.0.3 - Shared Framework (x86)', id: 'Contoso.WebCore.8', version: '8.0.3', available: '8.0.12' }),
      ],
      entries: watch.apps,
      now: NOW,
      ignoreGrace: true,
    })
    assert.deepEqual(r.active.map((i) => i.name), ['Contoso Runtime (x64)', 'Contoso Web Core - Shared Framework (x86)'])
  })
})

describe('apps-eol', () => {
  it('finds end-of-life packages by id, id pattern or name pattern', () => {
    const watch = lib.normalizeWatch({
      eol: [
        { idPattern: '^Vendor\\.Runtime\\.(5|6)$', name: 'Old runtime' },
        { id: 'Vendor.OldClient', name: 'Old client' },
        { namePattern: '^Legacy Installer' },
      ],
    })
    const rows = [
      { name: 'Vendor Runtime 6', id: 'Vendor.Runtime.6', version: '6.0.9' },
      { name: 'Vendor Runtime 8', id: 'Vendor.Runtime.8', version: '8.0.4' },
      { name: 'Old Client', id: 'vendor.oldclient', version: '11.0' },
      { name: 'Legacy Installer 4.0', id: 'ARP\\Machine\\X64\\{ABC}', version: '4.0.1234' },
    ]
    assert.deepEqual(
      lib.evaluateEol({ rows, entries: watch.eol }).map((i) => `${i.name} ${i.version}`),
      ['Legacy Installer 4.0.1234', 'Old client 11.0', 'Vendor Runtime 6 6.0.9'],
    )
  })

  it('carries the items of an entry skipped for a bad pattern, and only those', () => {
    const prior = [{ key: 'Vendor.Runtime.6', id: 'Vendor.Runtime.6', name: 'Old runtime', version: '6.0.9', note: '', entryKey: 'Old runtime' }]
    assert.deepEqual(lib.evaluateEol({ rows: [], entries: [], prior, frozenKeys: ['Old runtime'] }), prior)
    assert.deepEqual(lib.evaluateEol({ rows: [], entries: [], prior, frozenKeys: [] }), [])
  })
})

describe('watch.json problems', () => {
  it('a file that is not valid JSON, or has a non-list apps, is unreadable (never an empty list that clears)', () => {
    const broken = lib.parseWatchJson('{ "apps": [ { "id": "Git.Git" }, ] ')
    assert.match(broken.unreadable, /^not valid JSON/)
    assert.deepEqual(broken.apps, [])
    assert.equal(lib.parseWatchJson('{ "apps": { "id": "Git.Git" } }').unreadable, '"apps" and "eol" must be lists')
    assert.equal(lib.parseWatchJson('[]').unreadable, 'not a JSON object')
    const ok = lib.parseWatchJson('{ "apps": [{ "id": "Git.Git", "name": "Git" }] }')
    assert.equal(ok.unreadable, null)
    assert.deepEqual(ok.apps.map((a) => a.key), ['Git.Git'])
  })
})

describe('runtimes', () => {
  const index = [
    { version: 'v26.3.0', date: '2025-03-26', lts: 'Lithium', security: false },
    { version: 'v26.2.1', date: '2025-03-19', lts: false, security: true },
    { version: 'v24.6.2', date: '2025-03-25', lts: 'Krypton', security: false },
    { version: 'v24.6.1', date: '2025-03-18', lts: 'Krypton', security: true },
    { version: 'v24.6.0', date: '2025-03-12', lts: 'Krypton', security: false },
    { version: 'v22.15.0', date: '2025-02-27', lts: 'Jod', security: true },
  ]
  const cycles = [
    { cycle: '26', lts: '2025-03-26', eol: '2027-09-27', latest: '26.3.0' },
    { cycle: '24', lts: '2024-03-26', eol: '2026-09-27', latest: '24.6.2' },
    { cycle: '20', lts: '2022-03-22', eol: '2024-09-26', latest: '20.9.0' },
  ]

  it('Node: a newer non-security patch or a newer major is not behind', () => {
    assert.deepEqual(lib.evaluateNode({ installed: ['24.6.1'], index, eolCycles: cycles, now: NOW }), [])
  })

  it('Node: a security release in the same major is behind, timed from its release date', () => {
    assert.deepEqual(lib.evaluateNode({ installed: ['24.6.0'], index, eolCycles: cycles, now: NOW }), [
      { key: 'node:24:security', runtime: 'node', reason: 'security', installed: '24.6.0', target: '24.6.2', since: Date.parse('2025-03-18') },
    ])
  })

  it('Node: a major past end of life is flagged at once', () => {
    const items = lib.evaluateNode({ installed: ['20.9.0'], index, eolCycles: cycles, now: NOW })
    assert.equal(items.length, 1)
    partial(items[0], { key: 'node:20:eol', reason: 'eol', eolDate: '2024-09-26', target: '26.3.0', noGrace: true })
  })

  it('Go: a newer patch of the same minor, or an unsupported minor', () => {
    const releases = ['go1.22.3', 'go1.22.0', 'go1.21.10', 'go1.21.5', 'go1.20.9', 'go1.23rc1'].map((v) => ({ version: v, stable: !v.includes('rc') }))
    assert.deepEqual(lib.evaluateGo({ installed: '1.21.5', releases }), [
      { key: 'go:1.21:patch', runtime: 'go', reason: 'patch', installed: '1.21.5', line: '1.21', target: '1.21.10' },
    ])
    assert.deepEqual(lib.evaluateGo({ installed: '1.21.10', releases }), [])
    assert.deepEqual(lib.evaluateGo({ installed: '1.20.9', releases }), [
      { key: 'go:1.20:unsupported', runtime: 'go', reason: 'unsupported', installed: '1.20.9', line: '1.20', target: '1.22.3' },
    ])
  })

  it('Java: a newer Zulu build of the same major, ignoring CRaC and JavaFX bundles', () => {
    const pkgs = [
      { name: 'zulu21.36.17-ca-jdk21.0.6.0.2-win_x64.zip', java_version: [21, 0, 6, 0, 2] },
      { name: 'zulu21.38.1-ca-crac-jdk21.0.7-win_x64.zip', java_version: [21, 0, 7] },
    ]
    assert.deepEqual(lib.evaluateJava({ installs: [{ version: '21.0.2' }], packagesByMajor: { 21: pkgs } }), [
      { key: 'java:21:behind', runtime: 'java', reason: 'behind', installed: '21.0.2', target: '21.0.6' },
    ])
    assert.deepEqual(lib.evaluateJava({ installs: [{ version: '21.0.6' }], packagesByMajor: { 21: pkgs } }), [])
  })

  it('keeps the last result of a runtime whose feed could not be read', () => {
    const goItem = { key: 'go:1.21:patch' }
    const m = lib.mergeSubResults({ node: { readable: true, items: [] }, go: { readable: false } }, { go: [goItem] })
    assert.deepEqual(m.items, [goItem])
    assert.deepEqual(m.unreadable, ['go'])
    assert.equal(m.allUnreadable, false)
    assert.equal(lib.mergeSubResults({ go: { readable: false } }).allUnreadable, true)
  })

  it('grace clocks start at first sight (or an earlier release date) and drop when fixed', () => {
    const a = lib.applyClock({ items: [{ key: 'go:1.21:patch' }], now: NOW, graceMs: 7 * DAY })
    assert.deepEqual(a.active, [])
    const b = lib.applyClock({ items: [{ key: 'go:1.21:patch' }], clocks: a.clocks, now: NOW + 8 * DAY, graceMs: 7 * DAY })
    assert.equal(b.active.length, 1)
    const c = lib.applyClock({ items: [{ key: 'node:24:security', since: NOW - 10 * DAY }], now: NOW, graceMs: 7 * DAY })
    assert.equal(c.active.length, 1)
    assert.deepEqual(lib.applyClock({ items: [], clocks: b.clocks, now: NOW, graceMs: 7 * DAY }).clocks, {})
  })
})

describe('Windows checks', () => {
  const cu = {
    title: '2025-03 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5000001)',
    kb: ['5000001'],
    severity: 'Critical',
    categories: ['Security Updates', 'Windows 11'],
    released: '2025-03-11T17:00:00Z',
  }
  const defs = { title: 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602', kb: ['2267602'], severity: '', categories: ['Definition Updates'], released: '2025-03-27T04:00:00Z' }

  it('alerts on a security update more than 7 days past release, ignoring definition updates', () => {
    const r = lib.evaluateWindowsUpdates({ updates: [cu, defs], now: NOW })
    assert.equal(r.active.length, 1)
    partial(r.active[0], { key: 'KB5000001', kb: 'KB5000001', severity: 'Critical', title: '2025-03 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems' })
    assert.equal(r.securityPending, true)
    const fresh = lib.evaluateWindowsUpdates({ updates: [{ ...cu, released: '2025-03-25T17:00:00Z' }], now: NOW })
    assert.deepEqual(fresh.active, [])
    assert.equal(fresh.pending.length, 1)
    assert.equal(lib.evaluateWindowsUpdates({ updates: [defs], now: NOW }).securityPending, false)
  })

  it('a re-released update keeps its first-seen clock', () => {
    const r = lib.evaluateWindowsUpdates({ updates: [{ ...cu, released: '2025-03-26T00:00:00Z' }], firstSeen: { KB5000001: NOW - 9 * DAY }, now: NOW })
    assert.equal(r.active.length, 1)
  })

  it('Defender: real-time off, old definitions, and passive mode', () => {
    const ok = { amServiceEnabled: true, antivirusEnabled: true, realTimeProtectionEnabled: true, runningMode: 'Normal', signatureLastUpdated: new Date(NOW - DAY).toISOString() }
    assert.deepEqual(lib.evaluateDefender(ok, NOW).items, [])
    const bad = { ...ok, realTimeProtectionEnabled: false, signatureLastUpdated: new Date(NOW - 5 * DAY).toISOString() }
    assert.deepEqual(lib.evaluateDefender(bad, NOW).items.map((i) => i.key), ['realtime-off', 'signatures-old'])
    const passive = { ...bad, runningMode: 'Passive Mode', antivirusEnabled: false }
    assert.deepEqual(lib.evaluateDefender(passive, NOW).items, [])
  })

  it('Firewall: any profile off', () => {
    assert.deepEqual(lib.evaluateFirewall([{ name: 'Domain', enabled: 'True' }, { name: 'Public', enabled: 'False' }]), [{ key: 'public', name: 'Public' }])
    assert.deepEqual(lib.evaluateFirewall([{ name: 'Private', enabled: 'True' }]), [])
  })
})

describe('WSL', () => {
  it('parses wsl -l -v, with or without UTF-16 NUL bytes', () => {
    const text = '  NAME              STATE           VERSION\r\n* Ubuntu-24.04      Stopped         2\r\n  docker-desktop    Running         2\r\n'
    const want = [
      { name: 'Ubuntu-24.04', state: 'Stopped', version: '2', isDefault: true },
      { name: 'docker-desktop', state: 'Running', version: '2', isDefault: false },
    ]
    assert.deepEqual(lib.parseWslList(text), want)
    assert.deepEqual(lib.parseWslList(text.split('').join(String.fromCharCode(0))), want)
  })

  it('counts upgrades from a -security pocket', () => {
    const out = [
      'NETHERSEC_UPDATE_RC=0',
      'Reading package lists...',
      'Inst libexample1 [1.4.0-1build1] (1.4.0-1ubuntu0.1 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])',
      'Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04.1 Ubuntu:24.04/noble-updates [all])',
      'Conf libexample1 (1.4.0-1ubuntu0.1 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])',
      'NETHERSEC_SIM_RC=0',
    ].join('\n')
    assert.deepEqual(lib.parseAptSimulation(out), { noApt: false, count: 1, packages: ['libexample1'], upgrades: 2, updateOk: true, simOk: true })
    assert.equal(lib.parseAptSimulation('NETHERSEC_NOAPT\n').noApt, true)
  })

  it('alerts on the second daily check in a row, keeps state when not due or unreadable', () => {
    const hit = { name: 'Ubuntu-24.04', ok: true, count: 3, packages: ['openssl'], updateOk: true }
    const day1 = lib.evaluateWsl({ results: [hit], now: NOW })
    assert.deepEqual(day1.active, [])
    assert.equal(day1.pending.length, 1)
    const skipped = lib.evaluateWsl({ results: [{ name: 'Ubuntu-24.04', skipped: true }], wslState: day1.wslState, now: NOW + 6 * 3_600_000 })
    assert.deepEqual(skipped.wslState, day1.wslState)
    const day2 = lib.evaluateWsl({ results: [hit], wslState: day1.wslState, now: NOW + DAY })
    assert.deepEqual(day2.active, [{ key: 'wsl:Ubuntu-24.04', name: 'Ubuntu-24.04', count: 3, packages: ['openssl'] }])
    const broken = lib.evaluateWsl({ results: [{ name: 'Ubuntu-24.04', ok: false, error: 'timed out' }], wslState: day2.wslState, now: NOW + 2 * DAY })
    assert.equal(broken.readable, false)
    assert.equal(broken.active.length, 1)
    const staleZero = lib.evaluateWsl({ results: [{ ...hit, count: 0, packages: [], updateOk: false }], wslState: day2.wslState, now: NOW + 2 * DAY })
    assert.equal(staleZero.readable, false)
    assert.equal(staleZero.active.length, 1)
    const fixed = lib.evaluateWsl({ results: [{ ...hit, count: 0, packages: [] }], wslState: day2.wslState, now: NOW + 2 * DAY })
    assert.deepEqual(fixed.active, [])
    assert.equal(lib.evaluateWsl({ results: [hit], now: NOW, ignoreGrace: true }).active.length, 1)
  })
})

describe('exploited (CISA KEV)', () => {
  const watch = lib.normalizeWatch({
    apps: [
      { id: 'Git.Git', name: 'Git', kev: [{ vendorProject: '^Git$', product: '^Git' }] },
      { id: 'Contoso.Archiver', name: 'Archiver', kev: [{ vendorProject: '^Contoso$', product: '^Archiver' }] },
    ],
  })
  const day = (offset) => new Date(NOW + offset * DAY).toISOString().slice(0, 10)
  const catalog = {
    vulnerabilities: [
      { cveID: 'CVE-2025-0001', vendorProject: 'Git', product: 'Git', dateAdded: '2024-01-22' },
      { cveID: 'CVE-2026-1000', vendorProject: 'Git', product: 'Git', dateAdded: day(-5) },
      { cveID: 'CVE-2026-2000', vendorProject: 'Microsoft', product: 'Windows', dateAdded: day(-16) },
      { cveID: 'CVE-2026-3000', vendorProject: 'GitLab', product: 'GitLab', dateAdded: day(-2) },
    ],
  }
  const target = (key, over = {}) => ({
    key,
    label: key === 'Git.Git' ? 'Git' : 'Archiver',
    kev: watch.apps.find((e) => e.key === key).kev,
    installed: true,
    version: '2.40.0',
    updateAvailable: '2.41.0.2',
    updateKnown: true,
    update: `winget upgrade --id ${key}`,
    ...over,
  })
  const clean = { readable: true, securityPending: false, build: '26100.1000' }

  it('first run: records the catalog, reports only recent matches, Windows entries follow Windows Update', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    assert.equal(r.firstRun, true)
    assert.deepEqual(Object.keys(r.findings), ['CVE-2026-1000'])
    partial(r.findings['CVE-2026-1000'], { actionable: true, label: 'Git', installed: '2.40.0', update: '2.41.0.2', command: 'winget upgrade --id Git.Git' })
    assert.deepEqual(r.treatedFixed, ['CVE-2026-2000'])
    assert.deepEqual(r.kevState.seen, ['CVE-2025-0001', 'CVE-2026-1000', 'CVE-2026-2000', 'CVE-2026-3000'])
    assert.equal(r.kevState.baselined, true)
  })

  it('a Windows entry is a finding while a security update waits, and waits while Windows Update is unreadable', () => {
    const pending = lib.evaluateKev({ catalog, targets: [], windows: { ...clean, securityPending: true }, now: NOW })
    partial(pending.findings['CVE-2026-2000'], { target: 'windows', actionable: true, installed: 'build 26100.1000' })
    const blind = lib.evaluateKev({ catalog, targets: [], windows: { readable: false, securityPending: false }, now: NOW })
    assert.deepEqual(blind.findings, {})
    assert.deepEqual(blind.deferred, ['CVE-2026-2000'])
    assert.equal(blind.kevState.seen.includes('CVE-2026-2000'), false)
    const closed = lib.evaluateKev({ catalog, kevState: pending.kevState, targets: [], windows: clean, now: NOW + DAY })
    assert.deepEqual(closed.findings, {})
  })

  it('later runs report any new matching entry, once', () => {
    const base = lib.evaluateKev({ catalog, targets: [target('Git.Git', { installed: false })], windows: clean, now: NOW })
    assert.deepEqual(base.findings, {})
    const grown = { vulnerabilities: [...catalog.vulnerabilities, { cveID: 'CVE-2019-9999', vendorProject: 'Git', product: 'Git for Windows', dateAdded: day(0) }] }
    const r = lib.evaluateKev({ catalog: grown, kevState: base.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + DAY })
    assert.deepEqual(r.added, ['CVE-2019-9999'])
    const again = lib.evaluateKev({ catalog: grown, kevState: r.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(again.added, [])
    assert.deepEqual(Object.keys(again.findings), ['CVE-2019-9999'])
  })

  it('closes a finding once the app is updated', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const updated = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { version: '2.41.0.2', updateAvailable: '' })], windows: clean, now: NOW + DAY })
    assert.deepEqual(updated.findings, {})
  })

  it('an app already on the newest version gets a one-time notice', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git', { updateAvailable: '' })], windows: clean, now: NOW })
    partial(r.findings['CVE-2026-1000'], { actionable: false, notice: true })
    r.kevState.findings['CVE-2026-1000'].delivered = true
    assert.deepEqual(lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { updateAvailable: '' })], windows: clean, now: NOW + DAY }).findings, {})
  })

  it('waits on app matches while the installed list is unreadable', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git', { installed: null })], windows: clean, now: NOW })
    assert.deepEqual(r.findings, {})
    assert.deepEqual(r.deferred, ['CVE-2026-1000'])
    const next = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + DAY })
    assert.deepEqual(Object.keys(next.findings), ['CVE-2026-1000'])
  })

  it('a watch entry added later gets the 30-day look-back for itself', () => {
    const z = { vulnerabilities: [...catalog.vulnerabilities, { cveID: 'CVE-2026-4000', vendorProject: 'Contoso', product: 'Archiver', dateAdded: day(-10) }] }
    const base = lib.evaluateKev({ catalog: z, targets: [target('Git.Git', { installed: false })], windows: clean, now: NOW })
    const r = lib.evaluateKev({
      catalog: z,
      kevState: base.kevState,
      targets: [target('Git.Git', { installed: false }), target('Contoso.Archiver', { version: '12.40', updateAvailable: '13.15' })],
      windows: clean,
      now: NOW + DAY,
    })
    assert.deepEqual(Object.keys(r.findings), ['CVE-2026-4000'])
  })

  it('a winget read that misses the app row does not close the finding', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const blip = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { updateAvailable: '' })], windows: clean, now: NOW + DAY })
    assert.deepEqual(Object.keys(blip.findings), ['CVE-2026-1000'])
    assert.deepEqual(blip.closedNow, [])
    const unknownUpdate = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { updateAvailable: '', updateKnown: false })], windows: clean, now: NOW + DAY })
    assert.deepEqual(Object.keys(unknownUpdate.findings), ['CVE-2026-1000'])
  })

  it('keeps a finding open when the version went up but an update still waits', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const partly = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { version: '2.40.2' })], windows: clean, now: NOW + DAY })
    partial(partly.findings['CVE-2026-1000'], { installed: '2.40.2', update: '2.41.0.2' })
  })

  it('a version that went up does not close a finding while winget upgrade cannot be read', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const blind = target('Git.Git', { version: '2.41.0.2', updateAvailable: '', updateKnown: false, upgradeReadable: false })
    const one = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [blind], windows: clean, now: NOW + DAY })
    assert.deepEqual(one.closedNow, [])
    partial(one.findings['CVE-2026-1000'], { installed: '2.40.0' })
    const read = lib.evaluateKev({ catalog, kevState: one.kevState, targets: [target('Git.Git', { version: '2.41.0.2', updateAvailable: '' })], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(read.closedNow, ['CVE-2026-1000'])
  })

  it('closing drops the CVE from the seen list; it stays quiet while fixed and reopens if the old version returns', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const upToDate = target('Git.Git', { version: '2.41.0.2', updateAvailable: '' })
    const fixed = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [upToDate], windows: clean, now: NOW + DAY })
    assert.deepEqual(fixed.findings, {})
    assert.deepEqual(fixed.closedNow, ['CVE-2026-1000'])
    assert.equal(fixed.kevState.seen.includes('CVE-2026-1000'), false)
    const quiet = lib.evaluateKev({ catalog, kevState: fixed.kevState, targets: [upToDate], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(quiet.added, [])
    assert.deepEqual(quiet.findings, {})
    assert.equal(quiet.kevState.seen.includes('CVE-2026-1000'), true)
    const rolledBack = lib.evaluateKev({ catalog, kevState: fixed.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(rolledBack.added, ['CVE-2026-1000'])
    partial(rolledBack.findings['CVE-2026-1000'], { actionable: true, installed: '2.40.0' })
  })

  it('closes after the app is absent on 2 good reads in a row, and reopens if it comes back behind', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const one = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { installed: false })], windows: clean, now: NOW + DAY })
    assert.deepEqual(Object.keys(one.findings), ['CVE-2026-1000'])
    const blind = lib.evaluateKev({ catalog, kevState: one.kevState, targets: [target('Git.Git', { installed: null })], windows: clean, now: NOW + DAY })
    assert.equal(blind.findings['CVE-2026-1000'].absent, 1)
    const two = lib.evaluateKev({ catalog, kevState: one.kevState, targets: [target('Git.Git', { installed: false })], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(two.findings, {})
    const stillGone = lib.evaluateKev({ catalog, kevState: two.kevState, targets: [target('Git.Git', { installed: false })], windows: clean, now: NOW + 3 * DAY })
    assert.deepEqual(stillGone.added, [])
    assert.deepEqual(stillGone.watching, ['CVE-2026-1000'])
    const back = lib.evaluateKev({ catalog, kevState: stillGone.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + 4 * DAY })
    assert.deepEqual(back.added, ['CVE-2026-1000'])
  })

  // Closed records: the next read that can settle one does; only an unsettled one waits.
  const closeOnUpdate = () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    return lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { version: '2.41.0.2', updateAvailable: '' })], windows: clean, now: NOW + DAY })
  }
  const closeOnRemoval = () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const one = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [target('Git.Git', { installed: false })], windows: clean, now: NOW + DAY })
    return lib.evaluateKev({ catalog, kevState: one.kevState, targets: [target('Git.Git', { installed: false })], windows: clean, now: NOW + 2 * DAY })
  }

  it('the next read that can settle a closed finding drops its record', () => {
    const fixed = closeOnUpdate()
    partial(fixed.kevState.closed['CVE-2026-1000'], { target: 'Git.Git', version: '2.41.0.2', at: NOW + DAY })
    const upToDate = target('Git.Git', { version: '2.41.0.2', updateAvailable: '' })
    const settled = lib.evaluateKev({ catalog, kevState: fixed.kevState, targets: [upToDate], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(settled.watching, [])
    assert.deepEqual(settled.kevState.closed, {})
    assert.equal(settled.kevState.seen.includes('CVE-2026-1000'), true)
  })

  it('a read that cannot settle a closed finding keeps its record', () => {
    const fixed = closeOnUpdate()
    for (const blind of [{ installed: null }, { version: 'Unknown', updateAvailable: '' }]) {
      const w = lib.evaluateKev({ catalog, kevState: fixed.kevState, targets: [target('Git.Git', blind)], windows: clean, now: NOW + 2 * DAY })
      assert.deepEqual(w.watching, ['CVE-2026-1000'])
      assert.deepEqual(w.kevState.closed, fixed.kevState.closed)
      const rolledBack = lib.evaluateKev({ catalog, kevState: w.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + 3 * DAY })
      assert.deepEqual(rolledBack.added, ['CVE-2026-1000'])
    }
    // After a removal the update list decides, so the record waits while that cannot be read.
    const removed = closeOnRemoval()
    partial(removed.kevState.closed['CVE-2026-1000'], { version: '' })
    const blindUpgrade = target('Git.Git', { updateAvailable: '', updateKnown: false, upgradeReadable: false })
    const back = lib.evaluateKev({ catalog, kevState: removed.kevState, targets: [blindUpgrade], windows: clean, now: NOW + 3 * DAY })
    assert.deepEqual(back.watching, ['CVE-2026-1000'])
    const seenBehind = lib.evaluateKev({ catalog, kevState: back.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + 4 * DAY })
    assert.deepEqual(seenBehind.added, ['CVE-2026-1000'])
  })

  it('a record no read could settle ends quietly a year (KEV_WATCH_DAYS) after the fix', () => {
    const removed = closeOnRemoval()
    const gone = target('Git.Git', { installed: false })
    const lastDay = NOW + 2 * DAY + (lib.KEV_WATCH_DAYS - 1) * DAY
    const late = lib.evaluateKev({ catalog, kevState: removed.kevState, targets: [gone], windows: clean, now: lastDay })
    assert.deepEqual(late.watching, ['CVE-2026-1000'])
    assert.deepEqual(lib.evaluateKev({ catalog, kevState: late.kevState, targets: [target('Git.Git')], windows: clean, now: lastDay }).added, ['CVE-2026-1000'])
    const ended = lib.evaluateKev({ catalog, kevState: removed.kevState, targets: [gone], windows: clean, now: lastDay + DAY })
    assert.deepEqual(ended.watching, [])
    assert.deepEqual(ended.kevState.closed, {})
    assert.equal(ended.kevState.seen.includes('CVE-2026-1000'), true)
    // Nor is it taken for a new match: an app that is back and up to date gets no notice.
    const fixed = closeOnUpdate()
    const upToDate = target('Git.Git', { version: '2.41.0.2', updateAvailable: '' })
    const expired = lib.evaluateKev({ catalog, kevState: fixed.kevState, targets: [upToDate], windows: clean, now: NOW + DAY + lib.KEV_WATCH_DAYS * DAY })
    assert.deepEqual(expired.findings, {})
    assert.deepEqual(expired.added, [])
  })

  it('a partial Windows Update read neither closes nor decides Windows findings', () => {
    const pending = lib.evaluateKev({ catalog, targets: [], windows: { ...clean, securityPending: true }, now: NOW })
    const partialRead = lib.evaluateKev({ catalog, kevState: pending.kevState, targets: [], windows: { readable: false, securityPending: false }, now: NOW + DAY })
    assert.deepEqual(Object.keys(partialRead.findings), ['CVE-2026-2000'])
    const done = lib.evaluateKev({ catalog, kevState: pending.kevState, targets: [], windows: clean, now: NOW + DAY })
    assert.deepEqual(done.findings, {})
    assert.equal(done.kevState.seen.includes('CVE-2026-2000'), false)
    const after = lib.evaluateKev({ catalog, kevState: done.kevState, targets: [], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(after.added, [])
    assert.deepEqual(after.treatedFixed, ['CVE-2026-2000'])
  })

  it('leaves findings of a skipped watch entry alone, and gives it the look-back once fixed', () => {
    const r = lib.evaluateKev({ catalog, targets: [target('Git.Git')], windows: clean, now: NOW })
    const frozen = lib.evaluateKev({ catalog, kevState: r.kevState, targets: [], frozenKeys: ['Git.Git'], windows: clean, now: NOW + DAY })
    assert.deepEqual(Object.keys(frozen.findings), ['CVE-2026-1000'])
    const grown = { vulnerabilities: [...catalog.vulnerabilities, { cveID: 'CVE-2026-5000', vendorProject: 'Git', product: 'Git', dateAdded: day(1) }] }
    const stillFrozen = lib.evaluateKev({ catalog: grown, kevState: frozen.kevState, targets: [], frozenKeys: ['Git.Git'], windows: clean, now: NOW + DAY })
    assert.deepEqual(stillFrozen.added, [])
    const repaired = lib.evaluateKev({ catalog: grown, kevState: stillFrozen.kevState, targets: [target('Git.Git')], windows: clean, now: NOW + 2 * DAY })
    assert.deepEqual(repaired.added, ['CVE-2026-5000'])
  })

  it('matchers need every given field to match', () => {
    const m = watch.apps[0].kev[0]
    assert.equal(lib.kevMatches({ vendorProject: 'Git', product: 'Git' }, m), true)
    assert.equal(lib.kevMatches({ vendorProject: 'GitLab', product: 'GitLab' }, m), false)
    assert.equal(lib.isWindowsKev({ vendorProject: 'Microsoft', product: 'Windows ' }), true)
    assert.equal(lib.isWindowsKev({ vendorProject: 'Microsoft', product: 'Win32k' }), true)
    assert.equal(lib.isWindowsKev({ vendorProject: 'Microsoft', product: 'Office' }), false)
  })
})

describe('report transitions', () => {
  const finding = (keys, over = {}) => ({ active: true, items: keys.map((key) => ({ key })), severity: 'warning', ...over })

  it('a check that cannot read changes nothing', () => {
    assert.equal(lib.decideReport({ sent: 'active', sentItems: ['a'], sentAt: NOW }, null, NOW).action, 'none')
  })

  it('sends on ok -> active, not again while unchanged, then a weekly reminder', () => {
    const first = lib.decideReport(undefined, finding(['a']), NOW)
    assert.deepEqual(first, { action: 'trigger', reason: 'new' })
    const ev = lib.recordDelivered({}, first, finding(['a']), NOW)
    assert.equal(lib.decideReport(ev, finding(['a']), NOW + 6 * DAY).action, 'none')
    assert.deepEqual(lib.decideReport(ev, finding(['a']), NOW + 7 * DAY), { action: 'trigger', reason: 'reminder' })
  })

  it('re-sends when an item joins, not when one leaves (but forgets the one that left)', () => {
    const ev = lib.recordDelivered({}, { action: 'trigger' }, finding(['a', 'b']), NOW)
    assert.deepEqual(lib.decideReport(ev, finding(['a', 'b', 'c']), NOW + DAY), { action: 'trigger', reason: 'changed', added: ['c'] })
    assert.deepEqual(lib.decideReport(ev, finding(['a']), NOW + DAY), { action: 'none', reason: 'unchanged', shrink: ['a'] })
  })

  it('re-sends when the severity goes up', () => {
    const ev = lib.recordDelivered({}, { action: 'trigger' }, finding(['a']), NOW)
    assert.equal(lib.decideReport(ev, finding(['a'], { severity: 'critical' }), NOW + DAY).reason, 'changed')
  })

  it('resolves once on active -> ok, quietly when asked', () => {
    const ev = lib.recordDelivered({}, { action: 'trigger' }, finding(['a']), NOW)
    assert.equal(lib.decideReport(ev, { active: false }, NOW).action, 'resolve')
    assert.equal(lib.decideReport(ev, { active: false, quiet: true }, NOW).action, 'quiet-clear')
    assert.equal(lib.decideReport(lib.recordDelivered(ev, { action: 'resolve' }, null, NOW), { active: false }, NOW).action, 'none')
    assert.equal(lib.decideReport(undefined, { active: false }, NOW).action, 'none')
  })

  it('caps a run and sends new problems before resolves and reminders', () => {
    const list = [
      { event: 'apps-behind', decision: { action: 'trigger', reason: 'reminder' } },
      { event: 'firewall', decision: { action: 'resolve', reason: 'cleared' } },
      { event: 'wsl-updates', decision: { action: 'trigger', reason: 'new' } },
      { event: 'exploited', decision: { action: 'trigger', reason: 'changed' } },
      { event: 'defender', decision: { action: 'none', reason: 'ok' } },
    ]
    const p = lib.planReports(list, 2)
    assert.deepEqual(p.send.map((x) => x.event), ['exploited', 'wsl-updates'])
    assert.deepEqual(p.deferred.map((x) => x.event), ['firewall', 'apps-behind'])
  })

  it('a check unreadable for over 2 days becomes a monitor-unreadable item, and clears on a good read', () => {
    let t = lib.trackReadability({}, { 'apps-behind': { readable: false, error: 'winget failed' } }, NOW)
    assert.deepEqual(t.items, [])
    t = lib.trackReadability(t.checks, { 'apps-behind': { readable: false, error: 'winget failed' } }, NOW + 2 * DAY + 1)
    assert.deepEqual(t.items, [{ key: 'apps-behind', error: 'winget failed' }])
    t = lib.trackReadability(t.checks, { 'apps-behind': { readable: true } }, NOW + 3 * DAY)
    assert.deepEqual(t.items, [])
  })

  it('forgets a check that did not run (turned off), so its cannot-read alert ends', () => {
    let t = lib.trackReadability({}, { 'runtimes.go': { readable: false, error: 'go.dev: timed out' } }, NOW)
    t = lib.trackReadability(t.checks, { 'runtimes.go': { readable: false, error: 'go.dev: timed out' } }, NOW + 3 * DAY)
    assert.equal(t.items.length, 1)
    const off = lib.trackReadability(t.checks, { defender: { readable: true } }, NOW + 3 * DAY + 1)
    assert.deepEqual(off.items, [])
    assert.deepEqual(Object.keys(off.checks), ['defender'])
  })
})

describe('time safety', () => {
  it('clamps stored times from the future to now, leaving counts and ids alone', () => {
    const s = {
      apps: { 'Git.Git': { firstBehind: NOW + 5 * DAY, missing: 1, installed: '2.40.0' } },
      checks: { x: { failSince: NOW + DAY, lastOk: NOW - DAY } },
      kev: { seen: ['CVE-1'], closed: { 'CVE-2': { at: NOW + DAY, version: '', target: 'Git.Git' } } },
      events: { a: { sentAt: NOW + 3 * DAY, sentItems: ['k'] } },
    }
    assert.deepEqual(lib.clampFutureTimes(s, NOW), {
      apps: { 'Git.Git': { firstBehind: NOW, missing: 1, installed: '2.40.0' } },
      checks: { x: { failSince: NOW, lastOk: NOW - DAY } },
      kev: { seen: ['CVE-1'], closed: { 'CVE-2': { at: NOW, version: '', target: 'Git.Git' } } },
      events: { a: { sentAt: NOW, sentItems: ['k'] } },
    })
  })

  it('a reminder is not stuck after a clock jump', () => {
    const ev = lib.clampFutureTimes({ sent: 'active', sentItems: ['a'], sentAt: NOW + 30 * DAY }, NOW)
    assert.equal(lib.decideReport(ev, { active: true, items: [{ key: 'a' }] }, NOW + 7 * DAY).reason, 'reminder')
  })

  it('cuts each probe to the time left in the run budget, and skips it under 3 seconds', () => {
    assert.equal(lib.probeTimeout(600_000, NOW + 14 * 60_000, NOW), 600_000)
    assert.equal(lib.probeTimeout(600_000, NOW + 60_000, NOW), 60_000)
    assert.equal(lib.probeTimeout(600_000, NOW + 2_000, NOW), 0)
    assert.equal(lib.probeTimeout(600_000, NOW - 1, NOW), 0)
  })
})

describe('report text', () => {
  const app = (i) => ({ key: `Vendor.App${i}`, id: `Vendor.App${i}`, name: `Some Application ${i}`, installed: '1.2.3', available: '1.2.4', update: `winget upgrade --id Vendor.App${i}` })

  it('one apps-behind report lists them all, clamped under 1000 characters with a +N more tail', () => {
    const d = lib.describeActive('apps-behind', { items: Array.from({ length: 60 }, (_, i) => app(i)) })
    assert.equal(d.title, '60 apps need updates')
    assert.ok(d.detail.length <= 1000)
    assert.match(d.detail, /; \+\d+ more\. Update one with: winget upgrade --id Vendor\.App0, or all with: winget upgrade --all$/)
  })

  it('names the fix command for one app', () => {
    const d = lib.describeActive('apps-behind', { items: [{ ...app(1), name: 'Git', installed: '2.40.0', available: '2.41.0.2', update: 'winget upgrade --id Git.Git' }] })
    assert.deepEqual(d, { title: 'Git needs an update', detail: 'Git 2.40.0 -> 2.41.0.2. Update with: winget upgrade --id Git.Git' })
  })

  it('clampJoin keeps whole items and counts the rest', () => {
    assert.equal(lib.clampJoin(['aaaa', 'bbbb', 'cccc'], 100), 'aaaa; bbbb; cccc')
    assert.equal(lib.clampJoin(['aaaa', 'bbbb', 'cccc'], 16), 'aaaa; bbbb; cccc')
    assert.equal(lib.clampJoin(['aaaa', 'bbbb', 'cccc'], 15), 'aaaa; +2 more')
    assert.ok(lib.clampJoin(['aaaa', 'bbbb', 'cccc'], 3).length <= 3)
    assert.equal(lib.clampText('x'.repeat(50), 10), 'xxxxxxx...')
  })

  it('every message is plain and fits the report protocol: no em-dash, title up to 120, detail up to 1500', () => {
    const items = {
      exploited: [{ key: 'CVE-1', cve: 'CVE-1', label: 'Git', product: 'Git Git', installed: '2.40.0', update: '2.41.0.2', actionable: true, command: 'winget upgrade --id Git.Git', target: 'Git.Git' }],
      'windows-updates': [{ key: 'KB1', title: '2025-03 Cumulative Update', kb: 'KB1', severity: 'Critical' }],
      defender: [{ key: 'realtime-off', text: 'Real-time protection is off.' }],
      firewall: [{ key: 'public', name: 'Public' }],
      runtimes: [{ key: 'go:1.21:patch', runtime: 'go', reason: 'patch', installed: '1.21.5', line: '1.21', target: '1.21.10' }],
      'apps-behind': [app(1)],
      'apps-eol': [{ key: 'X', name: 'Old runtime', version: '6.0.9', note: '' }],
      'wsl-updates': [{ key: 'wsl:U', name: 'Ubuntu-24.04', count: 2, packages: ['openssl', 'curl'] }],
      'monitor-unreadable': [{ key: 'apps-behind', error: 'winget failed' }],
    }
    const long = 'x'.repeat(400)
    for (const event of lib.EVENTS) {
      const d = lib.describeActive(event, { items: items[event], extra: { rebootPending: true, pausedUntil: '2025-04-03' } })
      const r = lib.describeResolved(event)
      for (const s of [d.title, d.detail, r.title, r.detail]) {
        assert.equal(s.includes(EM_DASH), false)
        assert.ok(s.length > 0)
      }
      // Long names still fit, and so does a reminder title.
      const big = items[event].map((i) => Object.fromEntries(Object.entries(i).map(([k, v]) => [k, typeof v === 'string' && k !== 'key' && k !== 'runtime' && k !== 'reason' ? v + long : v])))
      const body = lib.buildReport({ source: 'pc', event, decision: { action: 'trigger', reason: 'reminder' }, finding: { items: big, severity: 'warning' } })
      assert.ok(body.title.length <= 120, `${event} title is ${body.title.length}`)
      assert.ok(body.detail.length <= 1500, `${event} detail is ${body.detail.length}`)
    }
    assert.deepEqual(lib.describeActive('runtimes', { items: items.runtimes }), {
      title: 'Go 1.21.5 needs a security update',
      detail: 'Go 1.21.5 -> 1.21.10. Download from: go.dev/dl',
    })
    assert.equal(
      lib.describeActive('exploited', { items: items.exploited }).detail,
      'CVE-1 (Git Git): you have Git 2.40.0, update 2.41.0.2 is available. Attackers are using these flaws now. Update now: winget upgrade --id Git.Git',
    )
  })

  it('the Windows text follows the grace setting', () => {
    const items = [{ key: 'KB1', title: 'Update', kb: 'KB1', severity: '' }]
    assert.match(lib.describeActive('windows-updates', { items, extra: { graceDays: 7 } }).detail, /^Waiting over a week: /)
    assert.match(lib.describeActive('windows-updates', { items, extra: { graceDays: 3 } }).detail, /^Waiting over 3 days: /)
    assert.match(lib.describeActive('windows-updates', { items, extra: { graceDays: 1 } }).detail, /^Waiting over 1 day: /)
    assert.match(lib.describeActive('windows-updates', { items, extra: { graceDays: 0 } }).detail, /^Waiting: /)
  })

  it('builds the protocol body: triggered with severity, resolved without, reminders say so', () => {
    const f = { active: true, items: [{ key: 'public', name: 'Public' }], severity: 'warning' }
    assert.deepEqual(lib.buildReport({ source: 'pc', event: 'firewall', decision: { action: 'trigger', reason: 'new' }, finding: f }), {
      v: 1,
      kind: 'security',
      source: 'pc',
      event: 'firewall',
      state: 'triggered',
      severity: 'warning',
      title: 'Windows Firewall is off',
      detail: 'Off for: Public network. Turn it on in Windows Security > Firewall & network protection.',
    })
    assert.equal(lib.buildReport({ source: 'pc', event: 'firewall', decision: { action: 'trigger', reason: 'reminder' }, finding: f }).title, 'Reminder: Windows Firewall is off')
    assert.deepEqual(lib.buildReport({ source: 'pc', event: 'firewall', decision: { action: 'resolve', reason: 'cleared' }, finding: { active: false } }), {
      v: 1,
      kind: 'security',
      source: 'pc',
      event: 'firewall',
      state: 'resolved',
      title: 'Windows Firewall is on',
      detail: 'The firewall is on for every network.',
    })
  })

  it('every event name and the default source pass the protocol rules', () => {
    for (const e of lib.EVENTS) assert.match(e, /^[a-z0-9][a-z0-9._-]{0,63}$/)
    assert.match('pc', lib.SOURCE_RE)
  })
})
