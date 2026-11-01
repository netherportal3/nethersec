// Pure logic for the nethersec PC scanner: winget table parsing, version math, the
// per-check rules, grace clocks, report transitions, the message text, config checks
// and the delivery request (hub or Discord webhook). No I/O happens here, so the
// tests in pc/test cover all of it. No imports at all: it runs from a copy in
// %USERPROFILE%\.nethersec-pc with no node_modules.
//
// The same rules as the rest of nethersec (AGENTS.md):
//   - a check that cannot read returns null and changes nothing (never a false "ok");
//   - reports go out on a transition, when an active report gains an item, or as a
//     weekly reminder, never on every run;
//   - grace windows keep routine patching quiet.

export const HOUR = 3_600_000
export const DAY = 24 * HOUR

/** Report events in priority order (a run with more reports than its cap sends these first). */
export const EVENTS = [
  'exploited',
  'windows-updates',
  'defender',
  'firewall',
  'runtimes',
  'apps-behind',
  'apps-eol',
  'wsl-updates',
  'monitor-unreadable',
]

/** Plain names for the things that can fail to read, used in the monitor-unreadable report. */
export const CHECK_LABELS = {
  'windows-updates': 'Windows Update',
  defender: 'Defender status',
  firewall: 'Firewall status',
  'apps-behind': 'App updates (winget upgrade)',
  'apps-eol': 'Installed apps (winget list)',
  'runtimes.node': 'Node release list',
  'runtimes.go': 'Go release list',
  'runtimes.java': 'Java release list',
  'wsl-updates': 'WSL updates',
  exploited: 'Exploited flaws list (CISA)',
}

export const DEFAULTS = {
  appGraceDays: 7,
  runtimeGraceDays: 7,
  windowsGraceDays: 7,
  defenderSignatureMaxDays: 3,
  reminderDays: 7,
  unreadableAlertDays: 2,
  appTombstoneHours: 24,
  wslIntervalHours: 20,
  wslStreak: 2,
  kevLookbackDays: 30,
  maxPostsPerRun: 5,
  // The report protocol allows a 120-character title and a 1,500-character detail.
  titleMax: 120,
  detailMax: 1000,
}

/**
 * How long a closed exploited-flaw record waits for a read that can settle it (while
 * the app stays removed, say). After that its CVE counts as seen again, with no report.
 */
export const KEV_WATCH_DAYS = 365

/** The report protocol's rule for `source`, and the shape of a key. */
export const SOURCE_RE = /^[a-z0-9][a-z0-9-]{0,39}$/
export const KEY_RE = /^[0-9a-f]{64}$/

// Microsoft products in the CISA catalog that ship with Windows and are fixed through
// Windows Update. A KEV entry for one of these maps to the windows-updates check.
export const WINDOWS_KEV_PRODUCTS =
  /^(windows|win32k|dwm core library|smartscreen|directx|graphics|smbv|streaming service|task scheduler|ancillary function driver|client-server run-time|winverifytrust|internet key exchange|mshtml|defender|malware protection engine|common log file system|kerberos|remote desktop|http protocol stack|http\.sys)/i

// ---------------------------------------------------------------------------
// Console text
// ---------------------------------------------------------------------------

/**
 * Split console output into clean lines: ANSI escapes removed, backspaces applied,
 * a carriage return keeps only what was written after it (a spinner redraws the
 * same line), trailing spaces trimmed.
 * @param {string} text
 * @returns {string[]}
 */
export function cleanConsoleLines(text) {
  const s = String(text ?? '')
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
  const out = []
  for (let line of s.split('\n')) {
    if (line.endsWith('\r')) line = line.slice(0, -1)
    if (line.includes('\b')) {
      const chars = []
      for (const ch of line) {
        if (ch === '\b') chars.pop()
        else chars.push(ch)
      }
      line = chars.join('')
    }
    const cr = line.lastIndexOf('\r')
    if (cr >= 0) line = line.slice(cr + 1)
    out.push(line.replace(/\s+$/, ''))
  }
  return out
}

/** A spinner frame or a progress bar line winget draws while it works. */
function isJunkLine(trimmed) {
  if (/^[-\\|/]$/.test(trimmed)) return true
  if (/[\u2580-\u259f\u25a0\u25a1]/.test(trimmed)) return true
  return false
}

/** Terminal cell width of one code point (wide East Asian and emoji take 2). */
function charWidth(cp) {
  if (cp < 32 || (cp >= 0x7f && cp < 0xa0)) return 0
  if ((cp >= 0x300 && cp <= 0x36f) || (cp >= 0x200b && cp <= 0x200f) || cp === 0xfe0f) return 0
  if (
    (cp >= 0x1100 && cp <= 0x115f) ||
    (cp >= 0x2e80 && cp <= 0xa4cf && cp !== 0x303f) ||
    (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe4f) ||
    (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f300 && cp <= 0x1f64f) ||
    (cp >= 0x1f900 && cp <= 0x1f9ff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) {
    return 2
  }
  return 1
}

/** The part of `line` that sits in terminal columns [start, end). */
function sliceCells(line, start, end) {
  let col = 0
  let out = ''
  for (const ch of line) {
    const w = charWidth(ch.codePointAt(0) ?? 0)
    if (col >= start && col < end) out += ch
    col += w
    if (col >= end) break
  }
  return out
}

/** Start column of each word in a header line. */
function headerTokens(line) {
  const tokens = []
  let col = 0
  let cur = null
  for (const ch of line) {
    if (/\s/.test(ch)) {
      if (cur) tokens.push(cur)
      cur = null
    } else if (!cur) {
      cur = { label: ch, start: col }
    } else {
      cur.label += ch
    }
    col += charWidth(ch.codePointAt(0) ?? 0)
  }
  if (cur) tokens.push(cur)
  return tokens
}

const KNOWN_COLUMNS = ['name', 'id', 'version', 'available', 'source']

/** Map a table header to column keys, by English label or else by position. */
function headerColumns(line) {
  const tokens = headerTokens(line)
  if (tokens.length < 3) return null
  const labels = tokens.map((t) => t.label.toLowerCase())
  let keys
  if (labels.every((l) => KNOWN_COLUMNS.includes(l))) keys = labels
  else if (tokens.length === 5) keys = ['name', 'id', 'version', 'available', 'source']
  else if (tokens.length === 4) keys = ['name', 'id', 'version', 'source']
  else return null
  if (keys[0] !== 'name' || keys[1] !== 'id') return null
  return tokens.map((t, i) => ({ key: keys[i], start: t.start }))
}

/** The terminal cells of a line: the character that starts in each, '' for the second cell of a wide one. */
function cellMap(line) {
  const at = []
  for (const ch of line) {
    const w = charWidth(ch.codePointAt(0) ?? 0)
    if (w > 0) at.push(ch, ...Array(w - 1).fill(''))
  }
  return at
}

/**
 * Where each column starts in one table row, in terminal cells. winget puts at least
 * one space between columns. A name with a character that winget measures wider or
 * narrower than this file does (some emoji) shifts the columns after it by a cell or
 * two; each column then starts where its value begins, at most 2 cells from where the
 * header says. Null when a column has no clear start: the row is not read.
 * @param {string} line
 * @param {Array<{start: number}>} cols
 * @returns {number[]|null}
 */
function rowStarts(line, cols) {
  const at = cellMap(line)
  const blank = (col) => col < 0 || col >= at.length || /\s/.test(at[col])
  const starts = [cols[0].start]
  let shift = 0
  for (let c = 1; c < cols.length; c++) {
    const s = cols[c].start + shift
    const d = [0, -1, 1, -2, 2].find((k) => blank(s + k - 1) && (k === 0 || !blank(s + k)))
    if (d === undefined) return null
    shift += d
    starts.push(s + d)
  }
  return starts
}

function isFooterLine(t) {
  return (
    /^\d+\s+(upgrades?|packages?|package\(s\))\b/i.test(t) ||
    /^the following packages/i.test(t) ||
    /require explicit targeting/i.test(t)
  )
}

/**
 * Parse `winget upgrade` or `winget list` output. Handles several tables (the
 * "require explicit targeting" section is a second table), the "N upgrades
 * available." footer, names or ids cut short with an ellipsis, spinner and
 * progress lines, and versions with spaces ("15.2.3 (January 2020)").
 * `ok` is false when no table and no "nothing found" message could be read.
 * `unread` holds the table rows it could not read (wingetReadable then refuses
 * the whole read: such a row could be any app).
 * @param {string} text
 * @returns {{ ok: boolean, empty: boolean, rows: Array<{name: string, id: string, version: string, available: string, source: string, explicit: boolean, nameTruncated: boolean, idTruncated: boolean}>, footerCount: number|null, failedSources: string[], errors: string[], notes: string[], unread: string[] }}
 */
export function parseWingetTable(text) {
  const lines = cleanConsoleLines(text)
  /** @type {any[]} */
  const rows = []
  const notes = []
  const errors = []
  const failedSources = []
  const unread = []
  let footerCount = null
  let tables = 0
  let empty = false
  let explicit = false
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const t = line.trim()
    if (!t || isJunkLine(t)) continue
    if (/require explicit targeting/i.test(t)) {
      explicit = true
      continue
    }
    const failed = /^failed when searching source:?\s*(.*)$/i.exec(t)
    if (failed) {
      failedSources.push(failed[1].trim().toLowerCase())
      errors.push(t)
      continue
    }
    if (/unexpected error|failed to (open|update) (the )?(predefined )?source|0x8a15/i.test(t)) {
      errors.push(t)
      continue
    }
    if (/^no (installed package found|available upgrade found|newer package versions? (is|are) available)/i.test(t)) {
      empty = true
      continue
    }
    const footer = /^(\d+)\s+upgrades?\s+available/i.exec(t)
    if (footer) {
      if (footerCount === null) footerCount = Number(footer[1])
      continue
    }
    const next = (lines[i + 1] ?? '').trim()
    if (!/^-{10,}$/.test(next)) continue
    const cols = headerColumns(line)
    if (!cols) {
      errors.push(`unrecognized table header: ${t.slice(0, 80)}`)
      i++
      continue
    }
    tables++
    i += 2
    for (; i < lines.length; i++) {
      const rowLine = lines[i]
      const rt = rowLine.trim()
      if (!rt) break
      if (isJunkLine(rt)) continue
      if (isFooterLine(rt)) {
        i--
        break
      }
      const starts = rowStarts(rowLine, cols)
      const row = {}
      for (let c = 0; starts && c < cols.length; c++) {
        const end = c + 1 < cols.length ? starts[c + 1] : Infinity
        row[cols[c].key] = sliceCells(rowLine, starts[c], end).trim()
      }
      // A winget id has no spaces; a local ARP or MSIX id can ("ARP\Machine\X64\Example App 123456").
      if (!starts || !row.name || !row.id || (/\s/.test(row.id) && !/^(ARP|MSIX)\\/i.test(row.id))) {
        unread.push(rt.replace(/\s+/g, ' ').slice(0, 80))
        continue
      }
      rows.push({
        name: row.name,
        id: row.id,
        version: row.version ?? '',
        available: row.available ?? '',
        source: (row.source ?? '').toLowerCase(),
        explicit,
        nameTruncated: row.name.endsWith('\u2026'),
        idTruncated: row.id.endsWith('\u2026'),
      })
    }
  }
  if (footerCount !== null) {
    const first = rows.filter((r) => !r.explicit).length
    if (first !== footerCount) notes.push(`footer says ${footerCount} upgrades, read ${first}`)
  }
  // Without the main winget source the list is mostly missing: not a read.
  const ok = (tables > 0 || empty) && !failedSources.includes('winget')
  return { ok, empty: empty && tables === 0, rows, footerCount, failedSources, errors, notes, unread }
}

/**
 * Is a winget run a good read? Not when it timed out, when the table did not parse,
 * when it has a row the parser could not read (that row could be any app, so the
 * read cannot say what is or is not installed or behind), when the
 * "N upgrades available." footer disagrees with the rows read, when
 * `winget upgrade` printed rows but no footer (output cut short), or when winget
 * exited non-zero without a complete answer ("nothing to upgrade", or a full
 * upgrade table with a matching footer, which winget can print while a minor
 * source such as msstore failed).
 * @param {ReturnType<typeof parseWingetTable>} parsed
 * @param {string|null} runError  null, "timed out", "out of time", "not installed" or "exit code N"
 * @param {{ expectFooter?: boolean }} [opts]  true for `winget upgrade`
 * @returns {{ ok: boolean, reason: string }}
 */
export function wingetReadable(parsed, runError, opts = {}) {
  if (runError && /timed out|out of time|not installed/.test(runError)) return { ok: false, reason: `winget ${runError}` }
  if (!parsed.ok) return { ok: false, reason: parsed.errors[0] || 'no table in winget output' }
  const unread = parsed.unread ?? []
  if (unread.length) {
    const more = unread.length > 1 ? ` (and ${unread.length - 1} more)` : ''
    return { ok: false, reason: `could not read a row: ${unread[0]}${more}` }
  }
  const main = parsed.rows.filter((r) => !r.explicit).length
  if (parsed.footerCount !== null && parsed.footerCount !== main) {
    return { ok: false, reason: `winget said ${parsed.footerCount} upgrades but listed ${main}` }
  }
  if (opts.expectFooter && main > 0 && parsed.footerCount === null) {
    return { ok: false, reason: 'winget output ended before its summary line' }
  }
  if (runError) {
    const complete = (parsed.empty && parsed.rows.length === 0) || (!!opts.expectFooter && parsed.footerCount !== null)
    if (!complete) return { ok: false, reason: `winget failed (${runError})` }
  }
  return { ok: true, reason: '' }
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/**
 * Parse a version as winget, Node, Go or Java print it: "2.41.0.2", "v24.6.1",
 * "go1.21.5", "< 3.2.1", "3.1.0 (1001)", "15.2.3 (January 2020)", "Unknown".
 * @param {unknown} raw
 * @returns {{ raw: string, op: string, nums: number[], pre: string, build: number|null, unknown: boolean }}
 */
export function parseVersion(raw) {
  const text = String(raw ?? '').trim()
  let s = text.replace(/\u2026$/, '')
  let op = ''
  if (s.startsWith('<') || s.startsWith('>')) {
    op = s[0]
    s = s.slice(1).trim()
  }
  s = s.replace(/^(v|go)(?=\d)/i, '')
  const m = /^(\d+(?:\.\d+)*)(?:[-]?((?:rc|beta|alpha|pre|preview)[0-9A-Za-z.]*|-[0-9A-Za-z.-]+))?/i.exec(s)
  if (!m) return { raw: text, op, nums: [], pre: '', build: null, unknown: true }
  const nums = m[1].split('.').map(Number)
  const pre = m[2] ? m[2].replace(/^-/, '') : ''
  const b = /\((\d+)\)\s*$/.exec(s)
  return { raw: text, op, nums, pre, build: b ? Number(b[1]) : null, unknown: false }
}

function cmpNums(a, b, len = Math.max(a.length, b.length)) {
  for (let i = 0; i < len; i++) {
    const x = a[i] ?? 0
    const y = b[i] ?? 0
    if (x !== y) return x < y ? -1 : 1
  }
  return 0
}

/**
 * Compare two versions: -1, 0 or 1, or null when either cannot be read. An
 * installed "< X" (winget's "older than X") sorts below X.
 * @param {unknown} a
 * @param {unknown} b
 * @returns {-1|0|1|null}
 */
export function compareVersions(a, b) {
  const va = parseVersion(a)
  const vb = parseVersion(b)
  if (va.unknown || vb.unknown) return null
  let c = cmpNums(va.nums, vb.nums)
  if (c === 0) {
    if (va.pre && !vb.pre) c = -1
    else if (!va.pre && vb.pre) c = 1
    else if (va.pre !== vb.pre) c = va.pre < vb.pre ? -1 : 1
  }
  if (c === 0 && va.build !== null && vb.build !== null && va.build !== vb.build) c = va.build < vb.build ? -1 : 1
  // "< 3.2.1" is below 3.2.1 and "> 8.1" above 8.1; two equal markers stay equal.
  if (c === 0 && va.op !== vb.op) {
    if (va.op === '<' || vb.op === '>') c = -1
    else c = 1
  }
  return /** @type {-1|0|1} */ (c)
}

/**
 * True when `available` starts a newer release line than `installed`. A line is the
 * first `lineParts` numbers: 1 for most apps (a new major), 2 for Go (1.21 -> 1.22).
 * @param {unknown} installed
 * @param {unknown} available
 * @param {number} [lineParts]
 */
export function isNewerLine(installed, available, lineParts = 1) {
  const a = parseVersion(installed)
  const b = parseVersion(available)
  if (a.unknown || b.unknown) return false
  return cmpNums(a.nums, b.nums, Math.max(1, lineParts)) < 0
}

/** "1.21" for lineParts 2. */
function lineOf(nums, parts) {
  return nums.slice(0, parts).map((n) => n ?? 0).join('.')
}

// ---------------------------------------------------------------------------
// Watch list
// ---------------------------------------------------------------------------

function compileRegex(pattern, where, errors) {
  if (pattern === undefined || pattern === null || pattern === '') return null
  try {
    return new RegExp(String(pattern), 'i')
  } catch {
    errors.push(`${where}: not a valid pattern: ${String(pattern).slice(0, 60)}`)
    return null
  }
}

function normalizeMatchers(raw, where, errors) {
  const list = Array.isArray(raw) ? raw : raw ? [raw] : []
  const out = []
  for (const m of list) {
    if (!m || typeof m !== 'object') continue
    const vendor = compileRegex(m.vendorProject, `${where} kev`, errors)
    const product = compileRegex(m.product, `${where} kev`, errors)
    if (vendor || product) out.push({ vendor, product })
  }
  return out
}

/** The stable key of a watch entry, the same whether or not its patterns compile. */
function entryKey(e) {
  const id = typeof e.id === 'string' ? e.id.trim() : ''
  return id || String(e.name || e.idPattern || e.namePattern || '')
}

/**
 * One watch entry. Returns `{ entry }`, `{ skipped }` (it has a pattern that does
 * not compile: its last results are kept as they were), or `{}` (unusable).
 */
function normalizeEntry(e, i, where, errors) {
  if (!e || typeof e !== 'object') {
    errors.push(`${where}[${i}]: not an object`)
    return {}
  }
  const label = `${where}[${i}] (${entryKey(e) || 'no id'})`
  const bad = []
  const id = typeof e.id === 'string' ? e.id.trim() : ''
  const idPattern = compileRegex(e.idPattern, label, bad)
  const namePattern = compileRegex(e.namePattern, label, bad)
  const kev = normalizeMatchers(e.kev, label, bad)
  if (bad.length) {
    errors.push(...bad.map((b) => `${b} (entry skipped, its last result kept)`))
    return { skipped: { list: where, key: entryKey(e), error: bad[0] } }
  }
  if (!id && !idPattern && !namePattern) {
    errors.push(`${where}[${i}]: needs id, idPattern or namePattern`)
    return {}
  }
  const entry = {
    key: entryKey(e),
    id,
    idPattern,
    namePattern,
    name: typeof e.name === 'string' && e.name.trim() ? e.name.trim() : id,
    followsMajor: e.followsMajor === true,
    lineParts: Number.isInteger(e.lineParts) && e.lineParts > 0 ? e.lineParts : 1,
    check: e.check === 'runtimes' ? 'runtimes' : 'apps',
    update: typeof e.update === 'string' && e.update.trim() ? e.update.trim() : '',
    note: typeof e.note === 'string' ? e.note.trim() : '',
    kev,
  }
  return { entry }
}

/**
 * Validate watch.json: `apps` (watched for updates and exploited flaws) and `eol`
 * (end-of-life packages). An entry with a pattern that does not compile goes to
 * `skipped` (the checks keep its last results untouched); other bad entries are
 * dropped. Both are named in `errors`.
 * @param {any} raw
 */
export function normalizeWatch(raw) {
  /** @type {string[]} */
  const errors = []
  /** @type {Array<{list: string, key: string, error: string}>} */
  const skipped = []
  const src = raw && typeof raw === 'object' ? raw : {}
  const take = (list, name) => {
    /** @type {any[]} */
    const out = []
    ;(Array.isArray(list) ? list : []).forEach((e, i) => {
      const r = normalizeEntry(e, i, name, errors)
      if (r.entry) out.push(r.entry)
      if (r.skipped) skipped.push(r.skipped)
    })
    return out
  }
  const apps = take(src.apps, 'apps')
  const eol = take(src.eol, 'eol')
  return { apps, eol, skipped, errors }
}

/** The entry's exact id equals the row id, or the row id is that id cut short with an ellipsis. */
function idMatches(entry, rowId) {
  if (!entry || !entry.id) return false
  if (rowId.toLowerCase() === entry.id.toLowerCase()) return true
  if (!rowId.endsWith('\u2026')) return false
  const prefix = rowId.slice(0, -1).toLowerCase()
  return prefix.length >= 3 && entry.id.toLowerCase().startsWith(prefix)
}

/**
 * Parse the text of watch.json. A file that is not valid JSON, or whose `apps` or
 * `eol` is not a list, sets `unreadable`: apps-behind, apps-eol and exploited then
 * change nothing this run (an empty list must never read as "everything fixed").
 * @param {string} text
 */
export function parseWatchJson(text) {
  const none = { apps: [], eol: [], skipped: [] }
  let raw
  try {
    raw = JSON.parse(String(text ?? '').replace(/^\ufeff/, ''))
  } catch (e) {
    const why = `not valid JSON (${String(e && e.message ? e.message : e).slice(0, 120)})`
    return { ...none, errors: [`watch list is ${why}`], unreadable: why }
  }
  const bad =
    !raw || typeof raw !== 'object' || Array.isArray(raw)
      ? 'not a JSON object'
      : (raw.apps !== undefined && !Array.isArray(raw.apps)) || (raw.eol !== undefined && !Array.isArray(raw.eol))
        ? '"apps" and "eol" must be lists'
        : ''
  if (bad) return { ...none, errors: [`watch list is ${bad}`], unreadable: bad }
  return { ...normalizeWatch(raw), unreadable: /** @type {string|null} */ (null) }
}

/** Does a winget row belong to this watch entry? */
export function entryMatchesRow(entry, row) {
  const rowId = String(row.id || '')
  if (idMatches(entry, rowId)) return true
  if (entry.idPattern && entry.idPattern.test(rowId)) return true
  if (entry.namePattern && entry.namePattern.test(String(row.name || ''))) return true
  return false
}

function findEntry(entries, row) {
  return entries.find((e) => entryMatchesRow(e, row)) ?? null
}

/**
 * The name to show for a row. An exact-id entry uses its own name; a pattern entry
 * can match several packages, so it shows the row's name without version numbers
 * ("Example Runtime - 8.0.4 (x64)" -> "Example Runtime (x64)").
 */
export function displayName(entry, row) {
  if (idMatches(entry, String(row.id || '')) && entry.name && entry.name !== entry.id) return entry.name
  const cleaned = String(row.name || row.id)
    .replace(/\u2026$/, '')
    .replace(/\s*-?\s*\bv?\d+(\.\d+)+\b/g, '')
    .replace(/\s+-\s+/g, ' - ')
    .replace(/\s{2,}/g, ' ')
    .replace(/\s*-\s*(?=\(|$)/g, ' ')
    .trim()
  return cleaned || String(row.id)
}

// ---------------------------------------------------------------------------
// apps-behind
// ---------------------------------------------------------------------------

/**
 * Watched apps with a newer version available. The clock runs per package from the
 * first run that saw it behind and does not restart when an even newer version
 * appears. A newer major (or Go-style line) does not count unless the entry says the
 * app follows majors.
 *
 * One flaky read must not clear an app: a package that drops out of the behind list
 * stays in it until it is missing on 2 good reads in a row, or `installedRows`
 * (winget list) shows its installed version changed. It is then kept as a tombstone
 * for a day, so coming back at the same version resumes its old clock. Packages from
 * a source winget could not search, and packages of a watch entry that was skipped
 * (`frozenKeys`, a pattern that does not compile), are carried untouched.
 * @param {{ rows: any[], installedRows?: any[]|null, failedSources?: string[], entries: any[], frozenKeys?: string[], appState?: Record<string, any>, now: number, graceDays?: number, ignoreGrace?: boolean, tombstoneHours?: number }} p
 */
export function evaluateAppsBehind(p) {
  const { rows, entries, now } = p
  const failed = new Set((p.failedSources ?? []).map((s) => s.toLowerCase()))
  const frozen = new Set(p.frozenKeys ?? [])
  const liveKeys = new Set(entries.map((e) => e.key))
  const installedRows = Array.isArray(p.installedRows) ? p.installedRows : null
  const appState = p.appState ?? {}
  const graceMs = (p.graceDays ?? DEFAULTS.appGraceDays) * DAY
  const tombMs = (p.tombstoneHours ?? DEFAULTS.appTombstoneHours) * HOUR
  /** @type {Record<string, any>} */
  const next = {}
  const active = []
  const pending = []
  const majorSkipped = []
  const unknown = []
  for (const row of rows) {
    const entry = findEntry(entries, row)
    if (!entry || entry.check === 'runtimes') continue
    if (!row.available) continue
    const inst = parseVersion(row.version)
    if (inst.unknown && !inst.op) {
      unknown.push({ id: row.id, name: displayName(entry, row) })
      continue
    }
    const cmp = compareVersions(row.version, row.available)
    if (cmp === null || cmp >= 0) continue
    if (!entry.followsMajor && isNewerLine(row.version, row.available, entry.lineParts)) {
      majorSkipped.push({ id: row.id, name: displayName(entry, row), installed: row.version, available: row.available })
      continue
    }
    const key = row.id
    if (next[key] && compareVersions(next[key].installed, row.version) !== 1) continue
    const prev = appState[key]
    let firstBehind = now
    if (prev && typeof prev.firstBehind === 'number') {
      const resumed = !prev.goneSince || (now - prev.goneSince <= tombMs && prev.installed === row.version)
      if (resumed) firstBehind = prev.firstBehind
    }
    const name = displayName(entry, row)
    const update = entry.update || `winget upgrade --id ${key}`
    next[key] = { firstBehind, installed: row.version, available: row.available, name, source: row.source, update, entryKey: entry.key, missing: 0 }
  }
  for (const [key, prev] of Object.entries(appState)) {
    if (next[key] || !prev || typeof prev !== 'object') continue
    if (prev.goneSince) {
      if (now - prev.goneSince <= tombMs) next[key] = prev
      continue
    }
    if (prev.entryKey && frozen.has(prev.entryKey)) {
      next[key] = prev
      continue
    }
    if (prev.source && failed.has(String(prev.source).toLowerCase())) {
      next[key] = prev
      continue
    }
    if (prev.entryKey && !liveKeys.has(prev.entryKey)) continue // taken off the watch list
    const installedNow = installedRows ? installedRows.filter((r) => String(r.id).toLowerCase() === key.toLowerCase()) : []
    const changed = installedNow.length > 0 && !installedNow.some((r) => r.version === prev.installed)
    const missing = (prev.missing ?? 0) + 1
    next[key] = changed || missing >= 2 ? { ...prev, missing, goneSince: now } : { ...prev, missing }
  }
  for (const [key, s] of Object.entries(next)) {
    if (s.goneSince) continue
    const item = {
      key,
      id: key,
      name: s.name,
      installed: s.installed,
      available: s.available,
      firstBehind: s.firstBehind,
      update: s.update || `winget upgrade --id ${key}`,
    }
    if (p.ignoreGrace || now - s.firstBehind > graceMs) active.push(item)
    else pending.push(item)
  }
  const byName = (a, b) => a.name.localeCompare(b.name)
  return { active: active.sort(byName), pending: pending.sort(byName), majorSkipped, unknown, appState: next }
}

// ---------------------------------------------------------------------------
// apps-eol
// ---------------------------------------------------------------------------

/**
 * Installed packages that the watch list names as end of life. Items of a skipped
 * watch entry (`frozenKeys`) are carried from `prior` as they were.
 * @param {{ rows: any[], entries: any[], prior?: any[], frozenKeys?: string[] }} p
 */
export function evaluateEol({ rows, entries, prior = [], frozenKeys = [] }) {
  /** @type {any[]} */
  const items = []
  const seen = new Set()
  for (const row of rows) {
    const entry = findEntry(entries, row)
    if (!entry) continue
    const key = `${row.id}@${row.version}`
    if (seen.has(key)) continue
    seen.add(key)
    items.push({ key: row.id, id: row.id, name: displayName(entry, row), version: row.version, note: entry.note, entryKey: entry.key })
  }
  const frozen = new Set(frozenKeys)
  for (const it of Array.isArray(prior) ? prior : []) {
    if (it && frozen.has(it.entryKey) && !seen.has(`${it.id}@${it.version}`)) {
      seen.add(`${it.id}@${it.version}`)
      items.push(it)
    }
  }
  return items.sort((a, b) => a.name.localeCompare(b.name))
}

// ---------------------------------------------------------------------------
// runtimes
// ---------------------------------------------------------------------------

/**
 * Node: behind when a newer release in the SAME major line is a security release,
 * or the major is past end of life. A newer major is never "behind".
 * @param {{ installed: string[], index: any[], eolCycles?: any[]|null, now: number }} p
 */
export function evaluateNode({ installed, index, eolCycles, now }) {
  const items = []
  const releases = (Array.isArray(index) ? index : []).filter((r) => r && typeof r.version === 'string')
  for (const v of [...new Set(installed)]) {
    const iv = parseVersion(v)
    if (iv.unknown) continue
    const major = iv.nums[0]
    const newer = releases
      .filter((r) => parseVersion(r.version).nums[0] === major && compareVersions(r.version, v) === 1)
      .sort((a, b) => compareVersions(b.version, a.version) ?? 0)
    const security = newer.filter((r) => r.security === true)
    if (security.length) {
      const oldest = security[security.length - 1]
      const since = Date.parse(oldest.date)
      items.push({
        key: `node:${major}:security`,
        runtime: 'node',
        reason: 'security',
        installed: iv.nums.join('.'),
        target: newer[0].version.replace(/^v/, ''),
        since: Number.isFinite(since) ? since : undefined,
      })
    }
    if (Array.isArray(eolCycles)) {
      const cycle = eolCycles.find((c) => String(c?.cycle) === String(major))
      const eol = cycle && typeof cycle.eol === 'string' ? Date.parse(cycle.eol) : NaN
      if (Number.isFinite(eol) && eol < now) {
        const supported = eolCycles
          .filter((c) => c && c.lts && typeof c.eol === 'string' && Date.parse(c.eol) > now)
          .sort((a, b) => Number(b.cycle) - Number(a.cycle))
        items.push({
          key: `node:${major}:eol`,
          runtime: 'node',
          reason: 'eol',
          installed: iv.nums.join('.'),
          eolDate: cycle.eol,
          target: supported[0] ? String(supported[0].latest || supported[0].cycle) : '',
          noGrace: true,
        })
      }
    }
  }
  return items
}

/**
 * Go: behind when a newer patch of the same minor exists (Go ships security fixes
 * as patch releases), or the minor is no longer one of the two supported lines.
 * @param {{ installed: string, releases: any[] }} p
 */
export function evaluateGo({ installed, releases }) {
  const iv = parseVersion(installed)
  if (iv.unknown) return []
  const stable = (Array.isArray(releases) ? releases : []).filter(
    (r) => r && r.stable === true && typeof r.version === 'string' && !parseVersion(r.version).pre,
  )
  if (!stable.length) return []
  const line = lineOf(iv.nums, 2)
  const lines = [...new Set(stable.map((r) => lineOf(parseVersion(r.version).nums, 2)))].sort(
    (a, b) => cmpNums(b.split('.').map(Number), a.split('.').map(Number)),
  )
  const newest = (filter) =>
    stable
      .filter(filter)
      .map((r) => r.version.replace(/^go/, ''))
      .sort((a, b) => compareVersions(b, a) ?? 0)[0]
  const installedText = iv.nums.join('.')
  if (!lines.slice(0, 2).includes(line)) {
    return [
      { key: `go:${line}:unsupported`, runtime: 'go', reason: 'unsupported', installed: installedText, line, target: newest(() => true) },
    ]
  }
  const top = newest((r) => lineOf(parseVersion(r.version).nums, 2) === line)
  if (top && compareVersions(top, installedText) === 1) {
    return [{ key: `go:${line}:patch`, runtime: 'go', reason: 'patch', installed: installedText, line, target: top }]
  }
  return []
}

/**
 * Java (Azul Zulu): behind when Azul's newest GA build for the same major is newer.
 * Compares feature.interim.update.patch; CRaC and JavaFX bundles are ignored.
 * @param {{ installs: Array<{version: string}>, packagesByMajor: Record<string, any[]|null|undefined> }} p
 */
export function evaluateJava({ installs, packagesByMajor }) {
  const items = []
  const done = new Set()
  for (const inst of installs) {
    const iv = parseVersion(inst.version)
    if (iv.unknown) continue
    const major = iv.nums[0]
    const key = `java:${major}:behind`
    if (done.has(key)) continue
    const pkgs = packagesByMajor[String(major)]
    if (!Array.isArray(pkgs)) continue
    const newest = pkgs
      .filter((p) => p && Array.isArray(p.java_version) && !/crac|-fx-|jdk-fx|javafx/i.test(String(p.name || '')))
      .map((p) => p.java_version.map(Number))
      .sort((a, b) => cmpNums(b, a, 4))[0]
    if (!newest) continue
    if (cmpNums(newest, iv.nums, 4) > 0) {
      done.add(key)
      const target = newest.slice(0, newest[3] ? 4 : 3).join('.')
      items.push({ key, runtime: 'java', reason: 'behind', installed: iv.nums.join('.'), target })
    }
  }
  return items
}

/**
 * Merge per-runtime results. A runtime whose feed could not be read keeps its last
 * known items, so an outage never reads as "fixed".
 * @param {Record<string, {readable: boolean, items?: any[]}>} subs
 * @param {Record<string, any[]>} [last]
 */
export function mergeSubResults(subs, last = {}) {
  const items = []
  const nextLast = { ...last }
  const unreadable = []
  for (const [name, r] of Object.entries(subs)) {
    if (r && r.readable) {
      nextLast[name] = r.items ?? []
      items.push(...(r.items ?? []))
    } else {
      unreadable.push(name)
      items.push(...(last[name] ?? []))
    }
  }
  const all = Object.keys(subs).length
  return { items, last: nextLast, unreadable, allUnreadable: all > 0 && unreadable.length === all }
}

/**
 * Grace clocks for items keyed by `key`. A clock starts the first run an item is
 * seen (or at the item's own `since`, when earlier) and is dropped when the item
 * goes away. `noGrace` items are active at once.
 * @param {{ items: any[], clocks?: Record<string, {since: number}>, now: number, graceMs: number, ignoreGrace?: boolean }} p
 */
export function applyClock({ items, clocks = {}, now, graceMs, ignoreGrace = false }) {
  /** @type {Record<string, {since: number}>} */
  const next = {}
  const active = []
  const pending = []
  for (const it of items) {
    let since = clocks[it.key]?.since ?? now
    if (typeof it.since === 'number' && it.since < since) since = it.since
    next[it.key] = { since }
    const item = { ...it, since }
    if (it.noGrace || ignoreGrace || now - since > graceMs) active.push(item)
    else pending.push(item)
  }
  return { active, pending, clocks: next }
}

// ---------------------------------------------------------------------------
// Windows: updates, Defender, firewall
// ---------------------------------------------------------------------------

/** A Windows Update entry that is a security fix: has an MSRC severity or the Security Updates category. */
export function isSecurityUpdate(u) {
  if (!u) return false
  if (typeof u.severity === 'string' && u.severity.trim()) return true
  return Array.isArray(u.categories) && u.categories.some((c) => /^security updates$/i.test(String(c).trim()))
}

function updateKey(u) {
  const kbs = (Array.isArray(u.kb) ? u.kb : []).map(String).filter(Boolean)
  return kbs.length ? kbs.map((k) => `KB${k}`).join('+') : String(u.title || '').slice(0, 120)
}

/** "2025-03 Cumulative Update for Windows 11 Version 24H2 (KB5000001)" without the KB tail. */
function shortUpdateTitle(u) {
  return String(u.title || 'Update')
    .replace(/\s*\((KB\d+)\)\s*$/i, '')
    .replace(/\s+/g, ' ')
    .slice(0, 90)
}

/**
 * Security updates released more than `graceDays` ago and still not installed. The
 * clock starts at the earlier of the release date and the first run that saw it,
 * so a re-released update does not restart it.
 * @param {{ updates: any[], firstSeen?: Record<string, number>, now: number, graceDays?: number, ignoreGrace?: boolean }} p
 */
export function evaluateWindowsUpdates({ updates, firstSeen = {}, now, graceDays = DEFAULTS.windowsGraceDays, ignoreGrace = false }) {
  const active = []
  const pending = []
  /** @type {Record<string, number>} */
  const nextSeen = {}
  for (const u of (Array.isArray(updates) ? updates : []).filter(isSecurityUpdate)) {
    const key = updateKey(u)
    const seen = typeof firstSeen[key] === 'number' ? firstSeen[key] : now
    nextSeen[key] = seen
    const released = Date.parse(u.released)
    const start = Number.isFinite(released) ? Math.min(released, seen) : seen
    const kb = (Array.isArray(u.kb) ? u.kb : []).map((k) => `KB${k}`).join(', ')
    const item = { key, title: shortUpdateTitle(u), kb, severity: String(u.severity || '').trim(), since: start }
    if (ignoreGrace || now - start > graceDays * DAY) active.push(item)
    else pending.push(item)
  }
  return { active, pending, securityPending: active.length + pending.length > 0, firstSeen: nextSeen }
}

/**
 * Defender problems: service or antivirus off, real-time protection off, or
 * definitions older than `maxDays`. Passive mode (another antivirus is in charge)
 * skips the on/off items.
 * @param {any} st
 * @param {number} now
 * @param {number} [maxDays]
 */
export function evaluateDefender(st, now, maxDays = DEFAULTS.defenderSignatureMaxDays) {
  const items = []
  const notes = []
  const mode = String(st.runningMode || '')
  const passive = /passive|edr block/i.test(mode)
  if (passive) notes.push(`Defender is in ${mode.toLowerCase()} (another antivirus is in charge)`)
  else {
    if (st.amServiceEnabled === false) items.push({ key: 'service-off', text: 'The Defender service is not running.' })
    if (st.antivirusEnabled === false) items.push({ key: 'antivirus-off', text: 'Antivirus is turned off.' })
    if (st.realTimeProtectionEnabled === false) items.push({ key: 'realtime-off', text: 'Real-time protection is off.' })
  }
  let ageDays = null
  const updated = Date.parse(st.signatureLastUpdated)
  if (Number.isFinite(updated)) ageDays = Math.floor((now - updated) / DAY)
  else if (typeof st.signatureAgeDays === 'number' && st.signatureAgeDays >= 0) ageDays = st.signatureAgeDays
  if (!passive && ageDays !== null && ageDays > maxDays) {
    items.push({ key: 'signatures-old', text: `Virus definitions are ${ageDays} days old.`, ageDays })
  }
  return { items, notes, ageDays }
}

/**
 * Firewall profiles that are off.
 * @param {Array<{name: string, enabled: unknown}>} profiles
 */
export function evaluateFirewall(profiles) {
  return (Array.isArray(profiles) ? profiles : [])
    .filter((p) => p && !/^(true|1)$/i.test(String(p.enabled)))
    .map((p) => ({ key: String(p.name).toLowerCase(), name: String(p.name) }))
}

// ---------------------------------------------------------------------------
// WSL
// ---------------------------------------------------------------------------

/**
 * Parse `wsl.exe -l -v` (run with WSL_UTF8=1). NUL bytes from a UTF-16 read are dropped.
 * @param {string} text
 * @returns {Array<{name: string, state: string, version: string, isDefault: boolean}>}
 */
export function parseWslList(text) {
  const out = []
  for (const line of cleanConsoleLines(String(text ?? '').replace(/\u0000/g, ''))) {
    const t = line.trim()
    if (!t || /^NAME\s+STATE/i.test(t.replace(/^\*\s*/, ''))) continue
    const isDefault = t.startsWith('*')
    const parts = t.replace(/^\*\s*/, '').split(/\s+/)
    if (parts.length < 3 || !/^\d+$/.test(parts[parts.length - 1])) continue
    out.push({ name: parts[0], state: parts[1], version: parts[parts.length - 1], isDefault })
  }
  return out
}

/**
 * Which WSL distros to check this run. A distro that is not running is left alone
 * unless `startStopped` is set: starting one boots its systemd units and [boot]
 * command, and apt-daily-upgrade could start installing packages. Distros matching
 * `skip` (docker-desktop) are ignored; a distro checked within `intervalMs` is not due.
 * @param {{ distros: Array<{name: string, state: string}>, skip?: RegExp[], startStopped?: boolean, lastCheck?: Record<string, number>, now: number, intervalMs: number }} p
 * @returns {Array<{name: string, action: 'check'|'not-due'|'not-running'}>}
 */
export function planWslChecks({ distros, skip = [], startStopped = false, lastCheck = {}, now, intervalMs }) {
  /** @type {Array<{name: string, action: 'check'|'not-due'|'not-running'}>} */
  const out = []
  for (const d of distros) {
    if (skip.some((re) => re.test(d.name))) continue
    const last = lastCheck[d.name]
    if (typeof last === 'number' && now - last < intervalMs) out.push({ name: d.name, action: 'not-due' })
    else if (!startStopped && !/^running$/i.test(d.state)) out.push({ name: d.name, action: 'not-running' })
    else out.push({ name: d.name, action: 'check' })
  }
  return out
}

/**
 * Count pending upgrades from a `-security` pocket in `apt-get -s` output. The
 * scanner's shell wrapper adds NETHERSEC_* marker lines.
 * @param {string} text
 */
export function parseAptSimulation(text) {
  const lines = String(text ?? '').split(/\r?\n/)
  if (lines.some((l) => l.trim() === 'NETHERSEC_NOAPT')) return { noApt: true, count: 0, packages: [], upgrades: 0, updateOk: true, simOk: true }
  const packages = []
  let upgrades = 0
  for (const l of lines) {
    const m = /^Inst (\S+) (?:\[[^\]]*\] )?\(([^)]*)\)/.exec(l)
    if (!m) continue
    upgrades++
    if (/-security\b/.test(m[2])) packages.push(m[1])
  }
  const updateRc = /NETHERSEC_UPDATE_RC=(\d+)/.exec(text)
  const simRc = /NETHERSEC_SIM_RC=(\d+)/.exec(text)
  return {
    noApt: false,
    count: packages.length,
    packages,
    upgrades,
    updateOk: !!updateRc && updateRc[1] === '0',
    simOk: !!simRc && simRc[1] === '0',
  }
}

/**
 * WSL security updates, checked at most once a day per distro. A distro alerts once
 * its count has been non-zero on `streakNeeded` daily checks in a row. `results`
 * holds this run's reads: `{ name, skipped: true }` when the check was not due, or
 * `{ name, ok: false }` when it could not read (both keep the last known state).
 * @param {{ results: any[], wslState?: Record<string, any>, now: number, ignoreGrace?: boolean, streakNeeded?: number }} p
 */
export function evaluateWsl({ results, wslState = {}, now, ignoreGrace = false, streakNeeded = DEFAULTS.wslStreak }) {
  /** @type {Record<string, any>} */
  const next = {}
  const active = []
  const pending = []
  const errors = []
  for (const r of results) {
    const prev = wslState[r.name] ?? { count: 0, streak: 0, packages: [] }
    let cur = prev
    if (r.skipped) cur = prev
    else if (!r.ok) {
      errors.push(`${r.name}: ${r.error ?? 'could not read'}`)
    } else if (r.noApt) cur = { count: 0, streak: 0, packages: [], checkedAt: now, noApt: true }
    else if (r.count > 0) cur = { count: r.count, streak: (prev.streak ?? 0) + 1, packages: r.packages.slice(0, 10), checkedAt: now }
    else if (!r.updateOk) {
      // Zero on package lists that did not refresh proves nothing.
      errors.push(`${r.name}: apt could not refresh its package lists`)
    } else cur = { count: 0, streak: 0, packages: [], checkedAt: now }
    next[r.name] = cur
    if (cur.count > 0) {
      const item = { key: `wsl:${r.name}`, name: r.name, count: cur.count, packages: cur.packages ?? [] }
      if (ignoreGrace || (cur.streak ?? 0) >= streakNeeded) active.push(item)
      else pending.push(item)
    }
  }
  return { active, pending, wslState: next, errors, readable: errors.length === 0 }
}

// ---------------------------------------------------------------------------
// Exploited flaws (CISA KEV)
// ---------------------------------------------------------------------------

/** Does a KEV entry match one matcher? Both given patterns must match. */
export function kevMatches(vuln, matcher) {
  if (!vuln || !matcher) return false
  const vendor = String(vuln.vendorProject ?? '').trim()
  const product = String(vuln.product ?? '').trim()
  if (matcher.vendor && !matcher.vendor.test(vendor)) return false
  if (matcher.product && !matcher.product.test(product)) return false
  return !!(matcher.vendor || matcher.product)
}

/** A Microsoft KEV entry for a part of Windows (fixed through Windows Update). */
export function isWindowsKev(vuln) {
  return /^microsoft$/i.test(String(vuln?.vendorProject ?? '').trim()) && WINDOWS_KEV_PRODUCTS.test(String(vuln?.product ?? '').trim())
}

/**
 * Match the CISA Known Exploited Vulnerabilities catalog against what is installed.
 *
 * First run: every entry is recorded as seen; only entries added in the last
 * `lookbackDays` that match something installed become findings. Later runs: any
 * entry not seen before that matches. A watch entry added later (or fixed after a
 * bad pattern skipped it) gets the same look-back for itself. Windows entries map to
 * the Windows check: with no security update waiting they are treated as already
 * fixed; with one waiting they are a finding; with Windows Update unreadable or
 * only partly read they wait. App entries wait while the installed list is unreadable.
 *
 * A finding closes only on evidence: for an app, its installed version went up and a
 * good `winget upgrade` read shows no update waiting any more (an app winget does not
 * track has none to wait for), or it was absent on 2 good reads in a row; for
 * Windows, a complete Windows Update read with no security update waiting. A missed
 * winget row never closes one.
 *
 * When an app finding closes, its CVE leaves the seen list and a closed record keeps
 * the fixed version. The next read that can settle it does: the finding reopens if
 * that read finds an older version (or, after a removal, the app back with an update
 * waiting); otherwise the record is dropped and the CVE is seen again. A read that
 * cannot settle it (the app gone, its version or the upgrade list unreadable, its
 * watch entry skipped) keeps the record, for up to KEV_WATCH_DAYS after the fix.
 *
 * A match on a target already on its newest version is a one-time `notice`: reported
 * once, then dropped. Findings of a skipped watch entry (`frozenKeys`) are left
 * untouched.
 *
 * A target is `{ key, label, kev, installed, version, updateAvailable, updateKnown,
 * upgradeReadable, update }`: `installed` is null when `winget list` could not be
 * read, and `upgradeReadable` false when `winget upgrade` could not.
 *
 * @param {{ catalog: any, kevState?: any, targets: any[], frozenKeys?: string[], windows: {readable: boolean, securityPending: boolean, build?: string}, now: number, lookbackDays?: number }} p
 */
export function evaluateKev({ catalog, kevState = {}, targets, frozenKeys = [], windows, now, lookbackDays = DEFAULTS.kevLookbackDays }) {
  const vulns = Array.isArray(catalog?.vulnerabilities) ? catalog.vulnerabilities : []
  const seen = new Set(Array.isArray(kevState.seen) ? kevState.seen : [])
  const firstRun = !kevState.baselined
  const baselinedTargets = new Set(Array.isArray(kevState.targets) ? kevState.targets : [])
  const frozen = new Set(frozenKeys)
  const wasFrozen = new Set(Array.isArray(kevState.frozen) ? kevState.frozen : [])
  const cutoff = now - lookbackDays * DAY
  /** @type {Record<string, any>} */
  const findings = { ...(kevState.findings ?? {}) }
  /** @type {Record<string, {target: string, version: string, at: number}>} */
  const closed = {}
  for (const [cve, c] of Object.entries(kevState.closed ?? {})) {
    if (!c || typeof c.at !== 'number') continue
    // A record no read could settle within KEV_WATCH_DAYS ends quietly: not a new match.
    if (now - c.at < KEV_WATCH_DAYS * DAY) closed[cve] = c
    else seen.add(cve)
  }
  const added = []
  const deferred = []
  const watching = []
  const treatedFixed = []
  const closedNow = []
  const appTargets = targets.filter((t) => Array.isArray(t.kev) && t.kev.length)
  const freshTargets = new Set(
    firstRun ? [] : appTargets.filter((t) => !baselinedTargets.has(t.key) || wasFrozen.has(t.key)).map((t) => t.key),
  )
  if (!firstRun && !baselinedTargets.has('windows')) freshTargets.add('windows')

  const appFinding = (v, t, over = {}) => {
    const actionable = !!t.updateAvailable || !t.updateKnown
    return {
      cve: String(v.cveID),
      target: t.key,
      label: t.label,
      product: `${v.vendorProject} ${String(v.product).trim()}`,
      installed: t.version || '',
      update: t.updateAvailable || '',
      updateKnown: !!t.updateKnown,
      command: t.update || '',
      actionable,
      notice: !actionable,
      added: v.dateAdded,
      ...over,
    }
  }

  for (const v of vulns) {
    const cve = String(v?.cveID ?? '')
    if (!cve) continue
    const isNew = !seen.has(cve)
    const addedAt = Date.parse(v.dateAdded)
    const recent = Number.isFinite(addedAt) && addedAt >= cutoff
    if (isNew && firstRun && !recent) {
      seen.add(cve)
      continue
    }
    if (!isNew && !(recent && freshTargets.size)) continue

    // A CVE whose finding closed earlier: the first read that can settle it reopens it
    // if the vulnerable state is back, or else drops the record. Until then it waits.
    const was = isNew ? closed[cve] : undefined
    if (was) {
      const t = appTargets.find((x) => x.key === was.target)
      const settles =
        !!t && t.installed === true && (was.version ? compareVersions(t.version, was.version) !== null : t.upgradeReadable !== false)
      if (frozen.has(was.target) || (t && !settles)) {
        watching.push(cve)
        continue
      }
      if (t) {
        const back = was.version ? compareVersions(t.version, was.version) === -1 : !!t.updateAvailable
        if (back && !findings[cve]) {
          findings[cve] = appFinding(v, t, { actionable: true, notice: false, update: t.updateAvailable || was.version })
          added.push(cve)
        }
      }
      delete closed[cve]
      seen.add(cve)
      continue
    }

    const consider = (key) => isNew || freshTargets.has(key)
    let wait = false
    if (isWindowsKev(v) && consider('windows')) {
      if (!windows.readable) wait = true
      else if (windows.securityPending) {
        if (!findings[cve]) {
          findings[cve] = {
            cve,
            target: 'windows',
            label: 'Windows',
            product: `${v.vendorProject} ${String(v.product).trim()}`,
            installed: windows.build ? `build ${windows.build}` : '',
            update: 'a Windows security update',
            actionable: true,
            added: v.dateAdded,
          }
          added.push(cve)
        }
      } else treatedFixed.push(cve)
    }
    for (const t of appTargets) {
      if (!consider(t.key) || !t.kev.some((m) => kevMatches(v, m))) continue
      if (t.installed === null || t.installed === undefined) {
        wait = true
        continue
      }
      if (!t.installed || findings[cve]) continue
      findings[cve] = appFinding(v, t)
      added.push(cve)
    }
    if (wait) deferred.push(cve)
    else seen.add(cve)
  }

  const close = (cve, f, version) => {
    delete findings[cve]
    seen.delete(cve)
    if (f.target !== 'windows') closed[cve] = { target: f.target, version, at: now }
    closedNow.push(cve)
  }
  for (const [cve, f0] of Object.entries(findings)) {
    const f = { ...f0 }
    if (f.notice) {
      if (f.delivered) delete findings[cve]
      continue
    }
    if (f.target === 'windows') {
      if (windows.readable && !windows.securityPending) close(cve, f, '')
      continue
    }
    if (frozen.has(f.target)) continue
    const t = targets.find((x) => x.key === f.target)
    if (!t) {
      delete findings[cve] // taken off the watch list
      continue
    }
    if (t.installed === null || t.installed === undefined) continue
    if (t.installed === false) {
      f.absent = (f.absent ?? 0) + 1
      if (f.absent >= 2) close(cve, f, '')
      else findings[cve] = f
      continue
    }
    f.absent = 0
    // Only a good winget upgrade read can show that no update waits: until one, the
    // version is left as it was for a read that can decide.
    if (t.upgradeReadable === false) {
      findings[cve] = f
      continue
    }
    const newer = !!f.installed && !!t.version && compareVersions(t.version, f.installed) === 1
    const stillBehind = !!t.updateKnown && !!t.updateAvailable
    if (newer && !stillBehind) {
      close(cve, f, t.version)
      continue
    }
    if (newer) f.installed = t.version
    if (t.updateAvailable) f.update = t.updateAvailable
    findings[cve] = f
  }

  const knownTargets = appTargets.filter((t) => t.installed !== null && t.installed !== undefined).map((t) => t.key)
  const nextTargets = [...new Set([...(firstRun ? [] : [...baselinedTargets]), ...knownTargets, ...(windows.readable ? ['windows'] : [])])]
  return {
    findings,
    added,
    deferred,
    watching,
    treatedFixed,
    closedNow,
    firstRun,
    kevState: {
      baselined: true,
      seen: [...seen].sort(),
      targets: nextTargets.sort(),
      frozen: [...frozen].sort(),
      findings,
      closed,
    },
  }
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/**
 * Join as many items as fit in `max` characters, ending with "+N more" when some
 * are left out.
 * @param {string[]} items
 * @param {number} max
 * @param {string} [sep]
 */
export function clampJoin(items, max, sep = '; ') {
  const n = items.length
  for (let k = n; k >= 0; k--) {
    const shown = items.slice(0, k)
    const tail = k < n ? `+${n - k} more` : ''
    const text = [...shown, ...(tail ? [tail] : [])].join(sep)
    if (text.length <= max) return text
  }
  return clampText(`+${n} more`, max)
}

/**
 * Hard limit with a "..." end.
 * @param {string} text
 * @param {number} max
 */
export function clampText(text, max) {
  const s = String(text ?? '')
  if (s.length <= max) return s
  if (max <= 3) return s.slice(0, max)
  return `${s.slice(0, max - 3).replace(/\s+$/, '')}...`
}

/** `prefix + list + suffix` with the list squeezed to keep the whole under `max`. */
function withList(prefix, items, suffix, max) {
  const room = Math.max(20, max - prefix.length - suffix.length)
  return clampText(`${prefix}${clampJoin(items, room)}${suffix}`, max)
}

function plural(n, one, many) {
  return n === 1 ? one : many
}

function utcDate(ms) {
  return new Date(ms).toISOString().slice(0, 10)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

const RUNTIME_SITES = { node: 'nodejs.org/en/download', go: 'go.dev/dl', java: 'azul.com/downloads' }

function runtimeLine(it) {
  if (it.runtime === 'node' && it.reason === 'security') {
    const major = String(it.installed).split('.')[0]
    return `Node ${it.installed} -> ${it.target} (security fix in the ${major}.x line)`
  }
  if (it.runtime === 'node' && it.reason === 'eol') {
    const major = String(it.installed).split('.')[0]
    return `Node ${major} ended support on ${it.eolDate}${it.target ? `, move to Node ${it.target}` : ''}`
  }
  if (it.runtime === 'go' && it.reason === 'unsupported') return `Go ${it.line} is no longer supported, move to Go ${it.target}`
  if (it.runtime === 'go') return `Go ${it.installed} -> ${it.target}`
  if (it.runtime === 'java') return `Java ${it.installed} (Zulu) -> ${it.target}`
  return `${it.runtime} ${it.installed} -> ${it.target}`
}

/** "Waiting over a week" for 7 days, "Waiting over 3 days", or just "Waiting" for 0. */
function waitingFor(days) {
  const d = Number(days)
  if (!Number.isFinite(d) || d <= 0) return 'Waiting'
  if (d === 7) return 'Waiting over a week'
  if (d === 14) return 'Waiting over two weeks'
  return `Waiting over ${d} ${plural(d, 'day', 'days')}`
}

function runtimeTitle(it) {
  const major = String(it.installed).split('.')[0]
  if (it.runtime === 'node' && it.reason === 'eol') return `Node ${major} is no longer supported`
  if (it.runtime === 'go' && it.reason === 'unsupported') return `Go ${it.line} is no longer supported`
  const name = it.runtime === 'node' ? 'Node' : it.runtime === 'go' ? 'Go' : it.runtime === 'java' ? 'Java' : it.runtime
  return `${name} ${it.installed} needs a security update`
}

function kevLine(f) {
  const what = f.installed ? `you have ${f.label} ${f.installed}` : `you have ${f.label}`
  let status
  if (f.target === 'windows') status = 'a Windows security update is waiting'
  else if (f.update) status = `update ${f.update} is available`
  else if (f.notice) status = 'you already have the newest version'
  else status = 'could not check for an update'
  return `${f.cve} (${f.product}): ${what}, ${status}`
}

/**
 * Title and detail for one event. `finding.items` are the active items; `extra`
 * carries notes such as a pending restart or paused updates.
 * @param {string} event
 * @param {{ items: any[], extra?: any }} finding
 * @param {{ titleMax?: number, detailMax?: number }} [opts]
 * @returns {{ title: string, detail: string }}
 */
export function describeActive(event, finding, opts = {}) {
  const titleMax = opts.titleMax ?? DEFAULTS.titleMax
  const max = opts.detailMax ?? DEFAULTS.detailMax
  const items = finding.items
  const n = items.length
  const extra = finding.extra ?? {}
  let title = ''
  let detail = ''
  switch (event) {
    case 'apps-behind': {
      title = n === 1 ? `${items[0].name} needs an update` : `${n} apps need updates`
      const list = items.map((i) => `${i.name} ${i.installed} -> ${i.available}`)
      const how =
        n === 1
          ? `. Update with: ${items[0].update}`
          : `. Update one with: ${items[0].update}, or all with: winget upgrade --all`
      detail = withList('', list, how, max)
      break
    }
    case 'apps-eol': {
      title = n === 1 ? `${items[0].name} is no longer supported` : `${n} unsupported programs are installed`
      const list = items.map((i) => `${i.name} ${i.version}`.trim())
      const notes = items.filter((i) => i.note).map((i) => i.note)
      const how = `. ${plural(n, 'It gets', 'They get')} no security fixes. ${
        notes.length ? notes.join(' ') : `Uninstall ${plural(n, 'it', 'them')} in Settings > Apps if nothing needs ${plural(n, 'it', 'them')}.`
      }`
      detail = withList('', list, how, max)
      break
    }
    case 'windows-updates': {
      title = n === 1 ? 'A Windows security update is not installed' : `${n} Windows security updates are not installed`
      const list = items.map((i) => `${i.title}${i.kb ? ` (${i.kb}${i.severity ? `, ${i.severity}` : ''})` : ''}`)
      let how = '. Install in Settings > Windows Update, then restart.'
      if (extra.rebootPending) how += ' A restart is already waiting to finish installing updates.'
      if (extra.pausedUntil) how += ` Updates are paused until ${extra.pausedUntil}.`
      detail = withList(`${waitingFor(extra.graceDays ?? DEFAULTS.windowsGraceDays)}: `, list, how, max)
      break
    }
    case 'defender': {
      const keys = new Set(items.map((i) => i.key))
      if (keys.has('service-off') || keys.has('antivirus-off')) title = 'Defender antivirus is off'
      else if (keys.has('realtime-off')) title = 'Defender real-time protection is off'
      else title = 'Defender virus definitions are out of date'
      const how = keys.has('signatures-old') && keys.size === 1
        ? ' Open Windows Security > Virus & threat protection and check for updates.'
        : ' Turn it on in Windows Security > Virus & threat protection.'
      detail = clampText(items.map((i) => i.text).join(' ') + how, max)
      break
    }
    case 'firewall': {
      title = 'Windows Firewall is off'
      detail = clampText(
        `Off for: ${items.map((i) => i.name).join(', ')} ${plural(n, 'network', 'networks')}. Turn it on in Windows Security > Firewall & network protection.`,
        max,
      )
      break
    }
    case 'runtimes': {
      title = n === 1 ? runtimeTitle(items[0]) : `${n} runtimes need security updates`
      const sites = [...new Set(items.map((i) => RUNTIME_SITES[i.runtime]).filter(Boolean))]
      detail = withList('', items.map(runtimeLine), `. Download from: ${sites.join(', ')}`, max)
      break
    }
    case 'wsl-updates': {
      title = n === 1 ? `${items[0].name} (WSL) has security updates waiting` : `${n} WSL systems have security updates waiting`
      const list = items.map((i) => {
        const pk = i.packages.length ? ` (${clampJoin(i.packages, 80, ', ')})` : ''
        return `${i.name}: ${i.count} security ${plural(i.count, 'update', 'updates')}${pk}`
      })
      detail = withList('', list, `. Update with: wsl -d ${items[0].name} -u root -- apt-get upgrade`, max)
      break
    }
    case 'exploited': {
      const labels = [...new Set(items.map((f) => f.label))]
      title = labels.length === 1 ? `Exploited flaw in ${labels[0]}` : `Exploited flaws in ${labels.length} programs you have`
      if (items.length > 1 && labels.length === 1) title = `Exploited flaws in ${labels[0]}`
      const act = items.find((f) => f.actionable)
      let how = ' Attackers are using these flaws now.'
      if (act && act.target === 'windows') how += ' Install updates in Settings > Windows Update and restart.'
      else if (act && act.command) how += ` Update now: ${act.command}`
      else if (act) how += ' Update it now.'
      else how += ' Check the vendor notice to confirm your version has the fix.'
      detail = withList('', items.map(kevLine), `.${how}`, max)
      break
    }
    case 'monitor-unreadable': {
      title = 'Some PC security checks cannot run'
      const list = items.map((i) => `${CHECK_LABELS[i.key] ?? i.key}${i.error ? ` (${clampText(i.error, 80)})` : ''}`)
      const days = extra.days ?? DEFAULTS.unreadableAlertDays
      detail = withList(
        `Not readable for over ${days} ${plural(days, 'day', 'days')}: `,
        list,
        '. The other checks still run. See last-run.json in the .nethersec-pc folder.',
        max,
      )
      break
    }
    default:
      title = event
      detail = ''
  }
  return { title: clampText(title, titleMax), detail: clampText(detail, max) }
}

/** Title and detail for a cleared event. */
export function describeResolved(event) {
  const map = {
    exploited: ['Exploited flaw fixed', 'The programs in the exploited-flaw alert are updated or removed.'],
    'windows-updates': ['Windows security updates installed', 'No security update is waiting.'],
    defender: ['Defender is back to normal', 'Protection is on and the virus definitions are current.'],
    firewall: ['Windows Firewall is on', 'The firewall is on for every network.'],
    runtimes: ['Runtimes are up to date', 'Node, Go and Java have their security fixes.'],
    'apps-behind': ['Watched apps are up to date', 'No watched app is behind any more.'],
    'apps-eol': ['Unsupported programs removed', 'No end-of-life program from the list is installed any more.'],
    'wsl-updates': ['WSL security updates installed', 'No WSL system has a security update waiting.'],
    'monitor-unreadable': ['PC security checks work again', 'Every check could read again.'],
  }
  const [title, detail] = map[event] ?? [`${event} cleared`, '']
  return { title, detail }
}

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------

const SEVERITY_RANK = { info: 0, warning: 1, critical: 2 }

/**
 * Decide what to send for one event.
 *  - finding null: the check could not read, change nothing.
 *  - active, last sent was not active: trigger (new).
 *  - active, an item the last report did not have, or a higher severity: trigger (changed).
 *  - active, unchanged, last report a week old or more: trigger (reminder).
 *  - inactive, last sent active: resolve (or a quiet clear when `finding.quiet`).
 * A shrinking item list sends nothing; `shrink` asks the caller to forget the
 * removed items so one that comes back counts as new again.
 * @param {any} ev  stored event state: { sent, sentItems, sentSeverity, sentAt }
 * @param {null | { active: boolean, items?: any[], severity?: string, quiet?: boolean }} finding
 * @param {number} now
 * @param {{ reminderDays?: number }} [opts]
 * @returns {{ action: 'none'|'trigger'|'resolve'|'quiet-clear', reason: string, added?: string[], shrink?: string[] }}
 */
export function decideReport(ev, finding, now, opts = {}) {
  const reminderMs = (opts.reminderDays ?? DEFAULTS.reminderDays) * DAY
  if (!finding) return { action: 'none', reason: 'unreadable' }
  const state = ev && typeof ev === 'object' ? ev : {}
  const wasActive = state.sent === 'active'
  if (finding.active) {
    const keys = (finding.items ?? []).map((i) => String(i.key))
    if (!wasActive) return { action: 'trigger', reason: 'new' }
    const prev = new Set(Array.isArray(state.sentItems) ? state.sentItems : [])
    const added = keys.filter((k) => !prev.has(k))
    const sevUp = (SEVERITY_RANK[finding.severity ?? 'warning'] ?? 1) > (SEVERITY_RANK[state.sentSeverity ?? 'warning'] ?? 1)
    if (added.length || sevUp) return { action: 'trigger', reason: 'changed', added }
    if (now - (state.sentAt ?? 0) >= reminderMs) return { action: 'trigger', reason: 'reminder' }
    const shrink = keys.length < prev.size ? keys : undefined
    return { action: 'none', reason: 'unchanged', ...(shrink ? { shrink } : {}) }
  }
  if (wasActive) return finding.quiet ? { action: 'quiet-clear', reason: 'cleared' } : { action: 'resolve', reason: 'cleared' }
  return { action: 'none', reason: 'ok' }
}

/**
 * The event state after a report was delivered (2xx) or a quiet clear.
 * @param {any} ev
 * @param {{ action: string }} decision
 * @param {any} finding
 * @param {number} now
 */
export function recordDelivered(ev, decision, finding, now) {
  if (decision.action === 'trigger') {
    return {
      ...ev,
      sent: 'active',
      sentItems: (finding.items ?? []).map((i) => String(i.key)),
      sentSeverity: finding.severity ?? 'warning',
      sentAt: now,
      sentActionable: !!finding.actionable,
    }
  }
  if (decision.action === 'resolve' || decision.action === 'quiet-clear') {
    return { sent: 'ok', sentAt: now }
  }
  return ev
}

/**
 * Order the reports of one run and cap them: new and changed triggers first (by
 * event priority), then resolves, then reminders. The rest wait for the next run.
 * @param {Array<{event: string, decision: {action: string, reason: string}}>} list
 * @param {number} max
 */
export function planReports(list, max = DEFAULTS.maxPostsPerRun) {
  const rank = (x) => {
    if (x.decision.action === 'trigger' && x.decision.reason !== 'reminder') return 0
    if (x.decision.action === 'resolve') return 1
    return 2
  }
  const sendable = list.filter((x) => x.decision.action === 'trigger' || x.decision.action === 'resolve')
  sendable.sort((a, b) => rank(a) - rank(b) || EVENTS.indexOf(a.event) - EVENTS.indexOf(b.event))
  return { send: sendable.slice(0, Math.max(0, max)), deferred: sendable.slice(Math.max(0, max)) }
}

/**
 * Track per-check readability. Returns the updated map and the monitor-unreadable
 * items (checks unreadable for longer than `days`). Only checks that ran this time
 * are kept, so turning a failing check off also ends its cannot-read alert.
 * @param {Record<string, any>} checks
 * @param {Record<string, {readable: boolean, error?: string}>} results
 * @param {number} now
 * @param {number} [days]
 */
export function trackReadability(checks, results, now, days = DEFAULTS.unreadableAlertDays) {
  const before = checks ?? {}
  /** @type {Record<string, any>} */
  const next = {}
  for (const [id, r] of Object.entries(results)) {
    const prev = before[id] ?? {}
    if (r.readable) next[id] = { lastOk: now, failSince: null }
    else next[id] = { ...prev, failSince: prev.failSince ?? now, lastError: r.error ?? 'could not read' }
  }
  const items = Object.entries(next)
    .filter(([, c]) => typeof c.failSince === 'number' && now - c.failSince > days * DAY)
    .map(([key, c]) => ({ key, error: c.lastError ?? '' }))
    .sort((a, b) => a.key.localeCompare(b.key))
  return { checks: next, items }
}

/**
 * How long one probe may run: its own limit, cut to what is left of the run's
 * budget. 0 means "out of time": with under 3 seconds left the probe is skipped
 * and its check counts as unreadable for this run.
 * @param {number} timeoutMs
 * @param {number} deadline
 * @param {number} now
 */
export function probeTimeout(timeoutMs, deadline, now) {
  const limit = Math.min(timeoutMs, deadline - now)
  return limit >= 3000 ? limit : 0
}

/**
 * After the clock jumped back (or a bad clock wrote the state), any stored time
 * later than now becomes now, so no clock or reminder is stuck in the future.
 * Only numbers in the millisecond-timestamp range are touched (counts are not).
 * @template T
 * @param {T} value
 * @param {number} now
 * @returns {T}
 */
export function clampFutureTimes(value, now) {
  if (Array.isArray(value)) return /** @type {any} */ (value.map((v) => clampFutureTimes(v, now)))
  if (value && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {}
    for (const [k, v] of Object.entries(value)) out[k] = clampFutureTimes(v, now)
    return /** @type {any} */ (out)
  }
  if (typeof value === 'number' && value > now && value >= 1e12 && value < 1e14) return /** @type {any} */ (now)
  return value
}

// ---------------------------------------------------------------------------
// Delivery: the hub (POST /v1/report) or a Discord webhook
// ---------------------------------------------------------------------------

/**
 * Is this host a loopback or private address (a LAN, a VPN or a tailnet)? Only an IP
 * literal or "localhost" counts: a name could resolve anywhere.
 * @param {string} hostname  as `URL.hostname` gives it (IPv6 in brackets)
 */
export function isPrivateHost(hostname) {
  const h = String(hostname ?? '').replace(/^\[|\]$/g, '').toLowerCase()
  if (h === 'localhost' || h === '::1') return true
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    if (v4.slice(1).some((n) => Number(n) > 255)) return false
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)
  }
  return /^f[cd][0-9a-f]{2}:/.test(h) // fc00::/7, IPv6 unique local
}

/**
 * The report endpoint for a hub address: `<hubUrl>/v1/report`. A URL that already
 * ends in /v1/report is taken as it is. Throws on a URL that cannot be used.
 * @param {string} hubUrl
 * @returns {URL}
 */
export function hubReportUrl(hubUrl) {
  const u = new URL(String(hubUrl ?? '').trim())
  if (u.username || u.password) throw new Error('has a user name or password in it')
  const base = u.pathname.replace(/\/+$/, '').replace(/\/v1\/report$/, '')
  u.pathname = `${base}/v1/report`
  u.search = ''
  u.hash = ''
  return u
}

const DISCORD_HOSTS = /^(discord\.com|discordapp\.com|ptb\.discord\.com|canary\.discord\.com)$/

/**
 * Is this a Discord webhook URL (https://discord.com/api/webhooks/<id>/<token>)?
 * @param {unknown} url
 */
export function isDiscordWebhookUrl(url) {
  try {
    const u = new URL(String(url ?? '').trim())
    return (
      u.protocol === 'https:' &&
      DISCORD_HOSTS.test(u.hostname) &&
      !u.port &&
      !u.username &&
      !u.password &&
      /^\/api(\/v\d+)?\/webhooks\/\d{5,25}\/[A-Za-z0-9_-]{20,200}\/?$/.test(u.pathname)
    )
  } catch {
    return false
  }
}

/**
 * The delivery mode config.json asks for: "hub" (also when unset), "webhook", or
 * whatever else was written there (checkDelivery refuses it).
 * @param {any} cfg
 */
export function deliveryMode(cfg) {
  return cfg?.delivery === undefined || cfg?.delivery === '' ? 'hub' : String(cfg.delivery)
}

/**
 * Check the delivery settings. `ok` is true when a report can go out; otherwise
 * `problem` says why in a line that never contains the key or the webhook URL.
 * A value that is set but wrong is also returned in `errors`.
 *
 * `secret` is what the run read for this mode: `value` (the key or the webhook URL)
 * and `from` (the file it came from), or `error` (a problem a person has to fix, such
 * as a secret.dpapi that does not decrypt) or `problem` (one that may pass by itself).
 * @param {any} cfg  config.json's settings; they hold no key or URL
 * @param {{ value?: string, from?: string, error?: string, problem?: string }} [secret]
 * @returns {{ mode: string, ok: boolean, problem: string, errors: string[] }}
 */
export function checkDelivery(cfg, secret = {}) {
  const mode = deliveryMode(cfg)
  const from = secret.from || 'secret.dpapi'
  const errors = []
  let problem = ''
  const bad = (text) => {
    errors.push(`${text} (nothing is sent until it is fixed)`)
    if (!problem) problem = text
  }
  if (!SOURCE_RE.test(String(cfg?.source ?? ''))) bad('source must be 1 to 40 lowercase letters, digits or dashes')
  if (mode === 'hub') {
    const url = String(cfg?.hubUrl ?? '').trim()
    if (!url) problem ||= 'hubUrl is not set in config.json'
    else {
      try {
        const u = hubReportUrl(url)
        const plainOk = u.protocol === 'http:' && (isPrivateHost(u.hostname) || cfg?.allowHttp === true)
        if (u.protocol !== 'https:' && !plainOk) bad('hubUrl must start with https:// (or http:// to a private address)')
      } catch (e) {
        bad(`hubUrl is not a usable URL${e instanceof Error && /user name/.test(e.message) ? ': it has a user name or password in it' : ''}`)
      }
    }
    const key = String(secret.value ?? '')
    if (secret.error) bad(secret.error)
    else if (secret.problem) problem ||= secret.problem
    else if (!key) problem ||= 'no key yet (run install.ps1 -NewKey)'
    else if (!KEY_RE.test(key)) bad(`the key in ${from} is not 64 lowercase hex characters (run install.ps1 -NewKey)`)
  } else if (mode === 'webhook') {
    const url = String(secret.value ?? '').trim()
    if (secret.error) bad(secret.error)
    else if (secret.problem) problem ||= secret.problem
    else if (!url) problem ||= 'no webhook URL yet (run install.ps1 -Webhook)'
    else if (!isDiscordWebhookUrl(url)) bad(`the webhook URL in ${from} is not a Discord webhook URL (https://discord.com/api/webhooks/...)`)
  } else {
    bad('delivery must be "hub" or "webhook"')
  }
  return { mode, ok: !problem, problem, errors }
}

/**
 * Text for a Discord embed: control characters dropped and markdown escaped, so a
 * name from the PC cannot format the message or hide a link.
 * @param {unknown} text
 */
export function discordText(text) {
  return String(text ?? '')
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '')
    .replace(/([\\*_~`|<>[\]])/g, '\\$1')
    .replace(/^([#-])/gm, '\\$1')
}

const DISCORD_COLORS = { critical: 0xd32f2f, warning: 0xf57c00, info: 0x1976d2, resolved: 0x388e3c }

/**
 * The Discord webhook body for one report: one embed, and no mention can ping.
 * @param {{ source: string, event: string, state: string, severity?: string, title: string, detail: string }} body
 */
export function discordPayload(body) {
  const resolved = body.state === 'resolved'
  const level = resolved ? 'resolved' : body.severity || 'warning'
  return {
    allowed_mentions: { parse: [] },
    embeds: [
      {
        title: clampText(discordText(String(body.title ?? '').replace(/[\x00-\x1f\x7f]/g, '')), 256),
        description: clampText(discordText(body.detail), 4000),
        color: DISCORD_COLORS[level] ?? DISCORD_COLORS.warning,
        footer: { text: `${body.source} ${body.event} ${level}` },
      },
    ],
  }
}

/**
 * The HTTP request for one report. Holds the key or webhook URL, so the result
 * must never be logged.
 * @param {any} cfg  a config that passed checkDelivery
 * @param {string} secret  the key (hub) or the webhook URL (webhook) that passed it too
 * @param {any} body  a report from buildReport
 * @returns {{ mode: string, url: string, headers: Record<string, string>, body: string }}
 */
export function deliveryRequest(cfg, secret, body) {
  if (cfg.delivery === 'webhook') {
    return { mode: 'webhook', url: String(secret).trim(), headers: { 'content-type': 'application/json' }, body: JSON.stringify(discordPayload(body)) }
  }
  return {
    mode: 'hub',
    url: hubReportUrl(cfg.hubUrl).href,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}` },
    body: JSON.stringify(body),
  }
}

/**
 * What an HTTP status means for this report and the rest of the run. Only a 2xx
 * counts as sent. `stop` is set when the other reports of this run would fail the
 * same way (bad key, rate limit, target down); they then wait for the next run.
 * @param {number} status
 * @param {string} mode  'hub' or 'webhook'
 * @returns {{ sent: boolean, stop: string }}
 */
export function responseOutcome(status, mode) {
  if (status >= 200 && status < 300) return { sent: true, stop: '' }
  const hub = mode !== 'webhook'
  if (status === 429) return { sent: false, stop: `${hub ? 'the hub' : 'Discord'} asked to slow down` }
  if (status === 401) return { sent: false, stop: hub ? 'the hub did not accept the key' : 'Discord did not accept the webhook URL' }
  if (status === 403) return { sent: false, stop: hub ? 'the hub refused this key for this source' : 'Discord refused the webhook' }
  if (status === 404) return { sent: false, stop: hub ? 'no report endpoint at hubUrl' : 'the webhook no longer exists (make a new one, then run install.ps1 -Webhook)' }
  if (status >= 500) return { sent: false, stop: `${hub ? 'the hub' : 'Discord'} could not deliver it now` }
  return { sent: false, stop: '' }
}

/**
 * Check config.json values that could break a run or send somewhere unsafe: the
 * delivery settings (see checkDelivery; nothing is sent until they are right), and
 * each `wsl.skip` pattern must compile (the WSL check does not run otherwise, so a
 * distro meant to be skipped is never touched).
 * @param {any} cfg
 * @param {Parameters<typeof checkDelivery>[1]} [secret]  as checkDelivery takes it
 * @returns {{ errors: string[], sendOk: boolean, sendProblem: string, mode: string, wslSkip: RegExp[] | null }}
 */
export function validateConfig(cfg, secret) {
  const delivery = checkDelivery(cfg, secret)
  const errors = [...delivery.errors]
  /** @type {RegExp[] | null} */
  let wslSkip = []
  const skip = cfg?.wsl?.skip
  for (const p of Array.isArray(skip) ? skip : skip ? [skip] : []) {
    try {
      wslSkip.push(new RegExp(String(p), 'i'))
    } catch {
      errors.push(`wsl.skip has a pattern that is not valid: ${String(p).slice(0, 60)} (the WSL check is off until it is fixed)`)
      wslSkip = null
      break
    }
  }
  return { errors, sendOk: delivery.ok, sendProblem: delivery.problem, mode: delivery.mode, wslSkip }
}

/**
 * One report body, as docs/report-protocol.md defines it.
 * @param {{ source: string, event: string, decision: {action: string, reason: string}, finding: any, opts?: any }} p
 */
export function buildReport({ source, event, decision, finding, opts = {} }) {
  if (decision.action === 'resolve') {
    const r = describeResolved(event)
    return { v: 1, kind: 'security', source, event, state: 'resolved', title: r.title, detail: r.detail }
  }
  const d = describeActive(event, finding, opts)
  const title = decision.reason === 'reminder' ? clampText(`Reminder: ${d.title}`, opts.titleMax ?? DEFAULTS.titleMax) : d.title
  return { v: 1, kind: 'security', source, event, state: 'triggered', severity: finding.severity ?? 'warning', title, detail: d.detail }
}
