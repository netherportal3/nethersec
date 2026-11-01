/**
 * watch.json: what the advisory watch reads, whether the container check runs,
 * and when acknowledged advisory cards close. See docs/hub/watch.md for the
 * reference.
 *
 * A missing file means the defaults: no components (so no KEV feed), the kernel
 * feed off, the container check on, acknowledged advisory cards closed after
 * DEFAULT_CLOSE_ACKNOWLEDGED_DAYS. A file that is there but wrong is an error
 * that names every problem, so a typo never silently turns a feed off.
 */
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

/** How the KEV catalog names a component. Each pattern given must match (case-insensitive), and there is at least one. */
export interface KevMatcher {
  vendor?: RegExp
  product?: RegExp
}

export type ComponentFeed =
  | { kind: 'github'; repo: string }
  /** `match` absent: every item cards. Present: an item cards when its title or one of its categories matches. */
  | { kind: 'rss'; url: string; match?: RegExp }
  | { kind: 'kev' }

export interface WatchComponent {
  id: string
  name: string
  /** Where it runs, shown on its cards. */
  runsOn?: string
  /** Absent: the component is watched only through the KEV feed. */
  feed?: ComponentFeed
  kev?: KevMatcher[]
}

/** An Ubuntu release for the kernel feed. */
export interface UbuntuRelease {
  /** The codename Ubuntu's CVE records use ("noble"). */
  codename: string
  /** What the card calls it ("Ubuntu 24.04"). */
  name: string
}

export interface KernelConfig {
  releases: UbuntuRelease[]
  runsOn?: string
}

export interface WatchConfig {
  components: WatchComponent[]
  /** null: the kernel feed is off. */
  kernel: KernelConfig | null
  containers: { enabled: boolean }
  /**
   * An advisory or KEV card a person acknowledged this many days ago closes by
   * itself. 0: never. Kernel, container and "can't read" cards are not touched.
   */
  advisoryCards: { closeAcknowledgedAfterDays: number }
}

/** The default for advisoryCards.closeAcknowledgedAfterDays. */
export const DEFAULT_CLOSE_ACKNOWLEDGED_DAYS = 90
/** The shortest setting other than 0, so a typo cannot close cards the day they are acknowledged. */
export const MIN_CLOSE_ACKNOWLEDGED_DAYS = 7
export const MAX_CLOSE_ACKNOWLEDGED_DAYS = 3650

/** The id the kernel feed's cards and state use. A component cannot take it. */
export const KERNEL_FEED_ID = 'linux-kernel'

/** Ubuntu releases by version. Another release can be given by its codename. */
export const UBUNTU_RELEASES: Record<string, string> = {
  '16.04': 'xenial',
  '18.04': 'bionic',
  '20.04': 'focal',
  '22.04': 'jammy',
  '24.04': 'noble',
  '24.10': 'oracular',
  '25.04': 'plucky',
  '25.10': 'questing',
  '26.04': 'resolute',
}

const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/
const REPO_RE = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/
const CODENAME_RE = /^[a-z]{3,20}$/
const MAX_COMPONENTS = 200
const MAX_MATCHERS = 20
const NAME_MAX = 60
const RUNS_ON_MAX = 500
const PATTERN_MAX = 200
const URL_MAX = 500

export class WatchConfigError extends Error {
  constructor(public errors: string[]) {
    super(`watch.json has ${errors.length === 1 ? 'a problem' : `${errors.length} problems`}:\n${errors.map((e) => `- ${e}`).join('\n')}`)
    this.name = 'WatchConfigError'
  }
}

export function defaultWatchConfig(): WatchConfig {
  return { components: [], kernel: null, containers: { enabled: true }, advisoryCards: { closeAcknowledgedAfterDays: DEFAULT_CLOSE_ACKNOWLEDGED_DAYS } }
}

function isObject(x: unknown): x is Record<string, unknown> {
  return !!x && typeof x === 'object' && !Array.isArray(x)
}

/** Keys that start with `_` are notes and are ignored. Any other unknown key is an error, to catch typos. */
function checkKeys(obj: Record<string, unknown>, allowed: string[], where: string, errors: string[]): void {
  for (const k of Object.keys(obj)) {
    if (k.startsWith('_') || allowed.includes(k)) continue
    errors.push(`${where}: unknown key "${k.slice(0, 40)}" (allowed: ${allowed.join(', ')})`)
  }
}

function optionalText(v: unknown, where: string, max: number, errors: string[]): string | undefined {
  if (v === undefined || v === null) return undefined
  if (typeof v !== 'string') {
    errors.push(`${where}: must be text`)
    return undefined
  }
  const s = v.replace(/\s+/g, ' ').trim()
  if (s.length > max) errors.push(`${where}: at most ${max} characters`)
  return s || undefined
}

function pattern(v: unknown, where: string, errors: string[]): RegExp | undefined {
  if (v === undefined || v === null || v === '') return undefined
  if (typeof v !== 'string') {
    errors.push(`${where}: must be a regular expression, as text`)
    return undefined
  }
  if (v.length > PATTERN_MAX) {
    errors.push(`${where}: at most ${PATTERN_MAX} characters`)
    return undefined
  }
  try {
    // No `g` flag: .test() would remember where it stopped.
    return new RegExp(v, 'i')
  } catch {
    errors.push(`${where}: not a valid regular expression: ${v.slice(0, 60)}`)
    return undefined
  }
}

function parseMatchers(raw: unknown, where: string, errors: string[]): KevMatcher[] | undefined {
  if (raw === undefined || raw === null) return undefined
  if (!Array.isArray(raw)) {
    errors.push(`${where}: must be a list of { "vendor", "product" } patterns`)
    return undefined
  }
  if (raw.length > MAX_MATCHERS) errors.push(`${where}: at most ${MAX_MATCHERS} entries`)
  const out: KevMatcher[] = []
  raw.slice(0, MAX_MATCHERS).forEach((m, i) => {
    const at = `${where}[${i}]`
    if (!isObject(m)) {
      errors.push(`${at}: must be an object with "vendor" and/or "product"`)
      return
    }
    checkKeys(m, ['vendor', 'product'], at, errors)
    const vendor = pattern(m.vendor, `${at}.vendor`, errors)
    const product = pattern(m.product, `${at}.product`, errors)
    if (!vendor && !product) {
      if (m.vendor === undefined && m.product === undefined) errors.push(`${at}: needs "vendor", "product" or both`)
      return
    }
    out.push({ ...(vendor ? { vendor } : {}), ...(product ? { product } : {}) })
  })
  return out
}

function parseFeed(raw: unknown, where: string, errors: string[]): ComponentFeed | undefined {
  if (raw === undefined || raw === null) return undefined
  if (!isObject(raw)) {
    errors.push(`${where}: must be an object with a "kind"`)
    return undefined
  }
  switch (raw.kind) {
    case 'github': {
      checkKeys(raw, ['kind', 'repo'], where, errors)
      if (typeof raw.repo !== 'string' || !REPO_RE.test(raw.repo)) {
        errors.push(`${where}.repo: must be "owner/repo"`)
        return undefined
      }
      return { kind: 'github', repo: raw.repo }
    }
    case 'rss': {
      checkKeys(raw, ['kind', 'url', 'match'], where, errors)
      let url: URL | null = null
      try {
        url = typeof raw.url === 'string' && raw.url.length <= URL_MAX ? new URL(raw.url) : null
      } catch {
        url = null
      }
      if (!url || url.protocol !== 'https:' || url.username || url.password) {
        errors.push(`${where}.url: must be an https:// address of at most ${URL_MAX} characters, with no user or password in it`)
        return undefined
      }
      const match = pattern(raw.match, `${where}.match`, errors)
      return { kind: 'rss', url: url.toString(), ...(match ? { match } : {}) }
    }
    case 'kev':
      checkKeys(raw, ['kind'], where, errors)
      return { kind: 'kev' }
    default:
      errors.push(`${where}.kind: must be "github", "rss" or "kev"`)
      return undefined
  }
}

function parseComponents(raw: unknown, errors: string[]): WatchComponent[] {
  if (raw === undefined || raw === null) return []
  if (!Array.isArray(raw)) {
    errors.push('components: must be a list')
    return []
  }
  if (raw.length > MAX_COMPONENTS) errors.push(`components: at most ${MAX_COMPONENTS} entries`)
  const out: WatchComponent[] = []
  const ids = new Set<string>()
  let kevFeeds = 0
  raw.slice(0, MAX_COMPONENTS).forEach((c, i) => {
    const where = `components[${i}]`
    if (!isObject(c)) {
      errors.push(`${where}: must be an object`)
      return
    }
    const label = typeof c.id === 'string' ? `${where} (${c.id.slice(0, 40)})` : where
    checkKeys(c, ['id', 'name', 'runsOn', 'feed', 'kev'], label, errors)
    const before = errors.length
    const id = typeof c.id === 'string' ? c.id : ''
    if (!ID_RE.test(id)) errors.push(`${label}.id: 1 to 40 lowercase letters, digits or dashes, starting with a letter or digit`)
    else if (id === KERNEL_FEED_ID) errors.push(`${label}.id: "${KERNEL_FEED_ID}" is the kernel feed's; pick another id`)
    else if (ids.has(id)) errors.push(`${label}.id: used twice`)
    ids.add(id)
    const name = optionalText(c.name, `${label}.name`, NAME_MAX, errors)
    if (!name && c.name === undefined) errors.push(`${label}.name: required`)
    else if (!name && typeof c.name === 'string') errors.push(`${label}.name: must not be empty`)
    const runsOn = optionalText(c.runsOn, `${label}.runsOn`, RUNS_ON_MAX, errors)
    const feed = parseFeed(c.feed, `${label}.feed`, errors)
    const kev = parseMatchers(c.kev, `${label}.kev`, errors)
    if (feed?.kind === 'kev') {
      kevFeeds++
      if (c.kev !== undefined) errors.push(`${label}: the KEV feed reads the catalog for every other component; it cannot have "kev" names itself`)
    }
    if (c.feed === undefined && c.kev === undefined) errors.push(`${label}: needs a "feed", "kev" names, or both`)
    else if (c.feed === undefined && kev && kev.length === 0 && Array.isArray(c.kev) && c.kev.length === 0) {
      errors.push(`${label}: has no feed and an empty "kev" list, so nothing watches it`)
    }
    if (errors.length > before || !name) return
    out.push({ id, name, ...(runsOn ? { runsOn } : {}), ...(feed ? { feed } : {}), ...(kev && kev.length ? { kev } : {}) })
  })
  if (kevFeeds > 1) errors.push('components: only one component can have the "kev" feed')
  return out
}

function parseKernel(raw: unknown, errors: string[]): KernelConfig | null {
  if (raw === undefined || raw === null || raw === false) return null
  if (!isObject(raw)) {
    errors.push('kernel: must be an object like { "ubuntu": ["24.04"] }')
    return null
  }
  checkKeys(raw, ['ubuntu', 'runsOn'], 'kernel', errors)
  const known = Object.keys(UBUNTU_RELEASES).join(', ')
  if (!Array.isArray(raw.ubuntu) || raw.ubuntu.length === 0) {
    errors.push(`kernel.ubuntu: must list at least one Ubuntu release (${known}, or a codename)`)
    return null
  }
  const releases: UbuntuRelease[] = []
  raw.ubuntu.forEach((r, i) => {
    const v = typeof r === 'string' ? r.trim() : ''
    const codename = UBUNTU_RELEASES[v] ?? (CODENAME_RE.test(v) ? v : '')
    if (!codename) {
      errors.push(`kernel.ubuntu[${i}]: not an Ubuntu release this knows (${known}, or a lowercase codename)`)
      return
    }
    if (releases.some((x) => x.codename === codename)) return
    const version = Object.entries(UBUNTU_RELEASES).find(([, c]) => c === codename)?.[0]
    releases.push({ codename, name: `Ubuntu ${version ?? codename}` })
  })
  const runsOn = optionalText(raw.runsOn, 'kernel.runsOn', RUNS_ON_MAX, errors)
  return releases.length ? { releases, ...(runsOn ? { runsOn } : {}) } : null
}

function parseContainers(raw: unknown, errors: string[]): { enabled: boolean } {
  if (raw === undefined || raw === null) return { enabled: true }
  if (!isObject(raw)) {
    errors.push('containers: must be an object like { "enabled": true }')
    return { enabled: true }
  }
  checkKeys(raw, ['enabled'], 'containers', errors)
  if (raw.enabled === undefined) return { enabled: true }
  if (typeof raw.enabled !== 'boolean') {
    errors.push('containers.enabled: must be true or false')
    return { enabled: true }
  }
  return { enabled: raw.enabled }
}

function parseAdvisoryCards(raw: unknown, errors: string[]): WatchConfig['advisoryCards'] {
  const def = { closeAcknowledgedAfterDays: DEFAULT_CLOSE_ACKNOWLEDGED_DAYS }
  if (raw === undefined || raw === null) return def
  if (!isObject(raw)) {
    errors.push(`advisoryCards: must be an object like { "closeAcknowledgedAfterDays": ${DEFAULT_CLOSE_ACKNOWLEDGED_DAYS} }`)
    return def
  }
  checkKeys(raw, ['closeAcknowledgedAfterDays'], 'advisoryCards', errors)
  const v = raw.closeAcknowledgedAfterDays
  if (v === undefined) return def
  if (typeof v !== 'number' || !Number.isInteger(v) || (v !== 0 && (v < MIN_CLOSE_ACKNOWLEDGED_DAYS || v > MAX_CLOSE_ACKNOWLEDGED_DAYS))) {
    errors.push(`advisoryCards.closeAcknowledgedAfterDays: must be 0 (never) or a whole number of days from ${MIN_CLOSE_ACKNOWLEDGED_DAYS} to ${MAX_CLOSE_ACKNOWLEDGED_DAYS}`)
    return def
  }
  return { closeAcknowledgedAfterDays: v }
}

/** Checks a parsed watch.json. Throws WatchConfigError naming every problem. */
export function parseWatchConfig(raw: unknown): WatchConfig {
  const errors: string[] = []
  if (!isObject(raw)) throw new WatchConfigError(['the file must hold one JSON object'])
  checkKeys(raw, ['components', 'kernel', 'containers', 'advisoryCards'], 'watch.json', errors)
  const config: WatchConfig = {
    components: parseComponents(raw.components, errors),
    kernel: parseKernel(raw.kernel, errors),
    containers: parseContainers(raw.containers, errors),
    advisoryCards: parseAdvisoryCards(raw.advisoryCards, errors),
  }
  if (errors.length) throw new WatchConfigError(errors)
  return config
}

/**
 * Reads watch.json. `path` is the file, or the data directory that holds it.
 * A missing file gives the defaults; anything else wrong throws WatchConfigError.
 */
export function loadWatchConfig(path: string): WatchConfig {
  let file = path
  try {
    if (statSync(path).isDirectory()) file = join(path, 'watch.json')
  } catch {
    // Not there: read below, which tells a missing file from an unreadable one.
  }
  let text: string
  try {
    text = readFileSync(file, 'utf8')
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === 'ENOENT') return defaultWatchConfig()
    throw new WatchConfigError([`could not read ${file} (${(e as NodeJS.ErrnoException)?.code ?? 'error'})`])
  }
  let raw: unknown
  try {
    raw = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text)
  } catch (e) {
    throw new WatchConfigError([`not valid JSON: ${e instanceof Error ? e.message.slice(0, 200) : 'parse error'}`])
  }
  return parseWatchConfig(raw)
}
