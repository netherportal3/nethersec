/**
 * Parsing the advisory feeds. PURE: no I/O, no clock.
 *
 *  - rss     an RSS 2.0 feed of bulletins or release news. With `match`, only the
 *            items whose title or a category matches card; the rest are recorded.
 *  - github  a repo's published GitHub security advisories.
 *  - kev     CISA's Known Exploited Vulnerabilities catalog, matched against the
 *            `kev` names of every component. An entry for something listed is
 *            critical (exploited in the wild); the rest are recorded.
 *
 * Every parser returns null when the body is not what it should be (an error page,
 * a moved feed), so a broken read is a failed read, never an empty one.
 */
import { createHash } from 'node:crypto'
import type { KevMatcher, WatchComponent } from './config.js'
import { asArray, asRecord, truncate } from './util.js'

export type AdvisorySeverity = 'critical' | 'high' | 'medium' | 'low'

export interface Advisory {
  id: string
  title: string
  summary: string
  /** https only, else empty. */
  url: string
  /** Epoch ms, or null when the feed did not say. */
  published: number | null
  /** null for a bulletin with no severity. */
  severity: AdvisorySeverity | null
  fixedIn: string | null
  /** Recorded without a card: an RSS item the match skips, or a KEV entry for something not listed. */
  noCard?: boolean
  kev?: KevMatch
}

export interface KevMatch {
  /** The catalog's vendor and product ("Linux Kernel"). */
  listedAs: string
  /** What it matched: the card names each and where it runs. */
  products: Array<{ name: string; runsOn?: string }>
  /** YYYY-MM-DD, as the catalog gives them. */
  dateAdded: string
  dueDate: string
  /** The catalog says it is known to be used in ransomware campaigns. */
  ransomware: boolean
}

/** Something the KEV feed matches: a component with `kev` names. */
export interface KevProduct {
  id: string
  name: string
  runsOn?: string
  kev: KevMatcher[]
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

function safeCodePoint(n: number): string {
  return Number.isInteger(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : ''
}

export function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => safeCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => safeCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
}

/**
 * Text read from one field of a feed item at most (a title, a description).
 * Each field is cut to this before any pattern runs on it, so a hostile feed
 * near the size cap costs no more than a normal one.
 */
export const FEED_FIELD_MAX = 20_000

/** A field's text: the inside of a CDATA section as is, else with entities decoded. Cut to FEED_FIELD_MAX. */
function unwrap(inner: string): string {
  const t = inner.trim()
  if (t.length >= 12 && t.startsWith('<![CDATA[') && t.endsWith(']]>')) return t.slice(9, -3).slice(0, FEED_FIELD_MAX)
  return decodeEntities(inner.slice(0, FEED_FIELD_MAX))
}

/**
 * The raw inside of each `<tag ...>...</tag>` in `s`, in order, at most `limit`.
 * It walks forward with one search for the next opening tag and one for its
 * closing tag, and stops at the first tag with no closing tag after it (no later
 * one can have one either), so tags that never close cost one pass, not one
 * pass each.
 */
function tagInners(s: string, tag: string, limit = Infinity): string[] {
  const open = new RegExp(`<${tag}(?:\\s[^<>]*)?>`, 'gi')
  const close = new RegExp(`</${tag}>`, 'gi')
  const out: string[] = []
  let from = 0
  while (out.length < limit) {
    open.lastIndex = from
    const o = open.exec(s)
    if (!o) break
    const start = o.index + o[0].length
    close.lastIndex = start
    const c = close.exec(s)
    if (!c) break
    out.push(s.slice(start, c.index))
    from = close.lastIndex
  }
  return out
}

function tagText(block: string, tag: string): string | null {
  const [inner] = tagInners(block, tag, 1)
  return inner === undefined ? null : unwrap(inner)
}

function tagTexts(block: string, tag: string): string[] {
  return tagInners(block, tag).map(unwrap)
}

/** Tags out, entities decoded, whitespace collapsed. A tag cannot contain `<`, which keeps this one pass over a run of `<`. */
export function plainText(html: string): string {
  return decodeEntities(html.replace(/<[^<>]*>/g, ' ')).replace(/\s+/g, ' ').trim()
}

/**
 * The paragraph that says what happened: one labeled "Description:", else the first
 * long enough to say something (bulletins often open with short "Published: ..."
 * lines), else the first one.
 */
function leadParagraph(html: string): string {
  const paras = tagInners(html, 'p').map(plainText).filter(Boolean)
  return paras.find((p) => /^description\s*:/i.test(p)) || paras.find((p) => p.length >= 40) || paras[0] || plainText(html)
}

const NOT_A_PRODUCT = new Set(['to', 'in', 'is', 'are', 'and', 'or', 'from', 'version', 'versions', 'update', 'upgrade'])

/**
 * "Example 1.4.2" from "Example v1.4.2 or later" or "fixed in Example version 1.2.3 or newer".
 * Every repeat in the pattern is bounded, so a long run of letters, digits or
 * spaces costs one pass, not one pass for each character in it.
 */
export function extractFixedIn(text: string, fallbackName: string): string | null {
  const m = /(?:\b([A-Za-z][\w-]{0,63})\s{1,8})?(?:version\s{1,8})?v?(?<!\d)(\d{1,9}\.\d{1,9}(?:\.\d{1,9})?)\s{1,8}or\s{1,8}(?:newer|later)/i.exec(text.slice(0, FEED_FIELD_MAX))
  if (!m) return null
  const product = m[1] && !NOT_A_PRODUCT.has(m[1].toLowerCase()) ? m[1] : fallbackName
  return `${product} ${m[2]}`
}

// ---------------------------------------------------------------------------
// Feeds
// ---------------------------------------------------------------------------

/** Items of an RSS 2.0 feed, in the feed's order. Null when it is not RSS. */
export function parseRssAdvisories(xml: string, componentName: string, match?: RegExp): Advisory[] | null {
  if (!/<rss[\s>]/i.test(xml) || !/<channel[\s>]/i.test(xml)) return null
  const out: Advisory[] = []
  for (const block of tagInners(xml, 'item')) {
    const title = plainText(tagText(block, 'title') || '')
    const link = (tagText(block, 'link') || '').trim()
    const id = (tagText(block, 'guid') || '').trim() || link || title
    if (!id || !title) continue
    const html = tagText(block, 'description') || ''
    const summary = leadParagraph(html).replace(/^description\s*:\s*/i, '')
    const pub = Date.parse(tagText(block, 'pubDate') || '')
    const categories = tagTexts(block, 'category').map((c) => plainText(c))
    const cards = !match || match.test(title) || categories.some((c) => match.test(c))
    out.push({
      id: id.length <= 200 ? id : `sha256:${createHash('sha256').update(id).digest('hex')}`,
      title: truncate(title, 120),
      summary: truncate(summary || title, 300),
      url: /^https:\/\//.test(link) ? link : '',
      published: Number.isFinite(pub) ? pub : null,
      severity: null,
      fixedIn: extractFixedIn(plainText(html), componentName),
      ...(cards ? {} : { noCard: true }),
    })
  }
  return out
}

/** A repo's published GitHub advisories (GET /repos/{repo}/security-advisories). Null when it is not a list. */
export function parseGithubAdvisories(raw: unknown): Advisory[] | null {
  if (!Array.isArray(raw)) return null
  const out: Advisory[] = []
  for (const a of raw) {
    const r = asRecord(a)
    if (!r) continue
    const id = typeof r.ghsa_id === 'string' ? r.ghsa_id : ''
    if (!id || r.withdrawn_at || (r.state !== undefined && r.state !== 'published')) continue
    const sev = typeof r.severity === 'string' ? r.severity.toLowerCase() : ''
    const fixes = new Set<string>()
    for (const v of asArray(r.vulnerabilities)) {
      const p = asRecord(v)?.patched_versions
      if (typeof p === 'string' && p.trim()) fixes.add(p.trim())
    }
    const pub = Date.parse(typeof r.published_at === 'string' ? r.published_at : '')
    const summary = typeof r.summary === 'string' ? r.summary : ''
    out.push({
      id,
      title: id,
      summary: truncate(summary || id, 300),
      url: typeof r.html_url === 'string' && /^https:\/\//.test(r.html_url) ? r.html_url : '',
      published: Number.isFinite(pub) ? pub : null,
      severity: sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' ? sev : sev === 'moderate' ? 'medium' : null,
      fixedIn: fixes.size > 0 ? truncate([...fixes].join('; '), 200) : null,
    })
  }
  return out
}

const KEV_CVE = /^CVE-\d{4}-\d{4,}$/

/** Whether a KEV entry matches one matcher: every pattern given matches the trimmed field, and there is at least one. */
export function kevMatches(vendorProject: string, product: string, m: KevMatcher): boolean {
  if (!m.vendor && !m.product) return false
  return (!m.vendor || m.vendor.test(vendorProject.trim())) && (!m.product || m.product.test(product.trim()))
}

/** Everything the KEV feed matches: each component with `kev` names. */
export function kevInventory(components: WatchComponent[]): KevProduct[] {
  return components.flatMap((c) => (c.kev?.length ? [{ id: c.id, name: c.name, runsOn: c.runsOn, kev: c.kev }] : []))
}

/** The KEV catalog. An entry for something in `inventory` is critical; the rest are recorded. Null when it is not the catalog. */
export function parseKevCatalog(raw: unknown, inventory: KevProduct[]): Advisory[] | null {
  const catalog = asRecord(raw)
  if (!catalog || !Array.isArray(catalog.vulnerabilities)) return null
  const out: Advisory[] = []
  for (const x of catalog.vulnerabilities) {
    const v = asRecord(x)
    if (!v) continue
    const text = (k: string) => (typeof v[k] === 'string' ? (v[k] as string).replace(/\s+/g, ' ').trim() : '')
    const cve = text('cveID').toUpperCase()
    if (!KEV_CVE.test(cve)) continue
    const vendor = text('vendorProject')
    const product = text('product')
    const hits = inventory.filter((p) => p.kev.some((m) => kevMatches(vendor, product, m)))
    const added = Date.parse(text('dateAdded'))
    out.push({
      id: cve,
      title: cve,
      summary: truncate(text('shortDescription') || text('vulnerabilityName') || cve, 300),
      url: `https://nvd.nist.gov/vuln/detail/${cve}`,
      published: Number.isFinite(added) ? added : null,
      severity: hits.length > 0 ? 'critical' : null,
      fixedIn: null,
      ...(hits.length > 0
        ? {
            kev: {
              listedAs: truncate(`${vendor} ${product}`.trim(), 200),
              products: hits.map((p) => ({ name: p.name, ...(p.runsOn ? { runsOn: p.runsOn } : {}) })),
              dateAdded: text('dateAdded').slice(0, 10),
              dueDate: text('dueDate').slice(0, 10),
              ransomware: /^known$/i.test(text('knownRansomwareCampaignUse')),
            },
          }
        : { noCard: true }),
    })
  }
  return out
}

// ---------------------------------------------------------------------------
// What cards
// ---------------------------------------------------------------------------

/** Whether an advisory gets a card: critical, high, and any bulletin with no severity. */
export function cardsAdvisory(a: Advisory): boolean {
  if (a.noCard) return false
  return a.severity === null || a.severity === 'critical' || a.severity === 'high'
}

/**
 * One group per fix: a component's advisories that name the same fixed version
 * are closed by one update, so they share a card. One with no fixed version stays
 * alone. Groups keep the order of their first advisory.
 */
export function groupAdvisoriesByFix(advisories: Advisory[]): Advisory[][] {
  const groups: Advisory[][] = []
  const byFix = new Map<string, Advisory[]>()
  for (const a of advisories) {
    const fix = a.fixedIn?.trim().toLowerCase()
    const group = fix ? byFix.get(fix) : undefined
    if (group) {
      group.push(a)
      continue
    }
    const created = [a]
    groups.push(created)
    if (fix) byFix.set(fix, created)
  }
  return groups
}
