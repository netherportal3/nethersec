/**
 * The kernel feed: a critical Linux kernel bug reachable over the network that
 * Ubuntu has not released a security fix for yet, on a release in watch.json.
 *
 * Why it exists: a box's own update check sees a kernel CVE only once Ubuntu ships
 * the fix, so a critical network bug can sit unfixed for weeks with nothing saying
 * so. This feed says so while there is still no fix to install.
 *
 * Every run reads the kernel records NVD changed since the last run (one NVD query
 * by the kernel CNA's source id and modified date) and keeps those with a CVSS 3
 * base score of KERNEL_MIN_SCORE or more and a network attack vector. The score is
 * the kernel CNA's own when it gave one, else NVD's: the CNA usually scores first,
 * and NVD's severity filter reads only NVD's score, so the filtering is done here.
 * A re-score changes the modified date, so an old CVE that becomes critical comes
 * back. Ubuntu's own priority is not used: Ubuntu often files a new kernel CVE at a
 * lower priority for days.
 *
 * Each CVE that passes is looked up in Ubuntu's record. "Pending" there means Ubuntu
 * built the fix (in -proposed, or in -updates) but has not released it as a
 * security update, so it still counts as no fix.
 *
 * The kernel CNA scores many network bugs 9.8, and many wait on the same kernel
 * build, so the CVEs one run finds share one card, which pages, and the CVEs the
 * feed's first read finds share one quiet card that grows as that read goes on.
 * Ubuntu's record of every CVE on an open card is read again each run (the longest
 * unchecked first), and a card closes once every release is fixed or not affected
 * for all of its CVEs. Until then each open card is sent again every RESURFACE_MS,
 * with its current Ubuntu status, so a card a person resolved too early comes back.
 */
import type { KernelConfig, UbuntuRelease } from './config.js'
import { KERNEL_FEED_ID } from './config.js'
import { fetchJson, type HttpOptions } from './http.js'
import type { AdvisoryRunReport, CardSink } from './types.js'
import { asArray, asRecord, cardId, closeCard, DAY_MS, esc, HOUR_MS, isoDay, joinAnd, jsonSize, RESURFACE_MS, sendCard, STATE_BUDGET, truncate } from './util.js'

/** NVD's CVE API (https://nvd.nist.gov/developers/vulnerabilities). */
export const NVD_CVE_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
/** The kernel's own CNA (kernel.org), as NVD names the source of its records and scores. */
export const KERNEL_CNA_SOURCE = '416baaa9-dc9f-4396-8d5f-8c081fb06d67'
/** Ubuntu's CVE records, one JSON per CVE. */
export const UBUNTU_CVE_URL = 'https://ubuntu.com/security/cves'
/** Ubuntu's page for a CVE, for people. */
const UBUNTU_PAGE = 'https://ubuntu.com/security'
/** A kernel CVE cards at this CVSS 3 base score or above, when its attack vector is the network. */
export const KERNEL_MIN_SCORE = 9.0
/** The first read looks back this far. */
export const KERNEL_LOOKBACK_DAYS = 30
/** NVD records per request. */
export const NVD_PAGE_SIZE = 250
/** NVD requests per run. NVD allows 5 in any 30 seconds without an API key. */
export const NVD_PAGES_PER_RUN = 4
/** Ubuntu lookups of new CVEs per run. The rest wait in the queue. */
export const UBUNTU_LOOKUP_CAP = 40
/** Ubuntu lookups of CVEs on open cards per run, the longest unchecked first. */
export const UBUNTU_RECHECK_CAP = 40
const NVD_SOURCE = 'nvd@nist.gov'
const NVD_TIMEOUT_MS = 30_000
const MAX_NVD_PAGE_BYTES = 12 * 1024 * 1024
/** A new NVD window starts this far before the last one ended, for records NVD indexes late. */
const NVD_OVERLAP_MS = 2 * HOUR_MS
/** NVD refuses a modified-date window over 120 days. */
const NVD_MAX_WINDOW_MS = 119 * DAY_MS
const MAX_UBUNTU_RECORD_BYTES = 512 * 1024
const UBUNTU_LOOKUP_BATCH = 8
/** The generic kernel's source package. */
const UBUNTU_KERNEL_PACKAGE = 'linux'
/** Kernel CVEs that passed the score and needed no card, or whose card closed. */
const KERNEL_SEEN_CAP = 1000
const KERNEL_QUEUE_CAP = 500

/** A kernel CVE whose score and attack vector pass, waiting for its Ubuntu lookup or carded. */
export interface KernelCve {
  id: string
  /** The fix's subject line. */
  summary: string
  score: number
  vector: string
  /** Whose score it is: the kernel CNA's, or NVD's own. */
  scoredBy: 'kernel' | 'nvd'
  published: number | null
  /** Found by the feed's first read, so its card does not page. */
  baseline?: boolean
}

export interface NvdKernelPage {
  /** Records in the whole window. */
  total: number
  /** Records on this page. */
  count: number
  /** The records on this page whose score and attack vector pass. */
  cves: KernelCve[]
}

/** One release, in Ubuntu's record of a CVE. */
export interface UbuntuKernelStatus {
  codename: string
  name: string
  /**
   * Ubuntu's status for the kernel (needed, pending, released, not-affected, DNE,
   * ignored, deferred, needs-triage). 'unlisted' when the record has no row for the
   * release, 'no-record' when Ubuntu has no record or no kernel entry yet.
   */
  status: string
  /** What Ubuntu names with it: the pending or fixed kernel version, or a note. */
  version: string
}

interface KernelMember {
  cve: KernelCve
  ubuntu: UbuntuKernelStatus[]
  /** When Ubuntu's record was last read (epoch ms). */
  checked: number
}

interface KernelCard {
  key: string
  /** What the closing note names: the CVE, or "N critical kernel bugs". */
  label: string
  members: KernelMember[]
  /** When the card was last sent (epoch ms). Absent in a state saved before it was kept. */
  sent?: number
}

/** An NVD modified-date window, read from its last page back to its first. */
interface KernelPass {
  from: number
  to: number
  /** The pages below this record index are still to read. */
  next: number
}

export interface KernelState {
  seen?: string[]
  /** NVD records modified up to here (epoch ms) have been read. Absent until the first read completes. */
  through?: number
  pass?: KernelPass
  /** CVEs that passed the score and wait for their Ubuntu lookup, newest first. */
  queue?: KernelCve[]
  open?: KernelCard[]
  fails?: number
  failingSince?: number
  unreadableCarded?: boolean
}

const KERNEL_CVE_ID = /^CVE-\d{4}-\d{4,}$/
const KERNEL_BOILERPLATE = /^\s*In the Linux kernel, the following vulnerability has been resolved:\s*/i
/** Fixed, not affected, not in the release, or not listed (a CVE fixed before the release existed). */
const UBUNTU_CLEAR = new Set(['released', 'not-affected', 'DNE', 'unlisted'])

// ---------------------------------------------------------------------------
// Parsing (pure)
// ---------------------------------------------------------------------------

/** NVD writes UTC timestamps without an offset, which Date.parse would read as local time. */
function parseUtc(s: unknown): number | null {
  if (typeof s !== 'string' || !s) return null
  const ms = Date.parse(/(?:Z|[+-]\d\d:?\d\d)$/i.test(s) ? s : `${s}Z`)
  return Number.isFinite(ms) ? ms : null
}

/** The CVSS 3 score a kernel record is judged on: the kernel CNA's, else NVD's own. Null when neither scored it. */
export function kernelCvss(cve: unknown): { score: number; vector: string; network: boolean; scoredBy: 'kernel' | 'nvd' } | null {
  const metrics = asRecord(asRecord(cve)?.metrics)
  if (!metrics) return null
  const all: Array<Record<string, unknown>> = []
  for (const m of [...asArray(metrics.cvssMetricV31), ...asArray(metrics.cvssMetricV30)]) {
    const r = asRecord(m)
    if (r && asRecord(r.cvssData)) all.push(r)
  }
  const m = all.find((x) => x.source === KERNEL_CNA_SOURCE) || all.find((x) => x.source === NVD_SOURCE)
  const data = asRecord(m?.cvssData)
  if (!m || !data || typeof data.baseScore !== 'number' || !Number.isFinite(data.baseScore)) return null
  const vector = typeof data.vectorString === 'string' ? data.vectorString.slice(0, 200) : ''
  return {
    score: data.baseScore,
    vector,
    network: data.attackVector === 'NETWORK' || /\/AV:N(?:\/|$)/.test(vector),
    scoredBy: m.source === KERNEL_CNA_SOURCE ? 'kernel' : 'nvd',
  }
}

function kernelSummary(cve: Record<string, unknown>, id: string): string {
  const en = asArray(cve.descriptions)
    .map(asRecord)
    .find((d) => d?.lang === 'en')
  const text = typeof en?.value === 'string' ? en.value.replace(KERNEL_BOILERPLATE, '') : ''
  const line = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find(Boolean)
  return truncate(line || id, 160)
}

/** One page of an NVD CVE query. Null when it is not one. */
export function parseNvdKernelPage(raw: unknown): NvdKernelPage | null {
  const r = asRecord(raw)
  if (!r || typeof r.totalResults !== 'number' || !Array.isArray(r.vulnerabilities)) return null
  const cves: KernelCve[] = []
  for (const v of r.vulnerabilities) {
    const cve = asRecord(asRecord(v)?.cve)
    const id = typeof cve?.id === 'string' ? cve.id : ''
    if (!cve || !KERNEL_CVE_ID.test(id) || cve.vulnStatus === 'Rejected') continue
    const cvss = kernelCvss(cve)
    if (!cvss || !cvss.network || cvss.score < KERNEL_MIN_SCORE) continue
    cves.push({ id, summary: kernelSummary(cve, id), score: cvss.score, vector: cvss.vector, scoredBy: cvss.scoredBy, published: parseUtc(cve.published) })
  }
  return { total: r.totalResults, count: r.vulnerabilities.length, cves }
}

/** Every release as having no Ubuntu record of the CVE yet. */
export function noUbuntuRecord(releases: UbuntuRelease[]): UbuntuKernelStatus[] {
  return releases.map((r) => ({ codename: r.codename, name: r.name, status: 'no-record', version: '' }))
}

/** Ubuntu's kernel status for each release, from its record of one CVE. Null when it is not that record. */
export function parseUbuntuKernelStatus(raw: unknown, id: string, releases: UbuntuRelease[]): UbuntuKernelStatus[] | null {
  const r = asRecord(raw)
  if (!r || r.id !== id || !Array.isArray(r.packages)) return null
  const kernel = r.packages.map(asRecord).find((p) => p?.name === UBUNTU_KERNEL_PACKAGE)
  if (!kernel) return noUbuntuRecord(releases)
  const rows = asArray(kernel.statuses).map(asRecord)
  return releases.map((rel) => {
    const row = rows.find((s) => s?.release_codename === rel.codename)
    const status = !row ? 'unlisted' : typeof row.status === 'string' && row.status ? row.status.slice(0, 40) : 'needs-triage'
    return { codename: rel.codename, name: rel.name, status, version: typeof row?.description === 'string' ? truncate(row.description.trim(), 80) : '' }
  })
}

/** Whether a release still has no fixed Ubuntu kernel. An unknown status counts as no fix. */
export function kernelFixMissing(statuses: UbuntuKernelStatus[]): boolean {
  return statuses.some((s) => !UBUNTU_CLEAR.has(s.status))
}

/** "pending 6.8.0-101.101" */
export function describeUbuntuStatus(s: UbuntuKernelStatus): string {
  const v = s.version
  switch (s.status) {
    case 'pending':
      return v ? `pending ${v}` : 'pending'
    case 'needed':
      return 'needed (no fix yet)'
    case 'needs-triage':
      return 'not triaged yet'
    case 'no-record':
      return 'no Ubuntu record yet'
    case 'released':
      return v ? `fixed in ${v}` : 'fixed'
    case 'not-affected':
      return 'not affected'
    case 'DNE':
      return 'not in this release'
    case 'unlisted':
      return 'not listed'
    default:
      // deferred, ignored: the note says until when or why.
      return v ? `${s.status} (${v})` : s.status
  }
}

/** One line per release: the CVE's status, or for several CVEs how many are in each. Ubuntu's text is escaped for a card body. */
export function ubuntuStatusLines(ubuntu: UbuntuKernelStatus[][]): string {
  const byRelease = new Map<string, { label: string; counts: Map<string, number> }>()
  for (const statuses of ubuntu) {
    for (const s of statuses) {
      const r = byRelease.get(s.codename) || { label: `${s.name} (${s.codename})`, counts: new Map<string, number>() }
      const d = esc(describeUbuntuStatus(s))
      r.counts.set(d, (r.counts.get(d) || 0) + 1)
      byRelease.set(s.codename, r)
    }
  }
  return [...byRelease.values()]
    .map(({ label, counts }) => {
      if (ubuntu.length === 1) return `${label}: ${[...counts.keys()][0]}`
      const parts = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([d, n]) => `${n} ${d}`)
      return `${label}: ${parts.join(', ')}`
    })
    .join('\n')
}

export function kernelCardKey(ids: string[]): string {
  return cardId('advisory', KERNEL_FEED_ID, ids.length === 1 ? ids[0] : [...ids].sort().join('+'))
}

export function kernelFirstReadCardKey(): string {
  return cardId('advisory', KERNEL_FEED_ID, 'first-read')
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/** What one run of the kernel feed read. */
export interface KernelRead {
  at: number
  through?: number
  pass?: KernelPass
  /** No NVD read has completed yet. */
  baseline: boolean
  /** Records read whose score or attack vector does not pass. */
  belowScore: number
  /** CVEs still waiting for an Ubuntu lookup, newest first. */
  queue: KernelCve[]
  /** New CVEs looked up this run. */
  looked: Array<{ cve: KernelCve; ubuntu: UbuntuKernelStatus[] }>
  /** Carded CVEs looked up this run. One whose lookup failed is left out and stays as it was. */
  openStatus: Array<{ id: string; ubuntu: UbuntuKernelStatus[] }>
}

function nvdKernelUrl(from: number, to: number, startIndex: number, size: number): string {
  const q = new URLSearchParams({
    sourceIdentifier: KERNEL_CNA_SOURCE,
    lastModStartDate: new Date(from).toISOString(),
    lastModEndDate: new Date(to).toISOString(),
    resultsPerPage: String(size),
    startIndex: String(startIndex),
  })
  return `${NVD_CVE_API}?${q}&noRejected`
}

async function fetchNvdKernelPage(http: HttpOptions, from: number, to: number, startIndex: number, size: number): Promise<NvdKernelPage | null> {
  const res = await fetchJson(http, nvdKernelUrl(from, to, startIndex, size), MAX_NVD_PAGE_BYTES, NVD_TIMEOUT_MS)
  return res.ok ? parseNvdKernelPage(res.body) : null
}

/** Ubuntu's kernel status for one CVE. Null when the lookup failed; no record yet reads as 'no-record'. */
async function fetchUbuntuKernelStatus(http: HttpOptions, id: string, releases: UbuntuRelease[]): Promise<UbuntuKernelStatus[] | null> {
  const res = await fetchJson(http, `${UBUNTU_CVE_URL}/${id}.json`, MAX_UBUNTU_RECORD_BYTES)
  if (!res.ok) return res.code === 404 ? noUbuntuRecord(releases) : null
  return parseUbuntuKernelStatus(res.body, id, releases)
}

/** The open kernel cards in the state, without anything malformed. */
function kernelCards(prev: KernelState): KernelCard[] {
  return asArray(prev.open).flatMap((x) => {
    const card = asRecord(x) as Partial<KernelCard> | null
    if (!card || typeof card.key !== 'string' || !Array.isArray(card.members)) return []
    const members = card.members
      .filter((m) => m && m.cve && typeof m.cve.id === 'string' && KERNEL_CVE_ID.test(m.cve.id) && Array.isArray(m.ubuntu))
      .map((m) => ({ ...m, checked: typeof m.checked === 'number' ? m.checked : 0 }))
    return [{ key: card.key, label: typeof card.label === 'string' ? card.label : card.key, members, ...(typeof card.sent === 'number' ? { sent: card.sent } : {}) }]
  })
}

async function lookupUbuntu(http: HttpOptions, ids: string[], releases: UbuntuRelease[]): Promise<Array<UbuntuKernelStatus[] | null>> {
  const out: Array<UbuntuKernelStatus[] | null> = []
  for (let i = 0; i < ids.length; i += UBUNTU_LOOKUP_BATCH) {
    out.push(...(await Promise.all(ids.slice(i, i + UBUNTU_LOOKUP_BATCH).map((id) => fetchUbuntuKernelStatus(http, id, releases)))))
  }
  return out
}

/**
 * Reads the NVD window since the last run: in one request when it fits a page,
 * else from its last page back to its first, NVD_PAGES_PER_RUN pages a run. NVD
 * lists a window oldest first, so this reads the newest records first, and a
 * record that leaves the window mid-read (changed again) only moves the unread
 * ones up into pages still to come. Then it looks up, in Ubuntu's records, up to
 * UBUNTU_RECHECK_CAP CVEs on open cards and up to UBUNTU_LOOKUP_CAP waiting ones.
 * Null when NVD or Ubuntu could not be read: the run changes nothing.
 */
export async function readKernelFeed(http: HttpOptions, kernel: KernelConfig, prev: KernelState, now: number): Promise<KernelRead | null> {
  const baseline = typeof prev.through !== 'number'
  const queued = asArray(prev.queue).filter((q): q is KernelCve => !!q && typeof (q as KernelCve).id === 'string' && KERNEL_CVE_ID.test((q as KernelCve).id))
  const members = kernelCards(prev).flatMap((card) => card.members)
  const known = new Set([...asArray(prev.seen).filter((s): s is string => typeof s === 'string'), ...members.map((m) => m.cve.id), ...queued.map((q) => q.id)])
  const open = [...members]
    .sort((a, b) => a.checked - b.checked)
    .slice(0, UBUNTU_RECHECK_CAP)
    .map((m) => m.cve.id)
  const found = new Map<string, KernelCve>()
  let belowScore = 0
  const take = (page: NvdKernelPage) => {
    belowScore += page.count - page.cves.length
    for (const cve of page.cves) if (!known.has(cve.id)) found.set(cve.id, baseline ? { ...cve, baseline: true } : cve)
  }

  let through = baseline ? undefined : prev.through
  let pass = asRecord(prev.pass) ? prev.pass : undefined
  let pages = 0
  if (!pass) {
    const to = now
    const from = Math.max(through === undefined ? now - KERNEL_LOOKBACK_DAYS * DAY_MS : through - NVD_OVERLAP_MS, to - NVD_MAX_WINDOW_MS)
    const first = await fetchNvdKernelPage(http, from, to, 0, NVD_PAGE_SIZE)
    if (!first) return null
    pages++
    take(first)
    if (first.total <= first.count) through = to
    else pass = { from, to, next: first.total }
  }
  while (pass && pages < NVD_PAGES_PER_RUN) {
    const start = Math.max(0, pass.next - NVD_PAGE_SIZE)
    const page = await fetchNvdKernelPage(http, pass.from, pass.to, start, pass.next - start)
    if (!page) {
      if (pages === 0) return null
      // Keep what was read; the window goes on next run.
      break
    }
    pages++
    take(page)
    if (start === 0) {
      through = pass.to
      pass = undefined
    } else {
      pass = { ...pass, next: start }
    }
  }

  const queue = [...queued, ...found.values()].sort((a, b) => (b.published ?? 0) - (a.published ?? 0))
  const batch = queue.slice(0, UBUNTU_LOOKUP_CAP)
  const results = await lookupUbuntu(http, [...open, ...batch.map((q) => q.id)], kernel.releases)
  // Ubuntu unreadable: nothing moves, and the failure streak counts it.
  if (results.length > 0 && results.every((r) => r === null)) return null

  const looked: KernelRead['looked'] = []
  const retry: KernelCve[] = []
  batch.forEach((cve, i) => {
    const ubuntu = results[open.length + i]
    if (ubuntu) looked.push({ cve, ubuntu })
    else retry.push(cve)
  })
  const openStatus = open.flatMap((id, i) => {
    const ubuntu = results[i]
    return ubuntu ? [{ id, ubuntu }] : []
  })
  return { at: now, through, pass, baseline, belowScore, queue: [...retry, ...queue.slice(UBUNTU_LOOKUP_CAP)], looked, openStatus }
}

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

const KERNEL_ADVICE =
  "Ubuntu has not released a security update with the fix yet, so a box's own update check has nothing to install. Pending means Ubuntu built the fix (in -proposed or -updates) but has not released it. Check whether the bug is reachable on your servers and mitigate it until the fix ships. This card closes once every listed Ubuntu release has the fix. If you resolve it before that, it opens again within about 6 hours."

/** Room for the list of CVEs on a card with several. */
const KERNEL_LIST_MAX = 1800

function kernelCardText(kernel: KernelConfig, card: KernelCard, pages: boolean): { title: string; body: string; url?: string } {
  const members = [...card.members].sort((a, b) => (b.cve.published ?? 0) - (a.cve.published ?? 0) || a.cve.id.localeCompare(b.cve.id))
  const lone = members.length === 1 ? members[0].cve : null
  const lead = pages ? '' : `Already open when this feed first read the last ${KERNEL_LOOKBACK_DAYS} days, so this card does not page. `
  const scores = members.map((m) => m.cve.score)
  const low = Math.min(...scores)
  const high = Math.max(...scores)
  const scorers = [...new Set(members.map((m) => (m.cve.scoredBy === 'kernel' ? 'the kernel CNA' : 'NVD')))]
  const days = [...new Set(members.flatMap((m) => (m.cve.published === null ? [] : [isoDay(m.cve.published)])))].sort()
  let text: string
  if (lone) {
    text = `${esc(lone.summary.replace(/\.+$/, ''))}. ${lead}${KERNEL_ADVICE}`
  } else {
    const lines: string[] = []
    let used = 0
    for (const [i, m] of members.entries()) {
      const line = `${m.cve.id}, ${m.cve.score}: ${esc(m.cve.summary)}`
      if (used + line.length > KERNEL_LIST_MAX) {
        lines.push(`And ${members.length - i} more.`)
        break
      }
      lines.push(line)
      used += line.length + 1
    }
    text = `${lead}${lines.join('\n')}\n\nUbuntu's page for each: ${UBUNTU_PAGE}/<CVE id>\n\n${KERNEL_ADVICE}`
  }
  const fields = [
    kernel.runsOn ? `Runs on: ${kernel.runsOn}` : '',
    lone
      ? `CVSS: ${lone.score} from ${scorers[0]}${lone.vector ? `, ${esc(lone.vector)}` : ''}`
      : `CVSS: ${low === high ? low : `${low} to ${high}`} from ${joinAnd(scorers)}, network`,
    `Published: ${days.length <= 1 ? days[0] || 'not given' : `${days[0]} to ${days[days.length - 1]}`}`,
  ].filter(Boolean)
  return {
    title: lone ? `Critical kernel bug with no Ubuntu security fix yet: ${lone.id}` : `${members.length} critical kernel bugs with no Ubuntu security fix yet`,
    body: `${text}\n\n${ubuntuStatusLines(members.map((m) => m.ubuntu))}\n${fields.join('\n')}`,
    ...(lone ? { url: `${UBUNTU_PAGE}/${lone.id}` } : {}),
  }
}


export interface KernelApplyCtx {
  cards: CardSink
  kernel: KernelConfig
  report: AdvisoryRunReport
  /** Cards this run may still send. */
  budget: { left: number }
}

function sendKernelCard(ctx: KernelApplyCtx, card: KernelCard, pages: boolean): Promise<boolean> {
  const t = kernelCardText(ctx.kernel, card, pages)
  return sendCard(ctx.cards, { id: card.key, severity: pages ? 'critical' : 'warning', ping: pages, title: t.title, body: t.body, ...(t.url ? { url: t.url } : {}) })
}

async function emitKernelCard(ctx: KernelApplyCtx, card: KernelCard, pages: boolean): Promise<boolean> {
  if (ctx.budget.left <= 0) return false
  const sent = await sendKernelCard(ctx, card, pages)
  if (sent) {
    ctx.budget.left--
    ctx.report.emitted++
  }
  return sent
}

/** Cards and closes kernel CVEs from one run's read, and returns the feed's next state. */
export async function applyKernelRead(ctx: KernelApplyCtx, prev: KernelState, k: KernelRead): Promise<KernelState> {
  const seen = new Set(asArray(prev.seen).filter((s): s is string => typeof s === 'string'))
  const queue = [...k.queue]
  ctx.report.belowThreshold += k.belowScore

  // Open cards: drop the CVEs that are fixed now, and close a card with none left.
  const latest = new Map(k.openStatus.map((o) => [o.id, o.ubuntu]))
  const open: KernelCard[] = []
  for (const card of kernelCards(prev)) {
    const members = card.members.flatMap((m) => {
      const ubuntu = latest.get(m.cve.id)
      // Not read this run (its turn has not come, or the lookup failed): as it was.
      if (!ubuntu) return [m]
      if (kernelFixMissing(ubuntu)) return [{ cve: m.cve, ubuntu, checked: k.at }]
      seen.add(m.cve.id)
      return []
    })
    if (members.length > 0) {
      open.push({ ...card, members })
      continue
    }
    const closed = await closeCard(
      ctx.cards,
      card.key,
      `Ubuntu security fix out for ${card.label}. Every listed Ubuntu release now has a security fix, or is not affected, for everything on this card. Install it and reboot.`,
    )
    if (closed) ctx.report.closed++
    // A close that did not go out keeps the card, empty, to try again next run.
    else open.push({ ...card, members })
  }

  // New CVEs: the first read's join its one quiet card, the rest of this run's share a new card that pages.
  const firstRead: KernelMember[] = []
  const fresh: KernelMember[] = []
  for (const { cve, ubuntu } of k.looked) {
    if (!kernelFixMissing(ubuntu)) {
      // Fixed or not affected on every listed release: a box's own update check covers the rest.
      seen.add(cve.id)
      ctx.report.skipped++
      continue
    }
    if (cve.baseline) firstRead.push({ cve, ubuntu, checked: k.at })
    else fresh.push({ cve, ubuntu, checked: k.at })
  }
  const sentNow = new Set<string>()
  if (firstRead.length > 0) {
    const key = kernelFirstReadCardKey()
    const existing = open.find((o) => o.key === key)
    const members = [...(existing?.members || []), ...firstRead]
    const card: KernelCard = { key, label: `the ${members.length} critical kernel bugs from the first read`, members, sent: k.at }
    if (await emitKernelCard(ctx, card, false)) {
      if (existing) Object.assign(existing, card)
      else open.push(card)
      sentNow.add(key)
    } else {
      queue.unshift(...firstRead.map((m) => m.cve))
    }
  }
  if (fresh.length > 0) {
    const ids = fresh.map((m) => m.cve.id)
    const card: KernelCard = { key: kernelCardKey(ids), label: ids.length === 1 ? ids[0] : `${ids.length} critical kernel bugs`, members: fresh, sent: k.at }
    if (await emitKernelCard(ctx, card, true)) {
      open.push(card)
      sentNow.add(card.key)
    } else queue.unshift(...fresh.map((m) => m.cve))
  }

  // Still open: sent again on the slow timer, with the latest Ubuntu status. A card a
  // person resolved comes back as a new one. Outside the card budget: it is not new.
  for (const card of open) {
    if (sentNow.has(card.key) || card.members.length === 0 || k.at - (card.sent ?? 0) < RESURFACE_MS) continue
    if (await sendKernelCard(ctx, card, card.key !== kernelFirstReadCardKey())) {
      card.sent = k.at
      ctx.report.resent++
    }
  }

  ctx.report.deferred += queue.length
  const next: KernelState = {
    ...prev,
    seen: [...seen].slice(-KERNEL_SEEN_CAP),
    through: k.through,
    pass: k.pass,
    queue: queue.slice(0, KERNEL_QUEUE_CAP),
    open,
  }
  if (next.through === undefined) delete next.through
  if (next.pass === undefined) delete next.pass
  return fitKernelState(next)
}

/** Keeps the state under the save budget: the oldest seen ids go first, then the end of the queue. Open cards are kept. */
export function fitKernelState(state: KernelState): KernelState {
  const s = { ...state, seen: [...(state.seen ?? [])], queue: [...(state.queue ?? [])] }
  while (jsonSize(s) > STATE_BUDGET && (s.seen.length > 0 || s.queue.length > 0)) {
    if (s.seen.length > 0) s.seen = s.seen.slice(Math.ceil(s.seen.length / 2))
    else s.queue = s.queue.slice(0, Math.floor(s.queue.length / 2))
  }
  return s
}
