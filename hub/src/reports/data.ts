/**
 * The two data events (docs/report-protocol.md, "Data events"): parsed from a
 * report's `detail` into the records the hub keeps. PURE.
 *
 * The detail is untrusted. Only the known `key=value` tokens are read, each
 * value is checked against a fixed character set or range, lists are capped
 * before they are walked, and the stored time is the hub's receive time, never
 * the box's clock.
 */
import type { ContainerPackagesRecord, RebootPendingRecord } from '../state.js'

/** Sources with a pending reboot kept at most. */
export const REBOOT_PENDING_MAX = 200
export const REBOOT_PENDING_MAX_PKGS = 12
/** Containers kept at most, in all and per box. */
export const CONTAINERS_MAX = 200
export const CONTAINERS_MAX_PER_BOX = 50
/** Packages kept per container. */
export const CONTAINER_MAX_PKGS = 800
/** A box resends unchanged data about every 20 hours; past this it is stale. */
export const REBOOT_STALE_MS = 48 * 3_600_000
/** Past this with no report a record is dropped (the box or container is gone unheard). */
export const DATA_PRUNE_MS = 30 * 864e5

const TOKENS_MAX = 32
const COUNT_MAX = 99_999
/** 2015-01-01. Anything earlier is garbage or a unit mix-up. */
const MIN_EPOCH_MS = 1_420_070_400_000
const MAX_FUTURE_SKEW_MS = 24 * 3_600_000

const REBOOT_PKG_RE = /^[a-z0-9][a-z0-9+.-]{0,63}$/
const CONTAINER_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}$/
const IMAGE_ID_RE = /^(?:sha256:)?([0-9a-f]{12,64})$/
const OS_ID_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/
const OS_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/
const PKG_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9+._-]{0,99}$/
const PKG_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,99}$/

/** The first value of each `key=value` token. Later repeats are ignored. */
export function detailTokens(detail: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const t of detail.split(/\s+/).slice(0, TOKENS_MAX)) {
    const at = t.indexOf('=')
    if (at <= 0) continue
    const key = t.slice(0, at)
    if (!out.has(key)) out.set(key, t.slice(at + 1))
  }
  return out
}

function count(v: string | undefined): number | null {
  if (v === undefined || !/^\d{1,7}$/.test(v)) return null
  return Math.min(COUNT_MAX, Number(v))
}

function epochSeconds(v: string | undefined, now: number): number | null {
  if (v === undefined || !/^\d{1,12}$/.test(v)) return null
  const ms = Number(v) * 1000
  return ms >= MIN_EPOCH_MS && ms <= now + MAX_FUTURE_SKEW_MS ? ms : null
}

// ---- reboot-pending ------------------------------------------------------------

/** Never fails: an unknown or bad value reads as not sent, and `checked` holds only with both counts. */
export function parseRebootPending(detail: string, source: string, now: number): RebootPendingRecord {
  const tokens = detailTokens(detail)
  const covered = count(tokens.get('hc_covered'))
  const uncovered = count(tokens.get('hc_uncovered'))
  const checked = tokens.get('checked') === 'yes' && covered !== null && uncovered !== null
  const lp = tokens.get('livepatch')
  const pkgsRaw = tokens.get('pkgs')
  const pkgs: string[] = []
  if (pkgsRaw && pkgsRaw !== '-') {
    // Cap before walking, so an oversized list costs nothing.
    for (const p of pkgsRaw.split(',').slice(0, REBOOT_PENDING_MAX_PKGS * 2)) {
      if (REBOOT_PKG_RE.test(p) && !pkgs.includes(p)) pkgs.push(p)
      if (pkgs.length >= REBOOT_PENDING_MAX_PKGS) break
    }
  }
  return {
    source,
    since: epochSeconds(tokens.get('since'), now),
    checked,
    livepatch: lp === 'on' ? true : lp === 'off' ? false : null,
    pkgs,
    more: count(tokens.get('more')) ?? 0,
    covered: checked ? covered : null,
    uncovered: checked ? uncovered : null,
    receivedAt: now,
  }
}

// ---- container-packages ----------------------------------------------------------

/** The container a report names (`ctr=`), for a resolved report too. null when not usable. */
export function containerName(detail: string): string | null {
  const ctr = detailTokens(detail).get('ctr')
  return ctr && CONTAINER_RE.test(ctr) ? ctr : null
}

/**
 * An image reference without its digest, with `:latest` when it has no tag, so
 * the same image pinned by digest or not is one image. null when it is not one.
 */
export function normalizeImageRef(ref: string | undefined): string | null {
  if (!ref || !IMAGE_RE.test(ref)) return null
  const at = ref.indexOf('@')
  const bare = at >= 0 ? ref.slice(0, at) : ref
  if (!bare || bare.includes('@')) return null
  const slash = bare.lastIndexOf('/')
  const colon = bare.lastIndexOf(':')
  return colon > slash ? bare : `${bare}:latest`
}

/** null when the container name or the image is missing or not usable. */
export function parseContainerPackages(detail: string, box: string, now: number): ContainerPackagesRecord | null {
  const tokens = detailTokens(detail)
  const container = tokens.get('ctr')
  const image = normalizeImageRef(tokens.get('img'))
  if (!container || !CONTAINER_RE.test(container) || !image) return null
  const iid = IMAGE_ID_RE.exec(tokens.get('iid') ?? '')
  const os = tokens.get('os') ?? ''
  const osVersion = tokens.get('osver') ?? ''
  const pm = tokens.get('pm')
  const raw = tokens.get('pkgs')
  const items = raw && raw !== '-' ? raw.split(',') : []
  // Cap before walking, so an oversized list costs nothing.
  const capped = items.slice(0, CONTAINER_MAX_PKGS * 2)
  let dropped = items.length - capped.length
  const seen = new Set<string>()
  const packages: { name: string; version: string }[] = []
  for (const item of capped) {
    const at = item.indexOf('@')
    if (at <= 0) continue
    const name = item.slice(0, at)
    const version = item.slice(at + 1)
    if (!PKG_NAME_RE.test(name) || !PKG_VERSION_RE.test(version)) continue
    const id = `${name}@${version}`
    if (seen.has(id)) continue
    seen.add(id)
    if (packages.length >= CONTAINER_MAX_PKGS) {
      dropped++
      continue
    }
    packages.push({ name, version })
  }
  packages.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : a.version > b.version ? 1 : 0))
  return {
    box,
    container,
    image,
    imageId: iid ? iid[1].slice(0, 12) : null,
    builtAt: epochSeconds(tokens.get('built'), now),
    os: OS_ID_RE.test(os) ? os : '',
    osVersion: OS_VERSION_RE.test(osVersion) ? osVersion : '',
    pm: pm === 'dpkg' || pm === 'apk' ? pm : 'none',
    packages,
    more: Math.min(COUNT_MAX, (count(tokens.get('more')) ?? 0) + dropped),
    receivedAt: now,
  }
}

export function containerKey(box: string, container: string): string {
  return `${box}/${container}`
}
