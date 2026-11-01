/**
 * The interface between the watch modules and the hub. The hub implements
 * CardSink and WatchDeps; the watch modules never talk to Discord or the disk.
 */

/** One card the hub shows. `id` is stable per thing watched, so an upsert edits the open card in place. */
export interface WatchCard {
  id: string
  severity: 'critical' | 'warning' | 'info'
  /** Only matters for critical. */
  ping: boolean
  /** At most 120 characters, plain text. */
  title: string
  /** At most 3,500 characters, shown as Discord markdown: outside text goes through esc() (util.ts). */
  body: string
  url?: string
}

export interface CardSink {
  /**
   * Creates the card, or edits the open one with the same id. Never reposts an
   * unchanged card. When no card with the id is open (a person resolved it),
   * it creates a new one. Rejects when the card did not go out: the module
   * keeps it and tries again next run.
   */
  upsert(card: WatchCard): Promise<void>
  /**
   * Resolves the card. A no-op when no card with this id is open. Only for a
   * problem the hub saw end itself (a feed it read, a release it looked up):
   * when the only sign of a fix comes from the boxes, use reportFixed.
   */
  close(id: string, note: string): Promise<void>
  /**
   * Adds `note` to the open card and leaves it open for a person to Resolve:
   * a box cannot close an alert about itself. A no-op when no card with this
   * id is open. The next upsert of the id takes the note off again.
   */
  reportFixed(id: string, note: string): Promise<void>
}

/** One container's OS packages, as a box reported them (the `container-packages` data event). */
export interface ContainerPackagesRecord {
  box: string
  container: string
  image: string
  imageId: string | null
  /** Epoch ms. */
  builtAt: number | null
  /** os-release ID and VERSION_ID, empty when the image has no os-release. */
  os: string
  osVersion: string
  pm: 'dpkg' | 'apk' | 'none'
  /** Source packages (the dpkg `Source:` field, the Alpine origin). */
  packages: { name: string; version: string }[]
  /** Packages the box left out of the list. */
  more: number
  /** When the hub received the report, epoch ms. */
  receivedAt: number
}

export interface WatchDeps {
  cards: CardSink
  fetch: typeof fetch
  /** Epoch ms. */
  now(): number
  /** The value last saved under `name`, or undefined/null when there is none. */
  loadState(name: string): unknown
  /** About 512 kB of JSON per name at most. */
  saveState(name: string, value: unknown): Promise<void>
  listContainerPackages(): ContainerPackagesRecord[]
  /** One line. Never passed a token or a response body. */
  log(msg: string): void
  /** Sent only to https://api.github.com. */
  githubToken?: string
}

export interface AdvisoryRunReport {
  kind: 'advisories'
  /** Every feed's state was saved and no step threw. A feed that could not be read does not clear this; see `failed`. */
  ok: boolean
  /** Feeds this run read (components with a feed, plus the kernel feed). */
  feeds: number
  read: number
  notModified: number
  /** Ids of the feeds that could not be read. */
  failed: string[]
  /** Ids of the feeds on their first read. */
  baselined: string[]
  /** Cards created or edited. */
  emitted: number
  /** Cards closed. */
  closed: number
  /** Open cards for a problem that is still there, sent again on the 6-hour timer (RESURFACE_MS). */
  resent: number
  /** New advisories below the card threshold (medium, low, or a kernel CVE under the score), recorded without a card. */
  belowThreshold: number
  /** New items that concern nothing watched (an RSS item the match skips, a KEV entry for something not listed, a kernel CVE already fixed). */
  skipped: number
  /** New advisories left for a later run (over the card cap, or the card did not go out). */
  deferred: number
  errors: string[]
}

export interface ContainerSeverityCounts {
  /** Fixable CVEs, counted once per container and package. */
  critical: number
  high: number
  medium: number
  /** Low, or a score of 0. */
  low: number
  /** Fixable, with no severity yet. */
  unknown: number
  /** No fix in the container's release yet. */
  unfixed: number
}

export interface ContainerRunReport {
  kind: 'containers'
  /** The package lists and OSV were read and the state was saved. */
  ok: boolean
  /** Off in watch.json: nothing was read. */
  disabled: boolean
  containers: number
  /** Checked in full: every package answered and every matched record read. */
  evaluated: number
  /** A record still missing (over the fetch cap, or its fetch failed). */
  incomplete: number
  /** No report for 3 days: opens and closes nothing. */
  stale: number
  /** `box/container os version` of a container this check cannot read. */
  unsupported: string[]
  queries: number
  vulns: number
  detailsFetched: number
  detailsFailed: number
  detailsDeferred: number
  fixable: ContainerSeverityCounts
  emitted: number
  updated: number
  /** Open cards sent again on the 6-hour timer (RESURFACE_MS). */
  resent: number
  /** Cards closed: the "can't check" card, or an image card the hub saw fixed itself (none today). */
  closed: number
  /** Image cards marked fixed because the boxes report it: they wait for a person to press Resolve. */
  reportedFixed: number
  deferred: number
  cardsTracked: number
  errors: string[]
}

export type RunReport = AdvisoryRunReport | ContainerRunReport
