import { vi } from 'vitest'
import type { CardSink, ContainerPackagesRecord, WatchCard, WatchDeps } from '../../src/watch/types.js'

export const HOUR = 3_600_000
export const DAY = 86_400_000

/** Pins Date (only Date: AbortSignal.timeout and the promise queue keep real timers). */
export function pinClock(at: number): void {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(at)
}

export function advanceClock(ms: number): void {
  vi.setSystemTime(Date.now() + ms)
}

/** A sink that behaves like the hub's: upsert keeps one open card per id, close removes it. */
export class FakeSink implements CardSink {
  open = new Map<string, WatchCard>()
  upserts: WatchCard[] = []
  closes: Array<{ id: string; note: string; wasOpen: boolean }> = []
  fixedMarks: Array<{ id: string; note: string; wasOpen: boolean }> = []
  /** Open cards marked reported fixed, with the note. An upsert takes the mark off, as the hub does. */
  reportedFixed = new Map<string, string>()
  /** While false, every call throws, as a sink that cannot reach Discord would. */
  accept = true

  async upsert(card: WatchCard): Promise<void> {
    if (!this.accept) throw new Error('sink down')
    this.upserts.push(card)
    this.open.set(card.id, card)
    this.reportedFixed.delete(card.id)
  }

  async close(id: string, note: string): Promise<void> {
    if (!this.accept) throw new Error('sink down')
    this.closes.push({ id, note, wasOpen: this.open.has(id) })
    this.open.delete(id)
    this.reportedFixed.delete(id)
  }

  async reportFixed(id: string, note: string): Promise<void> {
    if (!this.accept) throw new Error('sink down')
    this.fixedMarks.push({ id, note, wasOpen: this.open.has(id) })
    if (this.open.has(id)) this.reportedFixed.set(id, note)
  }

  /** A person pressed Resolve. */
  resolve(id: string): void {
    this.open.delete(id)
    this.reportedFixed.delete(id)
  }

  clear(): void {
    this.upserts = []
    this.closes = []
    this.fixedMarks = []
  }
}

export type Route = (url: string, init: RequestInit | undefined) => Response | null | Promise<Response | null>

export interface FakeDeps extends WatchDeps {
  sink: FakeSink
  state: Map<string, string>
  logs: string[]
  requests: Array<{ url: string; method: string; headers: Headers; body: string | null; redirect?: RequestInit['redirect'] }>
  containers: ContainerPackagesRecord[]
  failLoad: Set<string>
  failSave: Set<string>
  fetchMock: ReturnType<typeof vi.fn>
}

/** Deps with in-memory state (JSON round-tripped, as a file store would), a fake sink and a routed fetch. */
export function fakeDeps(route: Route, extra: Partial<WatchDeps> = {}): FakeDeps {
  const sink = new FakeSink()
  const state = new Map<string, string>()
  const logs: string[] = []
  const requests: FakeDeps['requests'] = []
  const failLoad = new Set<string>()
  const failSave = new Set<string>()
  const deps = {
    sink,
    state,
    logs,
    requests,
    containers: [] as ContainerPackagesRecord[],
    failLoad,
    failSave,
    cards: sink,
    now: () => Date.now(),
    loadState(name: string): unknown {
      if (failLoad.has(name)) throw new Error('state store down')
      const raw = state.get(name)
      return raw === undefined ? undefined : JSON.parse(raw)
    },
    async saveState(name: string, value: unknown): Promise<void> {
      if (failSave.has(name)) throw new Error('state store down')
      state.set(name, JSON.stringify(value))
    },
    listContainerPackages(): ContainerPackagesRecord[] {
      return deps.containers
    },
    log(msg: string) {
      logs.push(msg)
    },
    ...extra,
  } as FakeDeps
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const headers = new Headers(init?.headers)
    requests.push({ url, method: init?.method ?? 'GET', headers, body: typeof init?.body === 'string' ? init.body : null, redirect: init?.redirect })
    const res = await route(url, init)
    if (res) {
      const etag = res.headers.get('etag')
      if (etag && headers.get('if-none-match') === etag) return new Response(null, { status: 304 })
      return res
    }
    return new Response('not found', { status: 404 })
  })
  deps.fetchMock = fetchMock
  deps.fetch = fetchMock as unknown as typeof fetch
  return deps
}

export function stateOf<T = Record<string, unknown>>(deps: FakeDeps, name: string): T | undefined {
  const raw = deps.state.get(name)
  return raw === undefined ? undefined : (JSON.parse(raw) as T)
}

export function json(body: unknown, etag?: string, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...(etag ? { etag } : {}) } })
}

export function text(body: string, etag?: string, status = 200): Response {
  return new Response(body, { status, headers: etag ? { etag } : {} })
}

/** Every card's text keeps to the hub's limits and the writing rules. */
/** A Discord masked link: `[text](url)` with neither bracket escaped. */
export const MASKED_LINK = /(?<!\\)\[[^\]]*(?<!\\)\]\(/

export function checkCardText(cards: WatchCard[]): void {
  for (const c of cards) {
    if (c.title.length > 120) throw new Error(`title too long: ${c.title}`)
    if (c.body.length > 3500) throw new Error(`body too long for ${c.id}`)
    if (c.id.length > 100) throw new Error(`id too long: ${c.id}`)
    const all = `${c.title}\n${c.body}`
    if (all.includes(String.fromCharCode(0x2014))) throw new Error(`em-dash in ${c.id}`)
    if (MASKED_LINK.test(all)) throw new Error(`markdown link in ${c.id}`)
  }
}
