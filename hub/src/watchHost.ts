/**
 * What the hub gives the watch modules (hub/src/watch/). The modules code
 * against these shapes; index.ts builds one WatchHost and hands it to them in
 * one call. Every member is a plain function, so it can be destructured.
 *
 *   cards.upsert(card)        create a card, or edit the open one with that id in
 *                             place; an unchanged card is not touched. `ping` is
 *                             honored only for critical (and on an open card only
 *                             when it rose to critical). Rejects when it could not
 *                             be posted; try again on the next run.
 *   cards.close(id, note)     close the open card with that id; a no-op when none.
 *                             A person can also Resolve a watch card; a later
 *                             upsert of the same id then opens a new one.
 *   cards.reportFixed(id, note)
 *                             add the note to the open card and leave it open
 *                             for a person to Resolve: for a fix only the boxes
 *                             report. A no-op when none is open; the next upsert
 *                             takes the note off.
 *   closeAcknowledged(match, ms, note)
 *                             close the open watch cards a person acknowledged
 *                             at least `ms` ago whose id `match` accepts (a few
 *                             per call); resolves to how many closed.
 *   listContainerPackages()   the stored container package lists (copies).
 *   registerHourlyJob(n, fn)  run fn about a minute after start, then hourly;
 *                             errors are logged and never stop the bot.
 *   loadModuleState(n)        a module's saved state (a copy), or undefined.
 *   saveModuleState(n, v)     save it (JSON, at most 512 kB per module).
 *   log(message)              one line in the hub's log.
 *
 * Watch cards go where their severity goes: critical to the critical channel,
 * warning to the alerts channel, info to the status channel. The title is shown
 * as plain text (at most 240 characters); the body as Discord markdown (at most
 * 4,000), so escape outside text in it (esc() in watch/util.ts). A mention
 * in a card never pings; only `ping` can.
 */
import type { CardSink, OpsCards, WatchCard } from './cards/ops.js'
import { loadModuleState, saveModuleState, type HourlyJobs } from './jobs.js'
import type { ContainerPackagesRecord } from './state.js'
import type { Store } from './store.js'

export type { CardSink, WatchCard, ContainerPackagesRecord }

export interface WatchHost {
  cards: CardSink
  closeAcknowledged(match: (id: string) => boolean, olderThanMs: number, note: string): Promise<number>
  listContainerPackages(): ContainerPackagesRecord[]
  registerHourlyJob(name: string, run: () => Promise<void>): void
  loadModuleState(name: string): unknown
  saveModuleState(name: string, value: unknown): Promise<void>
  log(message: string): void
}

export function createWatchHost(deps: { ops: OpsCards; store: Store; jobs: HourlyJobs; log: (msg: string) => void }): WatchHost {
  const { ops, store, jobs, log } = deps
  return {
    cards: {
      upsert: (card: WatchCard) => ops.upsert(card),
      close: (id: string, note: string) => ops.close(id, note),
      reportFixed: (id: string, note: string) => ops.reportFixed(id, note),
    },
    closeAcknowledged: (match, olderThanMs, note) => ops.closeAcknowledged(match, olderThanMs, note),
    listContainerPackages: () => structuredClone(Object.values(store.state.containers)),
    registerHourlyJob: (name, run) => jobs.register(name, run),
    loadModuleState: (name) => loadModuleState(store, name),
    saveModuleState: (name, value) => saveModuleState(store, name, value),
    log: (message) => log(String(message).slice(0, 500)),
  }
}
