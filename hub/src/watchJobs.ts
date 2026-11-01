/**
 * Runs the watch modules (src/watch) as two hourly jobs on the hub.
 *
 * watch.json is read again at the start of every run, so an edit takes effect
 * on the next run with no restart. A file that cannot be used turns both jobs
 * off for that run and opens one card that says so, because a watch that has
 * silently stopped would look the same as one that found nothing. The card
 * closes on the first run that reads the file cleanly, and opens again on the
 * next run if a person resolves it while the file is still wrong.
 *
 * After each advisory run, advisory and KEV cards a person acknowledged at least
 * advisoryCards.closeAcknowledgedAfterDays ago close (0 turns that off).
 */
import path from 'node:path'
import { createAdvisoryWatch, createContainerCheck, isAdvisoryNoticeId, loadWatchConfig, WatchConfigError, type WatchConfig, type WatchDeps } from './watch/index.js'
import type { WatchHost } from './watchHost.js'

export const WATCH_CONFIG_FILE = 'watch.json'
export const WATCH_CONFIG_CARD_ID = 'watch-config'
export const ADVISORY_JOB = 'advisory-watch'
export const CONTAINER_JOB = 'container-check'
const DAY_MS = 86_400_000

export interface WatchJobOptions {
  dataDir: string
  githubToken?: string
  fetch?: typeof fetch
  now?: () => number
  /** Test seam: how the config is read. */
  readConfig?: (file: string) => WatchConfig
}

export function registerWatchJobs(host: WatchHost, opts: WatchJobOptions): void {
  const file = path.join(opts.dataDir, WATCH_CONFIG_FILE)
  const readConfig = opts.readConfig ?? loadWatchConfig
  const deps: WatchDeps = {
    cards: host.cards,
    fetch: opts.fetch ?? globalThis.fetch,
    now: opts.now ?? Date.now,
    loadState: host.loadModuleState,
    saveState: host.saveModuleState,
    listContainerPackages: host.listContainerPackages,
    log: host.log,
    ...(opts.githubToken ? { githubToken: opts.githubToken } : {}),
  }

  /** The config for this run, or null when the file cannot be used (the card is then open). */
  const configForRun = async (): Promise<WatchConfig | null> => {
    let cfg: WatchConfig
    try {
      cfg = readConfig(file)
    } catch (err) {
      const problems = err instanceof WatchConfigError ? err.errors : [err instanceof Error ? err.message : 'it could not be read']
      host.log(`${WATCH_CONFIG_FILE} cannot be used, so the advisory watch and the container check are off until it is fixed: ${problems.join('; ')}`)
      await host.cards
        .upsert({
          id: WATCH_CONFIG_CARD_ID,
          severity: 'warning',
          ping: false,
          title: `${WATCH_CONFIG_FILE} has a problem, so the advisory watch and container check are off`,
          body: [
            `Fix ${WATCH_CONFIG_FILE} in the data folder. Both checks start again on the next hourly run after it reads cleanly. If you resolve this card before that, it opens again on the next run.`,
            '',
            ...problems.slice(0, 20).map((p) => `- ${p}`),
          ].join('\n'),
        })
        .catch((e) => host.log(`Could not post the ${WATCH_CONFIG_FILE} card: ${e instanceof Error ? e.message : 'unknown error'}`))
      return null
    }
    await host.cards.close(WATCH_CONFIG_CARD_ID, `${WATCH_CONFIG_FILE} reads cleanly again.`).catch(() => {})
    return cfg
  }

  host.registerHourlyJob(ADVISORY_JOB, async () => {
    const cfg = await configForRun()
    if (!cfg) return
    const report = await createAdvisoryWatch(cfg, deps).run()
    if (!report.ok) host.log(`Advisory watch finished with problems: ${report.errors.slice(0, 5).join('; ')}`)
    const days = cfg.advisoryCards.closeAcknowledgedAfterDays
    if (days > 0) {
      const note = `Closed by itself: acknowledged at least ${days} days ago (advisoryCards in ${WATCH_CONFIG_FILE}). The watch never checked whether the fix is installed.`
      const closed = await host.closeAcknowledged(isAdvisoryNoticeId, days * DAY_MS, note).catch(() => {
        host.log('Could not close the acknowledged advisory cards this run; the next run tries again.')
        return 0
      })
      if (closed) host.log(`Closed ${closed} advisory ${closed === 1 ? 'card' : 'cards'} acknowledged at least ${days} days ago.`)
    }
  })

  host.registerHourlyJob(CONTAINER_JOB, async () => {
    const cfg = await configForRun()
    if (!cfg || !cfg.containers.enabled) return
    const report = await createContainerCheck(cfg, deps).run()
    if (!report.ok) host.log(`Container check finished with problems: ${report.errors.slice(0, 5).join('; ')}`)
  })
}
