/**
 * The hub's hourly watch: the advisory watch (advisories.ts, kernel.ts) and the
 * container check (containers.ts). The hub loads watch.json once with
 * loadWatchConfig, builds both with its CardSink and WatchDeps, and calls run().
 * Neither run() throws.
 */
export { createAdvisoryWatch, isAdvisoryNoticeId } from './advisories.js'
export { createContainerCheck } from './containers.js'
export { defaultWatchConfig, loadWatchConfig, parseWatchConfig, WatchConfigError } from './config.js'
export type { ComponentFeed, KernelConfig, KevMatcher, UbuntuRelease, WatchComponent, WatchConfig } from './config.js'
export type {
  AdvisoryRunReport,
  CardSink,
  ContainerPackagesRecord,
  ContainerRunReport,
  ContainerSeverityCounts,
  RunReport,
  WatchCard,
  WatchDeps,
} from './types.js'
