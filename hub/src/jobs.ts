/**
 * Hourly jobs and saved module state, for the watch modules (watchHost.ts).
 *
 * A job runs about a minute after the hub starts and then every hour. It is
 * skipped while the hub is not set up, never runs twice at once, and an error
 * in it is logged and never stops the bot or the next run.
 */
import type { Store } from './store.js'

export const JOB_INTERVAL_MS = 3_600_000
export const FIRST_RUN_DELAY_MS = 60_000
/** Each job starts this much after the one registered before it, so they do not all run at once. */
const STAGGER_MS = 15_000
export const MAX_JOBS = 32
/** One per watched feed, so it allows the watch's 200 components plus its own few. */
export const MAX_MODULES = 256
export const MAX_MODULE_STATE_BYTES = 512 * 1024
/** All modules together, so state.json stays a size that saves quickly. */
export const MAX_MODULE_TOTAL_BYTES = 16 * 1024 * 1024
const NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/

interface Job {
  name: string
  run: () => Promise<void>
  timer: NodeJS.Timeout | null
  running: Promise<void> | null
  skippedNotice: boolean
}

export interface JobDeps {
  isSetUp: () => boolean
  log: (msg: string) => void
  /** Test seams. */
  setTimer?: (fn: () => void, ms: number) => NodeJS.Timeout
  clearTimer?: (t: NodeJS.Timeout) => void
}

export class HourlyJobs {
  private readonly jobs: Job[] = []
  private started = false
  private stopped = false
  private readonly setTimer: (fn: () => void, ms: number) => NodeJS.Timeout
  private readonly clearTimer: (t: NodeJS.Timeout) => void

  constructor(private readonly deps: JobDeps) {
    this.setTimer = deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms).unref())
    this.clearTimer = deps.clearTimer ?? ((t) => clearTimeout(t))
  }

  register(name: string, run: () => Promise<void>): void {
    if (!NAME_RE.test(name)) throw new TypeError('A job name is 1 to 64 lowercase letters, digits or dashes.')
    if (typeof run !== 'function') throw new TypeError('A job needs a function to run.')
    if (this.jobs.some((j) => j.name === name)) throw new Error(`A job named ${name} is already registered.`)
    if (this.jobs.length >= MAX_JOBS) throw new Error(`At most ${MAX_JOBS} jobs can be registered.`)
    const job: Job = { name, run, timer: null, running: null, skippedNotice: false }
    this.jobs.push(job)
    if (this.started) this.arm(job, FIRST_RUN_DELAY_MS)
  }

  start(): void {
    if (this.started) return
    this.started = true
    this.jobs.forEach((j, i) => this.arm(j, FIRST_RUN_DELAY_MS + i * STAGGER_MS))
  }

  stop(): void {
    this.stopped = true
    for (const j of this.jobs) if (j.timer) this.clearTimer(j.timer)
  }

  names(): string[] {
    return this.jobs.map((j) => j.name)
  }

  private arm(job: Job, ms: number): void {
    if (this.stopped) return
    if (job.timer) this.clearTimer(job.timer)
    job.timer = this.setTimer(() => {
      void this.runJob(job).finally(() => this.arm(job, JOB_INTERVAL_MS))
    }, ms)
  }

  /** Run one job now (also used by tests). Resolves when it is done; never rejects. */
  runNow(name: string): Promise<void> {
    const job = this.jobs.find((j) => j.name === name)
    return job ? this.runJob(job) : Promise.resolve()
  }

  private runJob(job: Job): Promise<void> {
    if (job.running) return job.running
    if (!this.deps.isSetUp()) {
      if (!job.skippedNotice) this.deps.log(`Job ${job.name} waits until the hub is set up.`)
      job.skippedNotice = true
      return Promise.resolve()
    }
    job.skippedNotice = false
    const run = (async () => {
      try {
        await job.run()
      } catch (err) {
        this.deps.log(`Job ${job.name} failed: ${err instanceof Error ? err.name : 'unknown error'}`)
        console.error(err)
      }
    })()
    job.running = run.finally(() => {
      job.running = null
    })
    return job.running
  }

  /** True once no job is running, or false after `timeoutMs`. */
  async whenIdle(timeoutMs: number): Promise<boolean> {
    const running = this.jobs.map((j) => j.running).filter((p): p is Promise<void> => !!p)
    if (!running.length) return true
    let timer: NodeJS.Timeout | undefined
    const timedOut = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), timeoutMs)
    })
    const idle = await Promise.race([Promise.all(running).then(() => true as const), timedOut])
    clearTimeout(timer)
    return idle
  }
}

/** A module's saved state, as a copy (changing it changes nothing until it is saved). undefined when none. */
export function loadModuleState(store: Store, name: string): unknown {
  if (!NAME_RE.test(name)) throw new TypeError('A module name is 1 to 64 lowercase letters, digits or dashes.')
  const v = store.state.modules[name]
  return v === undefined ? undefined : structuredClone(v)
}

/** Save a module's state. Rejects when it is not JSON or over MAX_MODULE_STATE_BYTES. */
export async function saveModuleState(store: Store, name: string, value: unknown): Promise<void> {
  if (!NAME_RE.test(name)) throw new TypeError('A module name is 1 to 64 lowercase letters, digits or dashes.')
  let json: string | undefined
  try {
    json = JSON.stringify(value)
  } catch {
    throw new TypeError(`The state of module ${name} cannot be saved as JSON.`)
  }
  if (json === undefined) throw new TypeError(`The state of module ${name} cannot be saved as JSON.`)
  const bytes = Buffer.byteLength(json)
  if (bytes > MAX_MODULE_STATE_BYTES) {
    throw new RangeError(`The state of module ${name} is ${bytes} bytes, over the ${MAX_MODULE_STATE_BYTES} byte cap.`)
  }
  const modules = store.state.modules
  if (!(name in modules) && Object.keys(modules).length >= MAX_MODULES) throw new Error(`At most ${MAX_MODULES} modules can save state.`)
  const sizes = moduleSizes(modules)
  let total = bytes
  for (const [other, size] of sizes) if (other !== name) total += size
  if (total > MAX_MODULE_TOTAL_BYTES) {
    throw new RangeError(`Saving module ${name} would bring all module state to ${total} bytes, over the ${MAX_MODULE_TOTAL_BYTES} byte cap.`)
  }
  modules[name] = JSON.parse(json)
  sizes.set(name, bytes)
  await store.save()
}

/** Saved size of each module, worked out once per state object and kept current by saveModuleState. */
const sizeCache = new WeakMap<object, Map<string, number>>()

function moduleSizes(modules: Record<string, unknown>): Map<string, number> {
  let sizes = sizeCache.get(modules)
  if (!sizes) {
    sizes = new Map()
    for (const [name, value] of Object.entries(modules)) sizes.set(name, Buffer.byteLength(JSON.stringify(value) ?? ''))
    sizeCache.set(modules, sizes)
  }
  return sizes
}
