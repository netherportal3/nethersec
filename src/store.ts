/**
 * Saves the state as one JSON file in the data folder. A save writes a temp
 * file and renames it over the old one, so a crash mid-write never leaves a
 * half-written file, and the previous copy is kept as state.json.bak.
 */
import { copyFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { normalizeState, type State, emptyState } from './state.js'

export class Store {
  private queue: Promise<void> = Promise.resolve()

  private constructor(
    public state: State,
    private readonly file: string,
  ) {}

  static async open(dataDir: string, intervalMinutes: number): Promise<Store> {
    await mkdir(dataDir, { recursive: true })
    const file = path.join(dataDir, 'state.json')
    const main = await readJson(file)
    if (main.kind === 'ok') return new Store(normalizeState(main.value, intervalMinutes), file)
    if (main.kind === 'missing') return new Store(emptyState(intervalMinutes), file)
    // The main file is damaged: fall back to the last good copy rather than starting over.
    const backup = await readJson(`${file}.bak`)
    if (backup.kind === 'ok') {
      console.warn(`[store] ${file} could not be read; using the backup copy.`)
      return new Store(normalizeState(backup.value, intervalMinutes), file)
    }
    throw new Error(
      `${file} could not be read and there is no good backup. Fix or delete the file to start fresh (you will need to run /cve setup again).`,
    )
  }

  /** Save the current state. Saves run one at a time, in order. */
  save(): Promise<void> {
    const data = JSON.stringify(this.state, null, 2)
    const run = async () => {
      const tmp = `${this.file}.tmp`
      await writeFile(tmp, data, 'utf8')
      await copyFile(this.file, `${this.file}.bak`).catch(() => {})
      await rename(tmp, this.file)
    }
    const next = this.queue.then(run, run)
    this.queue = next.catch(() => {})
    return next
  }
}

async function readJson(file: string): Promise<{ kind: 'ok'; value: unknown } | { kind: 'missing' } | { kind: 'bad' }> {
  let text: string
  try {
    text = await readFile(file, 'utf8')
  } catch (err: any) {
    return err?.code === 'ENOENT' ? { kind: 'missing' } : { kind: 'bad' }
  }
  try {
    return { kind: 'ok', value: JSON.parse(text) }
  } catch {
    return { kind: 'bad' }
  }
}
