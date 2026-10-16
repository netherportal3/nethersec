/**
 * Runs scans on a timer and turns each plan into Discord messages and saved
 * state. The planner decides; this file only does the I/O.
 *
 * A card that fails to post is not recorded, so its findings come back as new
 * on the next scan and get another try. Everything else that fails to post is
 * logged and noted on the status board.
 */
import { randomBytes } from 'node:crypto'
import type { Client, Message, SendableChannels } from 'discord.js'
import { activeRepos, countOpen, planScan, severityAtLeast, type AlertGroup } from './planner.js'
import { failureReason, MAX_REPO_PAGES, type FetchLike, type GitHubClient } from './scanner/http.js'
import { resolveTargets, runScan, ScanCache, type RepoScan } from './scanner/scan.js'
import { repoKey, type CardState, type RepoState, type RunSummary } from './state.js'
import type { Store } from './store.js'
import {
  alertCard,
  baselineMessage,
  dashboardEmbed,
  dashboardPayload,
  fixedMessage,
  noticeMessage,
  overflowMessage,
  scanFailedMessage,
  unreadableMessage,
  updatedCardButtons,
  updatedCardEmbed,
  COLORS,
  type Payload,
} from './discord/cards.js'
import { log } from './log.js'

/** Scans in a row that fail before reading any repo before the status channel hears about it. */
const FAIL_NOTICE_RUNS = 2
/** How long a fully fixed card stays in state (and can still be updated). */
const FIXED_CARD_TTL_MS = 30 * 24 * 60 * 60 * 1000
/** Any card older than this is forgotten. Its message stays in Discord. */
const CARD_TTL_MS = 365 * 24 * 60 * 60 * 1000
const FIRST_RUN_DELAY_MS = 15_000

export interface MonitorDeps {
  client: Client
  store: Store
  github: GitHubClient
  fetchImpl?: FetchLike
  now?: () => Date
}

export class Monitor {
  running = false
  nextRunAt: string | null = null
  githubLogin: string | undefined
  /** Every repo the token could read at the last scan, for autocomplete. */
  knownRepos: string[] = []
  private timer: NodeJS.Timeout | null = null
  private stopped = false
  private current: Promise<void> | null = null
  private dashboardQueue: Promise<void> = Promise.resolve()
  private readonly cache = new ScanCache()
  private readonly fetchImpl: FetchLike
  private readonly now: () => Date

  constructor(private readonly deps: MonitorDeps) {
    this.fetchImpl = deps.fetchImpl ?? ((input, init) => fetch(input, init))
    this.now = deps.now ?? (() => new Date())
  }

  get state() {
    return this.deps.store.state
  }

  save(): Promise<void> {
    return this.deps.store.save()
  }

  start(): void {
    this.stopped = false
    this.schedule(FIRST_RUN_DELAY_MS)
  }

  stop(): void {
    this.stopped = true
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
  }

  /** Plan the next scan `delayMs` from now (default: the configured interval). */
  schedule(delayMs?: number): void {
    if (this.stopped) return
    if (this.timer) clearTimeout(this.timer)
    const ms = delayMs ?? this.state.settings.intervalMinutes * 60_000
    this.nextRunAt = new Date(this.now().getTime() + ms).toISOString()
    this.timer = setTimeout(() => void this.run(), ms)
    this.timer.unref?.()
  }

  /** Start a scan now unless one is running. */
  scanNow(): 'started' | 'busy' | 'paused' | 'not-set-up' {
    if (!this.state.setup) return 'not-set-up'
    if (this.state.settings.paused) return 'paused'
    if (this.running) return 'busy'
    void this.run()
    return 'started'
  }

  /** One scan, then the next one is scheduled. Skips when one is already running. */
  run(): Promise<void> {
    if (this.running) return Promise.resolve()
    this.running = true
    const current: Promise<void> = this.runOnce().finally(() => {
      if (this.current === current) this.current = null
    })
    this.current = current
    return current
  }

  /**
   * Wait for the running scan to finish, at most `timeoutMs`. True when no scan
   * is running anymore. Used on shutdown, so a scan that is posting saves what
   * it posted and a restart does not post it again.
   */
  async whenIdle(timeoutMs: number): Promise<boolean> {
    const current = this.current
    if (!current) return true
    let timer: NodeJS.Timeout | undefined
    const timedOut = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), timeoutMs)
    })
    const idle = await Promise.race([current.then(() => true as const, () => true as const), timedOut])
    clearTimeout(timer)
    return idle
  }

  private async runOnce(): Promise<void> {
    try {
      if (!this.state.setup) {
        log('Not set up yet. Run /cve setup in your server to start scanning.')
        return
      }
      if (this.state.settings.paused) return
      await this.scanOnce()
    } catch (err) {
      log(`Scan stopped by an unexpected error: ${err instanceof Error ? err.name : 'unknown'}`)
      console.error(err)
    } finally {
      this.running = false
      this.schedule()
      if (!this.stopped) await this.updateDashboard().catch(() => {})
    }
  }

  private async scanOnce(): Promise<void> {
    const state = this.state
    const setup = state.setup!
    const settings = state.settings
    const github = this.deps.github
    const startedAt = this.now().toISOString()
    github.resetStats()
    log('Scan started.')

    let targets
    try {
      const who = await github.whoami()
      this.githubLogin = who.login
      targets = await resolveTargets(github, {
        mode: settings.repoMode,
        repos: settings.repos,
        exclude: settings.exclude,
        includeForks: settings.includeForks,
        includeArchived: settings.includeArchived,
      })
      if (who.publicOnly && !state.lastRun) {
        await this.post(setup.statusChannelId, noticeMessage('Public repos only', [
          'The GitHub token is a classic token without the `repo` scope, so private repos are not visible to it. Give it the `repo` scope, or use a fine-grained token with read access to Contents, to watch private repos.',
        ]))
      }
    } catch (err) {
      const reason = failureReason(err, 'GitHub')
      log(`Scan failed before reading any repo: ${reason}`)
      state.failStreak++
      if (state.failStreak >= FAIL_NOTICE_RUNS && !state.failNotified) {
        if (await this.post(setup.statusChannelId, scanFailedMessage(reason))) state.failNotified = true
      }
      state.lastRun = {
        startedAt,
        finishedAt: this.now().toISOString(),
        repos: 0,
        readable: 0,
        unreadable: [],
        notReached: 0,
        newAlerts: 0,
        fixed: 0,
        errors: [reason],
      }
      await this.save()
      return
    }
    if (state.failNotified) {
      await this.post(setup.statusChannelId, noticeMessage('Scans work again', ['GitHub can be read again.'], COLORS.fixed))
    }
    state.failStreak = 0
    state.failNotified = false
    this.knownRepos = targets.all.map((r) => r.fullName)

    const scan = await runScan({ github, fetchImpl: this.fetchImpl, cache: this.cache, targets: targets.targets })
    // Stopping for a restart: post nothing and save nothing, so the next start
    // runs this scan again instead of posting cards this one never recorded.
    if (this.stopped) {
      log('Stopping: this scan is dropped and runs again after the restart.')
      return
    }
    const unreadableTargets: RepoScan[] = targets.unreadable.map((u) => ({
      repo: u.repo,
      status: 'unreadable',
      reason: u.reason,
      lockfiles: [],
      skipped: [],
      treeTruncated: false,
      findings: [],
    }))
    scan.repos.push(...unreadableTargets)
    if (targets.listCapped) {
      const max = MAX_REPO_PAGES * 100
      log(`The GitHub token can read more than ${max} repos; only the first ${max} by name are watched.`)
      scan.errors.push(`The GitHub token can read more than ${max} repos, so only the first ${max} by name are watched. Use /cve repos mode to watch only the ones you add.`)
      // Repos past the end of the list are unknown this scan, not gone.
      const seen = new Set(scan.repos.map((r) => repoKey(r.repo)))
      const excluded = new Set(settings.exclude.map(repoKey))
      for (const r of activeRepos(state.repos)) {
        const k = repoKey(r.name)
        if (seen.has(k) || excluded.has(k)) continue
        scan.repos.push({ repo: r.name, status: 'not-reached', reason: 'Past the end of the repo list.', lockfiles: [], skipped: [], treeTruncated: false, findings: [] })
      }
    }
    if (targets.ssoPartial) scan.errors.push('Some organization repos are hidden because the token is not authorized for their SSO.')
    for (const r of scan.repos) if (r.treeTruncated) scan.errors.push(`${r.repo} is too big to list in full; some lockfiles may be missed.`)

    const now = this.now().toISOString()
    const plan = planScan({ scan, repos: state.repos, settings, mutes: state.mutes, now })
    const errors = [...scan.errors]

    // New advisories: one card each.
    let posted = 0
    for (const g of plan.alerts) {
      const ok = await this.postAlert(g, now, plan.nextRepos)
      if (ok) posted++
      else errors.push(`Could not post the alert for ${g.advisoryId}; it will be tried again.`)
    }
    if (plan.overflow.length) {
      const ok = await this.post(setup.alertsChannelId, overflowMessage(plan.overflow))
      if (!ok) for (const g of plan.overflow) this.forget(g, plan.nextRepos)
    }

    // Fixed advisories: update their cards, and say so once.
    const touched = new Set<string>()
    for (const item of plan.fixed) {
      const card = item.finding.cardId ? state.cards[item.finding.cardId] : undefined
      if (!card || !(item.repo in card.repos)) continue
      card.repos[item.repo] = 'fixed'
      touched.add(card.id)
    }
    for (const id of touched) {
      const card = state.cards[id]
      if (Object.values(card.repos).every((s) => s === 'fixed')) card.resolvedAt = now
      await this.refreshCard(card)
    }
    const worthSaying = plan.fixed.filter((i) => i.finding.malware || severityAtLeast(i.finding.severity, settings.minSeverity))
    if (worthSaying.length) await this.post(setup.statusChannelId, fixedMessage(worthSaying))

    if (plan.baselined.length) await this.post(setup.statusChannelId, baselineMessage(plan.baselined, settings.minSeverity))
    if (plan.unreadableNotices.length) await this.post(setup.statusChannelId, unreadableMessage(plan.unreadableNotices))
    if (plan.recovered.length) {
      await this.post(setup.statusChannelId, noticeMessage('Readable again', plan.recovered.map((r) => `**${r}** can be read again.`), COLORS.fixed))
    }
    if (plan.dropped.length) {
      await this.post(
        setup.statusChannelId,
        noticeMessage('No longer watching', [
          ...plan.dropped.map((r) => `**${r}**`),
          '',
          'These were removed from the watch list, or the GitHub token can no longer see them.',
        ], COLORS.info),
      )
    }

    state.repos = plan.nextRepos
    const readable = scan.repos.filter((r) => r.status === 'ok').length
    const summary: RunSummary = {
      startedAt,
      finishedAt: this.now().toISOString(),
      repos: scan.repos.length,
      readable,
      unreadable: scan.repos.filter((r) => r.status === 'unreadable').map((r) => ({ repo: r.repo, reason: r.reason ?? 'Unknown reason.' })),
      notReached: scan.repos.filter((r) => r.status === 'not-reached').length,
      newAlerts: posted,
      fixed: plan.fixed.length,
      errors: errors.slice(0, 10),
    }
    state.lastRun = summary
    this.pruneCards()
    await this.save()
    const open = countOpen(state.repos)
    log(
      `Scan done: ${readable}/${scan.repos.length} repos read, ${posted} new alerts, ${plan.fixed.length} fixed, open critical ${open.critical} high ${open.high}.`,
    )
  }

  /** Post one alert card and record it. False when it could not be posted (its findings are then forgotten). */
  private async postAlert(g: AlertGroup, now: string, nextRepos: Record<string, RepoState>): Promise<boolean> {
    const setup = this.state.setup!
    const channelId = g.channel === 'critical' ? setup.criticalChannelId : setup.alertsChannelId
    let id = randomBytes(5).toString('hex')
    while (this.state.cards[id]) id = randomBytes(5).toString('hex')
    const msg = await this.send(channelId, alertCard(g, { cardId: id, roleId: setup.roleId, now }))
    if (!msg) {
      this.forget(g, nextRepos)
      return false
    }
    const card: CardState = {
      id,
      channelId,
      messageId: msg.id,
      advisoryId: g.advisoryId,
      packageName: g.packageName,
      severity: g.severity,
      repos: Object.fromEntries(g.members.map((m) => [m.repo, 'open' as const])),
      createdAt: now,
    }
    this.state.cards[id] = card
    for (const m of g.members) {
      const f = nextRepos[repoKey(m.repo)]?.findings[m.key]
      if (f) f.cardId = id
    }
    return true
  }

  /** Drop a group's findings from the next state, so the next scan sees them as new again. */
  private forget(g: AlertGroup, nextRepos: Record<string, RepoState>): void {
    for (const m of g.members) delete nextRepos[repoKey(m.repo)]?.findings[m.key]
  }

  /** Re-render a card's message from its state. Best effort. */
  async refreshCard(card: CardState): Promise<void> {
    try {
      const channel = await this.deps.client.channels.fetch(card.channelId)
      if (!channel?.isTextBased()) return
      const msg = await channel.messages.fetch(card.messageId)
      const embed = msg.embeds[0]?.toJSON()
      if (!embed) return
      await msg.edit({
        embeds: [updatedCardEmbed(embed, card)],
        components: updatedCardButtons(embed.url, card),
        allowedMentions: { parse: [] },
      })
    } catch (err) {
      log(`Could not update the card for ${card.advisoryId}: ${err instanceof Error ? err.name : 'unknown'}`)
    }
  }

  private pruneCards(): void {
    const now = this.now().getTime()
    for (const [id, card] of Object.entries(this.state.cards)) {
      const fixedFor = card.resolvedAt ? now - new Date(card.resolvedAt).getTime() : 0
      const age = now - new Date(card.createdAt).getTime()
      if (fixedFor > FIXED_CARD_TTL_MS || age > CARD_TTL_MS) delete this.state.cards[id]
    }
  }

  private async channel(channelId: string): Promise<SendableChannels | null> {
    try {
      const channel = await this.deps.client.channels.fetch(channelId)
      return channel && channel.isSendable() ? channel : null
    } catch {
      return null
    }
  }

  private async send(channelId: string, payload: Payload): Promise<Message | null> {
    const channel = await this.channel(channelId)
    if (!channel) {
      log(`Channel ${channelId} is missing or the bot cannot post there. Run /cve setup again to repair the channels.`)
      return null
    }
    try {
      return await channel.send(payload)
    } catch (err) {
      log(`Could not post a message: ${err instanceof Error ? err.name : 'unknown'}`)
      return null
    }
  }

  async post(channelId: string, payload: Payload): Promise<boolean> {
    return (await this.send(channelId, payload)) !== null
  }

  /**
   * Edit the status board in place, or post a new one when it is gone. Updates
   * run one at a time, so two at once never post two boards.
   */
  updateDashboard(): Promise<void> {
    const next = this.dashboardQueue.then(() => this.renderDashboard())
    this.dashboardQueue = next.catch(() => {})
    return next
  }

  private async renderDashboard(): Promise<void> {
    const setup = this.state.setup
    if (!setup) return
    const payload = dashboardPayload(dashboardEmbed(this.state, { nextRunAt: this.nextRunAt, running: this.running, githubLogin: this.githubLogin }))
    const channel = await this.channel(setup.statusChannelId)
    if (!channel) return
    if (setup.dashboardMessageId) {
      try {
        const msg = await channel.messages.fetch(setup.dashboardMessageId)
        await msg.edit(payload)
        return
      } catch {
        // Deleted: post a fresh one below.
      }
    }
    try {
      const msg = await channel.send(payload)
      setup.dashboardMessageId = msg.id
      await this.save()
    } catch (err) {
      log(`Could not post the status board: ${err instanceof Error ? err.name : 'unknown'}`)
    }
  }
}
