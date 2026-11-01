/**
 * Slash command, button and autocomplete handlers. Replies to commands are
 * only visible to the person who ran them.
 */
import {
  DiscordAPIError,
  MessageFlags,
  PermissionFlagsBits,
  type AutocompleteInteraction,
  type ButtonInteraction,
  type ChatInputCommandInteraction,
  type Interaction,
} from 'discord.js'
import { ghsaFrom, SEVERITIES, type Severity } from '../scanner/advisories.js'
import { failureReason, type GitHubClient } from '../scanner/http.js'
import { MAX_INTERVAL_MINUTES, MIN_INTERVAL_MINUTES } from '../config.js'
import { repoKey, type Settings } from '../state.js'
import type { Monitor } from '../monitor.js'
import { activeRepos } from '../planner.js'
import { log } from '../log.js'
import {
  ACK_PREFIX,
  COLORS,
  dashboardEmbed,
  esc,
  findingsEmbed,
  joinLines,
  MUTE_PREFIX,
  SEVERITY_LABEL,
  updatedCardButtons,
  updatedCardEmbed,
} from './cards.js'
import { missingSetupPermissions, runSetup } from './setup.js'
import type { OpsCards } from '../cards/ops.js'
import { OPS_ACK_PREFIX, OPS_MUTE_PREFIX, OPS_RESOLVE_PREFIX, OPS_SEVERITY_LABEL, opsCardEdit, rebootLines } from '../cards/render.js'
import type { KeyRing } from '../reports/keys.js'
import { EVENT_RE, SOURCE_RE } from '../reports/protocol.js'

const EPHEMERAL = MessageFlags.Ephemeral
const NO_MENTIONS = { parse: [] as [] }
const REPO_RE = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/
const ADVISORY_RE = /^[A-Za-z0-9][A-Za-z0-9-]{2,63}$/

export interface HandlerDeps {
  monitor: Monitor
  /** null = repo scanning is off. */
  github: GitHubClient | null
  guildId: string
  ops: OpsCards
  keys: KeyRing
  publicUrl: string | null
}

export async function handleInteraction(deps: HandlerDeps, interaction: Interaction): Promise<void> {
  if (!interaction.inGuild() || interaction.guildId !== deps.guildId) {
    if (interaction.isRepliable()) {
      await interaction.reply({ content: 'This bot only works in the server it was set up for.', flags: EPHEMERAL })
    }
    return
  }
  try {
    if (interaction.isAutocomplete()) return await autocomplete(deps, interaction)
    if (interaction.isButton()) return await button(deps, interaction)
    if (interaction.isChatInputCommand() && interaction.commandName === 'nethersec') return await command(deps, interaction)
  } catch (err) {
    log(`An interaction failed: ${err instanceof Error ? err.name : 'unknown'}`)
    console.error(err)
    if (interaction.isRepliable()) {
      const content = 'Something went wrong. Check the bot logs.'
      try {
        if (interaction.deferred || interaction.replied) await interaction.followUp({ content, flags: EPHEMERAL })
        else await interaction.reply({ content, flags: EPHEMERAL })
      } catch {
        // The interaction expired; nothing more to do.
      }
    }
  }
}

function say(interaction: ChatInputCommandInteraction, content: string) {
  return interaction.reply({ content, flags: EPHEMERAL, allowedMentions: NO_MENTIONS })
}

/**
 * Refresh the status board without waiting for it. Discord drops a reply that
 * comes later than 3 seconds, and the board edit can be slow.
 */
function refreshBoard(monitor: Monitor): void {
  monitor.updateDashboard().catch(() => {})
}

function normalizeRepo(raw: string | null): string | null {
  const v = (raw ?? '').trim().replace(/^https:\/\/github\.com\//i, '').replace(/\.git$/i, '').replace(/\/+$/, '')
  return REPO_RE.test(v) ? v : null
}

export function normalizeAdvisoryId(raw: string): string | null {
  const ghsa = ghsaFrom(raw)
  if (ghsa) return ghsa
  const v = raw.trim().toUpperCase()
  return ADVISORY_RE.test(v) ? v : null
}

function settingsText(s: Settings): string {
  const mode = s.repoMode === 'all' ? 'every repo the GitHub token can read' : 'only the repos you add'
  return [
    `**Watching:** ${mode}`,
    `**Alerts for:** ${SEVERITY_LABEL[s.minSeverity]} and above`,
    `**Ping the watcher role on critical alerts:** ${s.pingRole ? 'yes' : 'no'}`,
    `**Ping when only dev dependencies are affected:** ${s.pingDevOnly ? 'yes' : 'no'}`,
    `**Forks:** ${s.includeForks ? 'watched' : 'skipped'} · **Archived repos:** ${s.includeArchived ? 'watched' : 'skipped'}`,
    `**Scan every:** ${s.intervalMinutes} minutes${s.paused ? ' (paused)' : ''}`,
  ].join('\n')
}

async function command(deps: HandlerDeps, interaction: ChatInputCommandInteraction): Promise<void> {
  const { monitor } = deps
  const state = monitor.state
  const group = interaction.options.getSubcommandGroup(false)
  const sub = interaction.options.getSubcommand()

  if (group === 'repos') return reposCommand(deps, interaction, sub)

  switch (sub) {
    case 'setup': {
      const guild = interaction.guild
      if (!guild) return void (await say(interaction, 'Run this in the server.'))
      const missing = missingSetupPermissions(guild)
      if (missing.length) {
        return void (await say(interaction, `I need these server permissions first: ${missing.join(', ')}.`))
      }
      await interaction.deferReply({ flags: EPHEMERAL })
      const isPrivate = interaction.options.getBoolean('private') ?? state.setup?.private ?? true
      const first = !state.setup
      try {
        state.setup = await runSetup(guild, state.setup, isPrivate)
      } catch (err) {
        const why = err instanceof DiscordAPIError ? err.message : 'an unexpected error'
        await interaction.editReply(`Setup did not finish (${why}). Check that my role is above the watcher role and that I have Manage Channels and Manage Roles, then run it again.`)
        return
      }
      await monitor.save()
      refreshBoard(monitor)
      const s = state.setup
      const lines = [
        `Done. Critical alerts go to <#${s.criticalChannelId}>, other alerts to <#${s.alertsChannelId}>, and scan status to <#${s.statusChannelId}>.`,
        s.private
          ? `The channels are private: give people the <@&${s.roleId}> role so they can see them and get pinged on critical alerts.`
          : `Anyone in the server can read the channels. Give people the <@&${s.roleId}> role to get pinged on critical alerts.`,
      ]
      if (first && monitor.scanning) {
        monitor.scanNow()
        lines.push(
          'The first scan is running now. It records what is already open and posts one summary, so you are not flooded with old advisories.',
          'By default it watches every repo the GitHub token can read. Use `/nethersec repos` to change that.',
        )
      } else if (first) {
        lines.push('Repo scanning is off because there is no GitHub token. Set GITHUB_TOKEN and restart the hub to turn it on.')
      }
      if (first) {
        const where = deps.publicUrl ? `${deps.publicUrl}/v1/report` : 'this hub on /v1/report'
        lines.push(`Hosts report to ${where} with a key. Make one on the hub with \`node dist/cli.js key new <source>\`.`)
      }
      await interaction.editReply({ content: lines.join('\n\n'), allowedMentions: NO_MENTIONS })
      return
    }

    case 'status': {
      if (!state.setup) return void (await say(interaction, 'Not set up yet. Run `/nethersec setup` first.'))
      const embed = dashboardEmbed(state, {
        nextRunAt: monitor.nextRunAt,
        running: monitor.running,
        githubLogin: monitor.githubLogin,
        repoScanning: monitor.scanning,
        publicUrl: deps.publicUrl,
      })
      await interaction.reply({ embeds: [embed], flags: EPHEMERAL, allowedMentions: NO_MENTIONS })
      return
    }

    case 'scan': {
      const result = monitor.scanNow()
      const text = {
        started: 'Scanning now. Anything new posts in the alert channels when it finishes.',
        busy: 'A scan is already running.',
        paused: 'Scanning is paused. Use `/nethersec resume` first.',
        'not-set-up': 'Not set up yet. Run `/nethersec setup` first.',
        off: 'Repo scanning is off because there is no GitHub token. Set GITHUB_TOKEN and restart the hub to turn it on.',
      }[result]
      await say(interaction, text)
      return
    }

    case 'findings': {
      if (activeRepos(state.repos).length === 0) return void (await say(interaction, 'Nothing has been scanned yet.'))
      const repoRaw = interaction.options.getString('repo')
      const repo = repoRaw ? normalizeRepo(repoRaw) : null
      if (repoRaw && !repo) return void (await say(interaction, 'Give the repo as owner/name.'))
      const severityRaw = interaction.options.getString('severity')
      const severity = severityRaw && (SEVERITIES as string[]).includes(severityRaw) ? (severityRaw as Severity) : undefined
      const embed = findingsEmbed(state.repos, { repo: repo ?? undefined, minSeverity: severity })
      await interaction.reply({ embeds: [embed], flags: EPHEMERAL, allowedMentions: NO_MENTIONS })
      return
    }

    case 'settings': {
      const s = state.settings
      const min = interaction.options.getString('min_severity')
      const pingCritical = interaction.options.getBoolean('ping_critical')
      const pingDev = interaction.options.getBoolean('ping_dev_only')
      const forks = interaction.options.getBoolean('include_forks')
      const archived = interaction.options.getBoolean('include_archived')
      const interval = interaction.options.getInteger('interval_minutes')
      let changed = false
      if (min && (SEVERITIES as string[]).includes(min)) {
        s.minSeverity = min as Severity
        changed = true
      }
      if (pingCritical !== null) {
        s.pingRole = pingCritical
        changed = true
      }
      if (pingDev !== null) {
        s.pingDevOnly = pingDev
        changed = true
      }
      if (forks !== null) {
        s.includeForks = forks
        changed = true
      }
      if (archived !== null) {
        s.includeArchived = archived
        changed = true
      }
      if (interval !== null) {
        if (interval < MIN_INTERVAL_MINUTES || interval > MAX_INTERVAL_MINUTES) {
          return void (await say(interaction, `The interval must be from ${MIN_INTERVAL_MINUTES} to ${MAX_INTERVAL_MINUTES} minutes.`))
        }
        s.intervalMinutes = interval
        changed = true
        if (!monitor.running) monitor.schedule()
      }
      if (changed) await monitor.save()
      await say(interaction, `${changed ? 'Saved.\n\n' : ''}${settingsText(s)}`)
      if (changed) refreshBoard(monitor)
      return
    }

    case 'mute': {
      const id = normalizeAdvisoryId(interaction.options.getString('advisory', true))
      if (!id) return void (await say(interaction, 'That does not look like an advisory ID. Use one like GHSA-xxxx-xxxx-xxxx or CVE-2024-12345.'))
      const repoRaw = interaction.options.getString('repo')
      const repo = repoRaw ? normalizeRepo(repoRaw) : null
      if (repoRaw && !repo) return void (await say(interaction, 'Give the repo as owner/name.'))
      // Already covered: muted everywhere, or muted for this same repo.
      if (state.mutes.some((m) => m.advisoryId === id && (m.repo === null || (repo !== null && repoKey(m.repo) === repoKey(repo))))) {
        return void (await say(interaction, `${id} is already muted${repo ? ` for ${repo}` : ''}.`))
      }
      state.mutes.push({ advisoryId: id, repo, by: interaction.user.id, at: new Date().toISOString() })
      await monitor.save()
      await say(interaction, `Muted ${id}${repo ? ` for ${repo}` : ' in every repo'}. It still shows in \`/nethersec findings\`. Undo with \`/nethersec unmute\`.`)
      return
    }

    case 'unmute': {
      const id = normalizeAdvisoryId(interaction.options.getString('advisory', true))
      if (!id) return void (await say(interaction, 'That does not look like an advisory ID.'))
      const repoRaw = interaction.options.getString('repo')
      const repo = repoRaw ? normalizeRepo(repoRaw) : null
      // A repo that does not read is refused: read as no repo, it would lift the mute for every repo.
      if (repoRaw && !repo) return void (await say(interaction, 'Give the repo as owner/name. Nothing was unmuted.'))
      const before = state.mutes.length
      state.mutes = state.mutes.filter(
        (m) => !(m.advisoryId === id && (repo ? m.repo !== null && repoKey(m.repo) === repoKey(repo) : m.repo === null)),
      )
      const removed = before - state.mutes.length
      if (!removed) return void (await say(interaction, `${id} was not muted${repo ? ` for ${repo}` : ' for every repo'}.`))
      await monitor.save()
      await say(interaction, `Unmuted ${id}${repo ? ` for ${repo}` : ''}. Alerts for it come back for repos where it is new.`)
      return
    }

    case 'mutes': {
      if (!state.mutes.length && !state.opsMutes.length) return void (await say(interaction, 'Nothing is muted.'))
      const lines = state.mutes.map((m) => `${m.advisoryId} ${m.repo ? `for ${m.repo}` : 'in every repo'} (by <@${m.by}>)`)
      for (const m of state.opsMutes) {
        const [kind, source, event] = m.key.split(':')
        lines.push(`Host check \`${event}\` on ${source} (${kind}, by <@${m.by}>). Undo with \`/nethersec host-unmute source:${source} check:${event} kind:${kind}\`.`)
      }
      await interaction.reply({
        embeds: [{ title: 'Muted', description: joinLines(lines, 4000), color: COLORS.info }],
        flags: EPHEMERAL,
        allowedMentions: NO_MENTIONS,
      })
      return
    }

    case 'pause': {
      state.settings.paused = true
      await monitor.save()
      await say(interaction, 'Paused. No scans run until `/nethersec resume`.')
      refreshBoard(monitor)
      return
    }

    case 'resume': {
      state.settings.paused = false
      await monitor.save()
      if (!monitor.running) monitor.schedule(5_000)
      await say(interaction, monitor.scanning ? 'Resumed. The next scan starts in a few seconds.' : 'Resumed. Repo scanning stays off until a GitHub token is set.')
      refreshBoard(monitor)
      return
    }

    case 'hosts':
    case 'alerts':
    case 'reboots':
    case 'keys':
    case 'host-unmute':
      return hostCommand(deps, interaction, sub)
  }
}

function ago(iso: string): string {
  return `<t:${Math.floor(new Date(iso).getTime() / 1000)}:R>`
}

async function hostCommand(deps: HandlerDeps, interaction: ChatInputCommandInteraction, sub: string): Promise<void> {
  const state = deps.monitor.state
  const reply = (title: string, lines: string[], color: number = COLORS.info) =>
    interaction.reply({ embeds: [{ title, description: joinLines(lines, 4000), color }], flags: EPHEMERAL, allowedMentions: NO_MENTIONS })

  switch (sub) {
    case 'hosts': {
      const hosts = Object.values(state.hosts).sort((a, b) => a.source.localeCompare(b.source))
      if (!hosts.length) return void (await say(interaction, 'No source has reported yet. Make a key on the hub with `node dist/cli.js key new <source>`.'))
      const open = deps.ops.openCards()
      const lines = hosts.map((h) => {
        const n = open.filter((c) => c.source === h.source).length
        return `**${h.source}**: last report ${ago(h.lastReportAt)}, ${n ? `${n} open ${n === 1 ? 'alert' : 'alerts'}` : 'nothing open'}`
      })
      await reply(`Hosts (${hosts.length})`, lines)
      return
    }

    case 'alerts': {
      const kind = interaction.options.getString('kind')
      const source = interaction.options.getString('source')
      const rank = { critical: 0, warning: 1, info: 2 }
      const cards = deps.ops
        .openCards()
        .filter((c) => (!kind || c.kind === kind) && (!source || c.source === source))
        .sort((a, b) => rank[a.severity] - rank[b.severity] || b.updatedAt.localeCompare(a.updatedAt))
      if (!cards.length) return void (await say(interaction, 'Nothing open.'))
      const lines = cards.map((c) => {
        const what = c.kind === 'watch' ? esc(c.title) : `${esc(c.title || c.event || '')} on ${c.source}`
        const flags = [c.reportedFixedAt ? 'reported fixed' : '', c.ackedBy ? 'acknowledged' : '', c.mutedBy ? 'muted' : ''].filter(Boolean)
        return `**${OPS_SEVERITY_LABEL[c.severity]}** [${what}](${deps.ops.link(c)})${flags.length ? ` (${flags.join(', ')})` : ''}`
      })
      await reply(`Open alerts (${cards.length})`, lines, cards[0].severity === 'critical' ? COLORS.critical : COLORS.high)
      return
    }

    case 'reboots': {
      const records = Object.values(state.rebootPending)
      if (!records.length) return void (await say(interaction, 'No box has reported a pending reboot.'))
      await reply(`Pending reboots (${records.length})`, rebootLines(records, Date.now()))
      return
    }

    case 'keys': {
      const keys = await deps.keys.current()
      if (!keys.length) return void (await say(interaction, 'No keys yet. Make one on the hub with `node dist/cli.js key new <source>`.'))
      const bySource = new Map<string, string[]>()
      for (const k of keys) {
        const flag = k.page ? 'page' : k.dmUserId ? 'direct messages' : 'cards'
        bySource.set(k.source, [...(bySource.get(k.source) ?? []), flag])
      }
      const lines = [...bySource.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([s, flags]) => `**${s}**: ${flags.length === 1 ? '1 key' : `${flags.length} keys`} (${[...new Set(flags)].join(', ')})`)
      await reply('Report keys', [...lines, '', 'Manage keys on the hub with `node dist/cli.js key ...`.'])
      return
    }

    case 'host-unmute': {
      const source = interaction.options.getString('source', true).trim()
      const event = interaction.options.getString('check', true).trim()
      const kind = interaction.options.getString('kind') === 'uptime' ? 'uptime' : 'security'
      if (!SOURCE_RE.test(source) || !EVENT_RE.test(event)) return void (await say(interaction, 'Give the source and the check exactly as the box sends them.'))
      await interaction.deferReply({ flags: EPHEMERAL })
      const done = await deps.ops.unmute(kind, source, event)
      await interaction.editReply({
        content: done ? `Unmuted \`${event}\` on ${source} (${kind}).` : `\`${event}\` on ${source} (${kind}) was not muted.`,
        allowedMentions: NO_MENTIONS,
      })
      return
    }
  }
}

async function reposCommand(deps: HandlerDeps, interaction: ChatInputCommandInteraction, sub: string): Promise<void> {
  const { monitor, github } = deps
  const s = monitor.state.settings
  if (!github && sub === 'add') {
    return void (await say(interaction, 'Repo scanning is off because there is no GitHub token. Set GITHUB_TOKEN and restart the hub to turn it on.'))
  }

  switch (sub) {
    case 'list': {
      const watched = activeRepos(monitor.state.repos)
        .map((r) => r.name)
        .sort((a, b) => a.localeCompare(b))
      const lines = [
        s.repoMode === 'all'
          ? 'Mode: **every repo the GitHub token can read**' + (s.includeForks ? '' : ', without forks') + (s.includeArchived ? '' : ', without archived repos') + '.'
          : 'Mode: **only the repos you add**.',
      ]
      if (s.repos.length) lines.push('', `**Added by name (${s.repos.length}):** ${s.repos.join(', ')}`)
      if (s.repoMode === 'all' && s.exclude.length) lines.push('', `**Excluded (${s.exclude.length}):** ${s.exclude.join(', ')}`)
      lines.push('', `**Watched at the last scan (${watched.length}):**`, watched.length ? watched.join(', ') : 'none yet')
      await interaction.reply({
        embeds: [{ title: 'Watched repos', description: joinLines(lines.join('\n').split('\n'), 4000), color: COLORS.info }],
        flags: EPHEMERAL,
        allowedMentions: NO_MENTIONS,
      })
      return
    }

    case 'add': {
      const repo = normalizeRepo(interaction.options.getString('repo', true))
      if (!repo) return void (await say(interaction, 'Give the repo as owner/name.'))
      await interaction.deferReply({ flags: EPHEMERAL })
      let fullName: string
      try {
        fullName = (await github!.getRepo(repo)).fullName
      } catch (err) {
        await interaction.editReply(`I can't read ${repo} with the GitHub token: ${failureReason(err, 'GitHub')}`)
        return
      }
      const k = repoKey(fullName)
      if (!s.repos.some((r) => repoKey(r) === k)) s.repos.push(fullName)
      s.exclude = s.exclude.filter((r) => repoKey(r) !== k)
      await monitor.save()
      await interaction.editReply(
        `Watching ${fullName}. It is read at the next scan: what is open there is recorded and summed up once, then new advisories get alerts.`,
      )
      return
    }

    case 'remove': {
      const repo = normalizeRepo(interaction.options.getString('repo', true))
      if (!repo) return void (await say(interaction, 'Give the repo as owner/name.'))
      const k = repoKey(repo)
      const wasAdded = s.repos.some((r) => repoKey(r) === k)
      s.repos = s.repos.filter((r) => repoKey(r) !== k)
      if (s.repoMode === 'all' && !s.exclude.some((r) => repoKey(r) === k)) s.exclude.push(repo)
      if (!wasAdded && s.repoMode === 'list') return void (await say(interaction, `${repo} is not on the watch list.`))
      await monitor.save()
      await say(interaction, `Stopped watching ${repo}. Its open advisories drop off at the next scan.`)
      return
    }

    case 'mode': {
      const mode = interaction.options.getString('mode', true) === 'list' ? 'list' : 'all'
      s.repoMode = mode
      await monitor.save()
      refreshBoard(monitor)
      if (mode === 'all') {
        await say(interaction, 'Now watching every repo the GitHub token can read (plus any you added by name). Use `/nethersec repos remove` to leave one out.')
      } else {
        await say(
          interaction,
          s.repos.length
            ? `Now watching only the ${s.repos.length} repos you added. Others drop off at the next scan.`
            : 'Now watching only the repos you add, and none are added yet. Add one with `/nethersec repos add`.',
        )
      }
      return
    }
  }
}

function canAck(interaction: ButtonInteraction, roleId: string | null): boolean {
  if (interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild)) return true
  if (!roleId) return false
  const roles = interaction.member?.roles
  if (!roles) return false
  return Array.isArray(roles) ? roles.includes(roleId) : roles.cache.has(roleId)
}

async function opsButton(deps: HandlerDeps, interaction: ButtonInteraction): Promise<void> {
  const id = interaction.customId
  const action = id.startsWith(OPS_ACK_PREFIX) ? 'ack' : id.startsWith(OPS_MUTE_PREFIX) ? 'mute' : 'resolve'
  const cardId = id.slice(id.lastIndexOf(':') + 1)
  const roleId = deps.monitor.state.setup?.roleId ?? null
  const admin = interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild) ?? false
  if (action === 'mute' ? !admin : !canAck(interaction, roleId)) {
    await interaction.reply({
      content: action === 'mute' ? 'Only server admins (Manage Server) can mute a check.' : 'Only admins and the watcher role can do that.',
      flags: EPHEMERAL,
    })
    return
  }
  // Answer Discord now; the card may wait behind a report for the same check.
  await interaction.deferUpdate()
  const result = await deps.ops.press(action, cardId, interaction.user.id)
  if (!result.ok) {
    await interaction.followUp({ content: result.reason, flags: EPHEMERAL, allowedMentions: NO_MENTIONS })
    return
  }
  const edit = opsCardEdit(result.card)
  await interaction.editReply({ embeds: edit.embeds, components: edit.components ?? [], allowedMentions: NO_MENTIONS })
  if (action === 'mute') {
    const c = result.card
    await interaction.followUp({
      content: `Muted \`${c.event}\` on ${c.source}: no new card and no ping for it. Undo with \`/nethersec host-unmute source:${c.source} check:${c.event} kind:${c.kind}\`.`,
      flags: EPHEMERAL,
      allowedMentions: NO_MENTIONS,
    })
  }
}

async function button(deps: HandlerDeps, interaction: ButtonInteraction): Promise<void> {
  const { monitor } = deps
  const state = monitor.state
  const id = interaction.customId
  if (id.startsWith(OPS_ACK_PREFIX) || id.startsWith(OPS_MUTE_PREFIX) || id.startsWith(OPS_RESOLVE_PREFIX)) return opsButton(deps, interaction)
  const isAck = id.startsWith(ACK_PREFIX)
  const isMute = id.startsWith(MUTE_PREFIX)
  if (!isAck && !isMute) return
  const card = state.cards[id.slice((isAck ? ACK_PREFIX : MUTE_PREFIX).length)]
  if (!card) {
    await interaction.reply({ content: 'This alert is no longer tracked.', flags: EPHEMERAL })
    return
  }
  const embed = interaction.message.embeds[0]?.toJSON()

  if (isAck) {
    if (!canAck(interaction, state.setup?.roleId ?? null)) {
      await interaction.reply({ content: 'Only admins and the watcher role can acknowledge alerts.', flags: EPHEMERAL })
      return
    }
    if (card.ackedBy) {
      await interaction.reply({ content: `Already acknowledged by <@${card.ackedBy}>.`, flags: EPHEMERAL, allowedMentions: NO_MENTIONS })
      return
    }
    card.ackedBy = interaction.user.id
    card.ackedAt = new Date().toISOString()
    await monitor.save()
  } else {
    if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild)) {
      await interaction.reply({ content: 'Only server admins (Manage Server) can mute an advisory.', flags: EPHEMERAL })
      return
    }
    if (!state.mutes.some((m) => m.advisoryId === card.advisoryId && m.repo === null)) {
      state.mutes.push({ advisoryId: card.advisoryId, repo: null, by: interaction.user.id, at: new Date().toISOString() })
    }
    card.mutedBy = interaction.user.id
    card.mutedAt = new Date().toISOString()
    await monitor.save()
  }

  if (embed) {
    await interaction.update({
      embeds: [updatedCardEmbed(embed, card)],
      components: updatedCardButtons(embed.url, card),
      allowedMentions: NO_MENTIONS,
    })
  } else {
    await interaction.deferUpdate()
  }
  if (isMute) {
    await interaction.followUp({
      content: `Muted ${card.advisoryId} in every repo. It still shows in \`/nethersec findings\`. Undo with \`/nethersec unmute advisory:${card.advisoryId}\`.`,
      flags: EPHEMERAL,
    })
  }
}

async function autocomplete(deps: HandlerDeps, interaction: AutocompleteInteraction): Promise<void> {
  const { monitor } = deps
  const typed = interaction.options.getFocused().toLowerCase()
  if (interaction.options.getFocused(true).name === 'source') {
    const sources = Object.keys(monitor.state.hosts)
      .filter((s) => s.includes(typed))
      .sort()
      .slice(0, 25)
    await interaction.respond(sources.map((s) => ({ name: s, value: s })))
    return
  }
  const names = new Map<string, string>()
  for (const r of activeRepos(monitor.state.repos)) names.set(repoKey(r.name), r.name)
  for (const r of monitor.state.settings.repos) names.set(repoKey(r), r)
  for (const r of monitor.knownRepos) if (!names.has(repoKey(r))) names.set(repoKey(r), r)
  const matches = [...names.values()]
    // Discord refuses the whole list if one choice is over 100 characters.
    .filter((n) => n.length <= 100 && n.toLowerCase().includes(typed))
    .sort((a, b) => a.localeCompare(b))
    .slice(0, 25)
  await interaction.respond(matches.map((n) => ({ name: n, value: n })))
}
