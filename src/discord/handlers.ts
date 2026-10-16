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
import { log } from '../log.js'
import {
  ACK_PREFIX,
  COLORS,
  dashboardEmbed,
  findingsEmbed,
  joinLines,
  MUTE_PREFIX,
  SEVERITY_LABEL,
  updatedCardButtons,
  updatedCardEmbed,
} from './cards.js'
import { missingSetupPermissions, runSetup } from './setup.js'

const EPHEMERAL = MessageFlags.Ephemeral
const NO_MENTIONS = { parse: [] as [] }
const REPO_RE = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/
const ADVISORY_RE = /^[A-Za-z0-9][A-Za-z0-9-]{2,63}$/

export interface HandlerDeps {
  monitor: Monitor
  github: GitHubClient
  guildId: string
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
    if (interaction.isChatInputCommand() && interaction.commandName === 'cve') return await command(deps, interaction)
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
        await interaction.editReply(`Setup did not finish (${why}). Check that my role is above the CVE Watch role and that I have Manage Channels and Manage Roles, then run it again.`)
        return
      }
      await monitor.save()
      await monitor.updateDashboard()
      const s = state.setup
      const lines = [
        `Done. Critical alerts go to <#${s.criticalChannelId}>, other alerts to <#${s.alertsChannelId}>, and scan status to <#${s.statusChannelId}>.`,
        s.private
          ? `The channels are private: give people the <@&${s.roleId}> role so they can see them and get pinged on critical alerts.`
          : `Anyone in the server can read the channels. Give people the <@&${s.roleId}> role to get pinged on critical alerts.`,
      ]
      if (first) {
        monitor.scanNow()
        lines.push(
          'The first scan is running now. It records what is already open and posts one summary, so you are not flooded with old advisories.',
          'By default it watches every repo the GitHub token can read. Use `/cve repos` to change that.',
        )
      }
      await interaction.editReply({ content: lines.join('\n\n'), allowedMentions: NO_MENTIONS })
      return
    }

    case 'status': {
      if (!state.setup) return void (await say(interaction, 'Not set up yet. Run `/cve setup` first.'))
      const embed = dashboardEmbed(state, { nextRunAt: monitor.nextRunAt, running: monitor.running, githubLogin: monitor.githubLogin })
      await interaction.reply({ embeds: [embed], flags: EPHEMERAL, allowedMentions: NO_MENTIONS })
      return
    }

    case 'scan': {
      const result = monitor.scanNow()
      const text = {
        started: 'Scanning now. Anything new posts in the alert channels when it finishes.',
        busy: 'A scan is already running.',
        paused: 'Scanning is paused. Use `/cve resume` first.',
        'not-set-up': 'Not set up yet. Run `/cve setup` first.',
      }[result]
      await say(interaction, text)
      return
    }

    case 'findings': {
      if (Object.keys(state.repos).length === 0) return void (await say(interaction, 'Nothing has been scanned yet.'))
      const repo = interaction.options.getString('repo') ?? undefined
      const severity = (interaction.options.getString('severity') ?? undefined) as Severity | undefined
      const embed = findingsEmbed(state.repos, { repo, minSeverity: severity })
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
      if (changed) {
        await monitor.save()
        await monitor.updateDashboard()
      }
      await say(interaction, `${changed ? 'Saved.\n\n' : ''}${settingsText(s)}`)
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
      await say(interaction, `Muted ${id}${repo ? ` for ${repo}` : ' in every repo'}. It still shows in \`/cve findings\`. Undo with \`/cve unmute\`.`)
      return
    }

    case 'unmute': {
      const id = normalizeAdvisoryId(interaction.options.getString('advisory', true))
      if (!id) return void (await say(interaction, 'That does not look like an advisory ID.'))
      const repoRaw = interaction.options.getString('repo')
      const repo = repoRaw ? normalizeRepo(repoRaw) : null
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
      if (!state.mutes.length) return void (await say(interaction, 'Nothing is muted.'))
      const lines = state.mutes.map((m) => `${m.advisoryId} ${m.repo ? `for ${m.repo}` : 'in every repo'} (by <@${m.by}>)`)
      await interaction.reply({
        embeds: [{ title: 'Muted advisories', description: joinLines(lines, 4000), color: COLORS.info }],
        flags: EPHEMERAL,
        allowedMentions: NO_MENTIONS,
      })
      return
    }

    case 'pause': {
      state.settings.paused = true
      await monitor.save()
      await monitor.updateDashboard()
      await say(interaction, 'Paused. No scans run until `/cve resume`.')
      return
    }

    case 'resume': {
      state.settings.paused = false
      await monitor.save()
      if (!monitor.running) monitor.schedule(5_000)
      await monitor.updateDashboard()
      await say(interaction, 'Resumed. The next scan starts in a few seconds.')
      return
    }
  }
}

async function reposCommand(deps: HandlerDeps, interaction: ChatInputCommandInteraction, sub: string): Promise<void> {
  const { monitor, github } = deps
  const s = monitor.state.settings

  switch (sub) {
    case 'list': {
      const watched = Object.values(monitor.state.repos)
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
        fullName = (await github.getRepo(repo)).fullName
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
      await monitor.updateDashboard()
      if (mode === 'all') {
        await say(interaction, 'Now watching every repo the GitHub token can read (plus any you added by name). Use `/cve repos remove` to leave one out.')
      } else {
        await say(
          interaction,
          s.repos.length
            ? `Now watching only the ${s.repos.length} repos you added. Others drop off at the next scan.`
            : 'Now watching only the repos you add, and none are added yet. Add one with `/cve repos add`.',
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

async function button(deps: HandlerDeps, interaction: ButtonInteraction): Promise<void> {
  const { monitor } = deps
  const state = monitor.state
  const id = interaction.customId
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
      content: `Muted ${card.advisoryId} in every repo. It still shows in \`/cve findings\`. Undo with \`/cve unmute advisory:${card.advisoryId}\`.`,
      flags: EPHEMERAL,
    })
  }
}

async function autocomplete(deps: HandlerDeps, interaction: AutocompleteInteraction): Promise<void> {
  const { monitor } = deps
  const typed = interaction.options.getFocused().toLowerCase()
  const names = new Map<string, string>()
  for (const r of Object.values(monitor.state.repos)) names.set(repoKey(r.name), r.name)
  for (const r of monitor.state.settings.repos) names.set(repoKey(r), r)
  for (const r of monitor.knownRepos) if (!names.has(repoKey(r))) names.set(repoKey(r), r)
  const matches = [...names.values()]
    .filter((n) => n.toLowerCase().includes(typed))
    .sort((a, b) => a.localeCompare(b))
    .slice(0, 25)
  await interaction.respond(matches.map((n) => ({ name: n, value: n })))
}
