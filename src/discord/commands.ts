/**
 * The /cve slash command. Admin-only by default (Manage Server); a server admin
 * can open it to other roles under Server Settings > Integrations.
 */
import { InteractionContextType, PermissionFlagsBits, SlashCommandBuilder } from 'discord.js'

const SEVERITY_CHOICES = [
  { name: 'Critical', value: 'critical' },
  { name: 'High', value: 'high' },
  { name: 'Moderate', value: 'moderate' },
  { name: 'Low', value: 'low' },
]

export const cveCommand = new SlashCommandBuilder()
  .setName('cve')
  .setDescription('Watch your GitHub repos for known vulnerabilities')
  .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
  .setContexts(InteractionContextType.Guild)
  .addSubcommand((s) =>
    s
      .setName('setup')
      .setDescription('Create (or repair) the alert channels and the watcher role')
      .addBooleanOption((o) =>
        o.setName('private').setDescription('Only admins and the watcher role can see the channels (default: yes)'),
      ),
  )
  .addSubcommand((s) => s.setName('status').setDescription('What is watched, what is open, and when the next scan runs'))
  .addSubcommand((s) => s.setName('scan').setDescription('Scan now'))
  .addSubcommand((s) =>
    s
      .setName('findings')
      .setDescription('List open advisories')
      .addStringOption((o) => o.setName('repo').setDescription('Only this repo (owner/name)').setAutocomplete(true))
      .addStringOption((o) => o.setName('severity').setDescription('Lowest severity to show').addChoices(...SEVERITY_CHOICES)),
  )
  .addSubcommandGroup((g) =>
    g
      .setName('repos')
      .setDescription('Choose which repos to watch')
      .addSubcommand((s) => s.setName('list').setDescription('Show how repos are chosen and which are watched'))
      .addSubcommand((s) =>
        s
          .setName('add')
          .setDescription('Watch a repo')
          .addStringOption((o) => o.setName('repo').setDescription('owner/name').setRequired(true).setAutocomplete(true)),
      )
      .addSubcommand((s) =>
        s
          .setName('remove')
          .setDescription('Stop watching a repo')
          .addStringOption((o) => o.setName('repo').setDescription('owner/name').setRequired(true).setAutocomplete(true)),
      )
      .addSubcommand((s) =>
        s
          .setName('mode')
          .setDescription('Watch every repo the GitHub token can read, or only the ones you add')
          .addStringOption((o) =>
            o
              .setName('mode')
              .setDescription('Which repos to watch')
              .setRequired(true)
              .addChoices({ name: 'Every repo the token can read', value: 'all' }, { name: 'Only repos I add', value: 'list' }),
          ),
      ),
  )
  .addSubcommand((s) =>
    s
      .setName('settings')
      .setDescription('Show or change alert settings')
      .addStringOption((o) =>
        o.setName('min_severity').setDescription('Lowest severity that gets its own alert').addChoices(...SEVERITY_CHOICES),
      )
      .addBooleanOption((o) => o.setName('ping_critical').setDescription('Ping the watcher role on critical alerts'))
      .addBooleanOption((o) =>
        o.setName('ping_dev_only').setDescription('Also ping when only dev dependencies are affected'),
      )
      .addBooleanOption((o) => o.setName('include_forks').setDescription('Watch forks too (every-repo mode)'))
      .addBooleanOption((o) => o.setName('include_archived').setDescription('Watch archived repos too (every-repo mode)'))
      .addIntegerOption((o) =>
        o.setName('interval_minutes').setDescription('Minutes between scans (15 to 1440)').setMinValue(15).setMaxValue(1440),
      ),
  )
  .addSubcommand((s) =>
    s
      .setName('mute')
      .setDescription('Stop alerts for an advisory')
      .addStringOption((o) => o.setName('advisory').setDescription('The advisory ID, like GHSA-xxxx-xxxx-xxxx').setRequired(true))
      .addStringOption((o) => o.setName('repo').setDescription('Only in this repo (default: every repo)').setAutocomplete(true)),
  )
  .addSubcommand((s) =>
    s
      .setName('unmute')
      .setDescription('Turn alerts for an advisory back on')
      .addStringOption((o) => o.setName('advisory').setDescription('The advisory ID').setRequired(true))
      .addStringOption((o) => o.setName('repo').setDescription('The repo it was muted for, if any').setAutocomplete(true)),
  )
  .addSubcommand((s) => s.setName('mutes').setDescription('List muted advisories'))
  .addSubcommand((s) => s.setName('pause').setDescription('Pause scanning'))
  .addSubcommand((s) => s.setName('resume').setDescription('Resume scanning'))
