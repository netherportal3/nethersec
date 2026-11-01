/**
 * The few Discord calls the host and watch cards need, behind one small
 * interface, so the card logic is tested with a fake.
 */
import { DiscordAPIError, type Client } from 'discord.js'
import type { Payload } from '../discord/cards.js'

/** The message (or its channel) no longer exists. */
export class MessageGone extends Error {
  override name = 'MessageGone'
}

export interface DiscordPort {
  isReady(): boolean
  /** Post a message; resolves to its id. Throws when it was not posted. */
  send(channelId: string, payload: Payload): Promise<string>
  /** Edit a message in place. Throws MessageGone when it was deleted. */
  edit(channelId: string, messageId: string, payload: Payload): Promise<void>
  /** One direct message. Throws when it was not delivered. */
  dm(userId: string, payload: Payload): Promise<void>
}

/** Unknown Channel, Unknown Message. */
const GONE_CODES = new Set([10003, 10008])

export function clientPort(client: Client): DiscordPort {
  const channel = async (id: string) => {
    let ch
    try {
      ch = await client.channels.fetch(id)
    } catch (err) {
      if (err instanceof DiscordAPIError && GONE_CODES.has(Number(err.code))) throw new MessageGone('channel gone')
      throw err
    }
    if (!ch || !ch.isSendable()) throw new MessageGone('channel gone')
    return ch
  }
  return {
    isReady: () => client.isReady(),
    async send(channelId, payload) {
      const ch = await channel(channelId)
      const msg = await ch.send(payload)
      return msg.id
    },
    async edit(channelId, messageId, payload) {
      const ch = await channel(channelId)
      try {
        const msg = await ch.messages.fetch(messageId)
        await msg.edit({ embeds: payload.embeds, components: payload.components ?? [], allowedMentions: payload.allowedMentions })
      } catch (err) {
        if (err instanceof DiscordAPIError && GONE_CODES.has(Number(err.code))) throw new MessageGone('message gone')
        throw err
      }
    },
    async dm(userId, payload) {
      const user = await client.users.fetch(userId)
      await user.send(payload)
    },
  }
}
