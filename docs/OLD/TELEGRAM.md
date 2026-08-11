# Telegram Alerts

This guide covers Telegram alert setup.

[<- Back to README](../README.md)

Telegram is optional. NetSpecter uses it for:

- IDS alerts
- Incident notifications
- Monitor alerts
- System warnings where supported

## What Telegram Is

Telegram is a messaging service. NetSpecter sends messages through a Telegram bot that you create.

## Create A Bot

1. Open Telegram.
2. Search for `@BotFather`.
3. Send `/newbot`.
4. Choose a bot name.
5. Choose a username ending in `bot`.
6. Copy the Bot Token.

The token looks roughly like:

```text
123456789:AAExampleTokenHere
```

Treat this token like a password.

## Obtain The Chat ID

1. Send the bot a message, for example `hi`.
2. Browse to this URL, replacing `YOUR_TOKEN`:

```text
https://api.telegram.org/botYOUR_TOKEN/getUpdates
```

Look for:

```json
"chat": {
  "id": 123456789
}
```

That number is the Chat ID.

For groups, add the bot to the group, send a message in the group, then use `getUpdates`. Group IDs often start with `-`.

## Configure NetSpecter

Open:

```text
Services -> Telegram
```

Set:

```text
Enable Telegram Alerts: on
Telegram Bot Token:     your bot token
Telegram Chat ID:       your chat ID
```

Click:

```text
Save and Send Test
```

Expected result:

- You receive a NetSpecter test message.
- Monitor pages can enable Telegram warning ticks.
- IDS settings can enable IDS Telegram alerts for P1/P2.

## Troubleshooting

| Problem | Check |
|---|---|
| No test message | Send the bot a first `hi` message before calling `getUpdates` |
| Wrong chat | Check the exact `chat.id` value |
| Group does not work | Confirm the bot is still in the group and the group ID includes the leading `-` |
| Invalid token | Re-copy the token from `@BotFather` |
| Nothing sends | Check appliance internet access and DNS |

## Security Recommendations

- Store the bot token only in NetSpecter settings.
- Remove old bots you no longer use.
- Do not post the token in issues, logs, screenshots, or chat.

---

Next:

- [Configure monitoring](MONITORING.md)
- [Understand incidents](INCIDENTS.md)
- [Return to README](../README.md)

