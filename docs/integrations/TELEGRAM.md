# Telegram Alerts

Telegram is optional. NetSpecter uses it for:

- IDS alerts
- Incident notifications
- Monitor alerts
- System warnings where supported

## Create A Bot

1. Open Telegram.
2. Search for `@BotFather`.
3. Send `/newbot`.
4. Choose a bot name.
5. Choose a username ending in `bot`.
6. Copy the Bot Token.

Treat the bot token like a password.

## Obtain The Chat ID

Send the bot a message, then browse to:

```text
https://api.telegram.org/botYOUR_TOKEN/getUpdates
```

Look for:

```json
"chat": {
  "id": 123456789
}
```

For groups, add the bot to the group, send a message in the group, then use `getUpdates`. Group IDs often start with `-`.

## Configure NetSpecter

Open `Services -> Telegram`.

```text
Enable Telegram Alerts: on
Telegram Bot Token:     your bot token
Telegram Chat ID:       your chat ID
```

Click `Save and Send Test`.

## Security Recommendations

- Store the bot token only in NetSpecter settings.
- Remove old bots you no longer use.
- Do not post the token in issues, logs, screenshots or chat.
