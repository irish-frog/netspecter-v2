# Incidents

This guide explains IDS incident grouping, statuses, and actions.

[<- Back to README](../README.md)

Incidents help reduce repeated IDS noise by grouping related alerts.

## Statuses

| Status | Meaning |
|---|---|
| Open | Needs attention and can notify |
| Acknowledged | Seen by an admin; should not repeat as an open alert |
| Investigating | Being reviewed |
| Closed | Resolved; should not notify as open |
| Ignored | Intentionally ignored |
| Banned | Source or endpoint has been banned by NetSpecter action |

## Actions

Available actions depend on the row and current status, but can include:

- acknowledge
- investigate
- close
- reopen
- ignore
- ban
- remove ban
- delete

Ban actions are intended to feed the NetSpecter IDS banned endpoint list used by collector-side blocking logic. Removing a ban should also update the status away from banned where the UI supports that workflow.

## Notification Rules

IDS reminders should be limited by status and cooldown:

- Open P1/P2 alerts can notify.
- Non-open alerts should not continue to notify.
- Cooldown prevents repeated messages for the same alert key.

## Troubleshooting

```bash
sqlite3 /var/lib/netspecter/netspecter.db "
SELECT id, severity, alert_status, src_ip, dest_ip, signature
FROM ids_events
ORDER BY id DESC
LIMIT 20;
"
```

Expected result:

- Closed or acknowledged rows are not treated as open rows.
- Reopened rows can appear as open again.

---

Next:

- [Configure Suricata IDS](SURICATA.md)
- [Configure Telegram](TELEGRAM.md)
- [Return to README](../README.md)

