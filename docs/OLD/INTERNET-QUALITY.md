# Internet Quality

This guide explains NetSpecter internet-quality history.

[<- Back to README](../README.md)

NetSpecter records WAN quality signals so you can see whether the internet link is stable over time.

Tracked areas include:

- latency
- packet loss
- jitter
- DNS response time
- scheduled speed-test history when enabled

## Settings

Relevant settings include:

- internet-quality targets
- DNS server and query
- interval seconds
- ping count and timeout
- retention days
- scheduled speed tests per day

Scheduled speed tests consume internet data. Keep them disabled unless you want the appliance to test the WAN regularly.

## Checks

```bash
systemctl status netspecter-collector netspecter-speedtest.timer --no-pager -l
journalctl -u netspecter-collector -n 80 --no-pager
```

Expected result:

- Internet quality rows are collected by the collector.
- Scheduled speed tests only run when enabled.

---

Next:

- [Settings Reference](SETTINGS.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Return to README](../README.md)

