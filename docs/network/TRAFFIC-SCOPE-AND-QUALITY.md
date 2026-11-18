# Internet usage, internal transfers and quality probes

## Internal traffic

NetSpecter excludes the configured LAN Prefix network from forwarded internet
usage. In **Settings → Network → Additional Internal Networks**, add other
internal IPv4 CIDRs such as VPN pools and routed VLANs. Separate networks with
commas. The default is empty, so no site-specific VPN range is imposed on other
appliances. An update does not infer or change these settings.

For a site with LAN `192.168.1.0/24`, file server `192.168.1.10`, and VPN pool
`10.20.30.0/24`, keep the LAN Prefix as `192.168.1.` and add
`10.20.30.0/24` to Additional Internal Networks. Client/server uploads and
downloads within the LAN, and between that LAN and the VPN pool, are excluded
in both directions. The server's internet traffic remains eligible. Extra
Ignored IPs excludes a device's own usage altogether, so it is a different
setting and is not needed merely to exclude local file copies.

The same scope applies to total byte counters and application, classification
and visibility counters. VPN users' split-tunnel traffic is invisible when it
bypasses the bridge. This setting does not add separate device tracking for a
VPN pool; NAT may also hide individual users behind a gateway address.

Changes apply to new counter samples. Old device/hourly totals cannot reliably
be rewritten to subtract an internal destination if that detail was never
stored. Compare a reporting period entirely after the setting was applied.

## Attribution and device names

Up to one quarter of classification counter slots are available to active
connections absent from the DNS candidate list. Unused capacity remains
available to DNS candidates, and the configured global limit is unchanged.
Capturing a destination does not establish an application: it still needs
supported DNS, TLS/HTTP metadata or a signature. Unknown traffic is not
relabelled solely to increase the coverage percentage.

Trusted device names retain their discovery source across routine traffic
updates. Lower-ranked observations do not replace those names or their saved
hostnames. Existing randomized-MAC identity restrictions remain in place.

## Quality measurements and fault isolation

Jitter uses consecutive RTT differences within each individual target's probe
series. RTT differences between two different internet hosts are not jitter.
Gateway, local DNS and external DNS results are observations, not proof that
the ISP or NetSpecter caused an incident. External DNS may be intercepted by
network policy; a response alone does not prove independent upstream paths.

When `dig` is unavailable, DNS checks report that measurement is unavailable.
They do not substitute the system resolver for the selected DNS server or
change the process-wide socket timeout. Empty speed-test output cannot be
successful merely because the command exited with code zero. Reports also
treat historical success rows lacking measurements as failed/incomplete.

After an update, run this read-only diagnostic on the appliance, preferably
during a reported problem:

```bash
python3 /opt/netspecter/scripts/diagnose-internet-quality.py --samples 3 --interval 5
```

It reports DNS and ICMP probes, load, available memory, service state and
per-interface error/drop deltas. It reads configuration without printing
credentials, does not restart services, and does not run bandwidth-saturating
speed tests. Three samples may take about a minute if probes time out.
Compare results with a client on the same LAN and, where operationally
appropriate, a separately planned bridge-bypass test. Healthy short samples
cannot rule out intermittent appliance, AdGuard, LAN or ISP faults.

## Retired Suricata runtime and alert cleanup

Normal installation and updates no longer install Suricata, download its rules,
validate its configuration or prepare capture-interface offloads. Existing
Suricata and IDS offload services are kept disabled. AdGuard DNS filtering and
the traffic/device collectors continue to operate independently of Suricata.
Already installed packages are not automatically purged.

To preview old security-alert records and Suricata log files:

```bash
python3 /opt/netspecter/scripts/clear-alert-history.py
```

To permanently delete that history after reviewing the preview:

```bash
python3 /opt/netspecter/scripts/clear-alert-history.py --apply
```

Run cleanup as root on the intended appliance. Apply mode refuses to run
unless security collection is disabled in configuration and Suricata is
confirmed stopped. It clears IDS alert rows, alert notifications, incident
records and attached incident notes/audit, anomaly alert events, threat-match
history, and named Suricata log files. It preserves DNS and traffic records,
device identities, application signatures, non-alert TLS metadata, threat
feeds and configuration. Cleanup is explicit and is never run automatically
by an update. Existing backups are not edited.
