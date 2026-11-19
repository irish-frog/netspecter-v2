# First passive-socket migration

A legacy collector may be active before netspecter-tls-metadata.socket exists. systemd refuses to start that socket while its target service is already running, because an existing process cannot receive activation descriptors retroactively. Initial pipeline tests started from an inactive collector and missed this migration state.

The installer now calls a fixed root helper before enabling other services. If the metadata socket is inactive, it stops the watchdog timer/service, sensor/exporter and collector, resets failed socket/collector state and enables the socket first. The installer's existing readiness-ordered startup then starts the collector with the inherited descriptor and restores the other units/timers. If the socket is already active, the helper is idempotent and does not pause collection unnecessarily. No AdGuard/DNS or bridge service is stopped or modified.

The root SSH wrapper retains umask077 for private state, but Git operations and the normal installer run with022. This prevents temporarily unreadable checked-out Python files/directories while the service user is active. Existing explicit config/secret permissions remain enforced by the installer. No history reset or purge occurs unless the full install/readiness/DNS stages succeed.

Disposable root Linux integration now starts an actual systemd legacy collector fixture before installing socket dependencies and exercises this handoff, followed by real packet capture, flow attribution, reset and fresh collection. Appliance logs confirmed the specific service-already-active refusal and a transient permission-denied before installer permission normalization; DNS continued working. No remote commands were run on the affected client by the assistant.
