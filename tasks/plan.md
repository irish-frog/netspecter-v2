# Implementation plan: attribution rebuild

Status: tls-metadata specification approved; this plan and its task breakdown approved by the operator on 2026-11-18. The remaining module specifications will be reviewed before their implementation.

## Scope and dependency order
Follow docs/engineering/attribution-rebuild-capabilities.md. Implement tls-metadata first, then flow-attribution, device-timeline, and explicit history-reset. Existing Python UI, DNS filtering and bridge forwarding remain operational throughout development. Work locally until tested; publish only a coherent validated change.

## Inspector architecture
1. A portable Rust library decodes Ethernet/VLAN/IP/TCP packets and bounded TLS ClientHello records using maintained parsers. Synthetic packets are the initial verification surface.
2. A bounded connection tracker reconstructs the client-side hello. Require the opening SYN to anchor TCP sequence space; a missed handshake produces a coverage gap rather than guessed data. Reject conflicting overlaps and expired/reused connections. Count each rejection and eviction. Apply global memory limits as well as per-flow limits.
3. Linux-only pcap capture reads the configured bridge. A separate bounded queue emits versioned connection metadata over a restricted filesystem UNIX socket. Dropped output cannot block capture indefinitely. No persistent packet storage and no network listener.
4. A hardened systemd service runs as a dedicated account with CAP_NET_RAW only, memory/CPU limits, restrictive filesystem access and automatic restart. Validate missing-interface and missing-consumer behavior.
5. Verify a Linux binary and deployment procedure before integrating the sensor into normal installation. The local Windows compiler is already working. Evaluate a local Linux build environment; do not install a compiler on appliances or silently substitute cloud publishing.

## Later module checkpoints
Flow attribution must preserve exact tuples and timestamps from measured flows and deduplicate exports. Match SNI to a connection, not a CDN IP. DNS fallback must be client/time scoped and mark ambiguity. Internal/VPN transfers stay excluded. Coverage counts measured eligible internet bytes and states unknown reasons.

Timeline displays source, confidence and actual attributed bytes using escaped user-controlled strings. History reset is preview-first and explicit on each authorized host; preserve manual identity records, custom mappings, settings, login/licence material and backups. Stop writers safely, prevent old DNS data reimport and recover services on failure. Never invoke the existing broad reset-history.sh for this task.

## Risks and mitigations
- Malicious/truncated traffic: mature parsers, no unsafe application code, deterministic resource caps, hostile-input tests.
- Midstream or encrypted names: explicit unknown; never inflate coverage by guessing.
- Privilege exposure: dedicated sensor user, local IPC, capability limited to capture, root-owned executable.
- Build mismatch: native Windows tests plus Linux build/integration validation.
- Reset data loss: reviewed preservation inventory, dry-run, transactional operations where possible, operator-visible report and coordinated restart. No automatic reset on the third unit.

## Review checkpoints
The detailed inspector tasks are in tasks/todo.md. Review parser/reassembly test results before capture integration; review Linux integration before attribution integration; validate the full replacement before either live reset.

## Integration plan (approved by operator on 2026-11-18)

After the sensor tests, implement the remaining modules sequentially using the tasks below. Add new traffic tables without destructive migrations. Systemd owns the listening socket and hands its descriptor to the collector. The receiver validates Linux peer credentials, schema, tuple, hostname, timestamps and bounded JSON before transactional batch writes. Receiver failure leaves DNS/forwarding independent.

Extract bounded NetFlow parsing and add stable export identities/start-end times. Persist deduplicated measurements before correlation. Reconcile late metadata and flow data without changing measured bytes. Bind intake to loopback and reject remote exporters. Classification uses explicit rules, exact connection evidence, unambiguous client DNS, then explicit unknown. Existing IP-only guesses must not continue contributing to primary-attributed bytes alongside the replacement. Bridge totals remain separate.

Add timeline queries/UI only after measurement and attribution tests pass. Integrate service installation using a verified Linux artifact, create the dedicated sensor identity/group and root-owned socket, and stage/validate units before enabling. Do not add compilers to units or alter AdGuard resolver behavior.

For reset, first inventory all schemas/retained state. Add preview and synthetic preservation tests. Then implement exclusive orchestration: record service/timer states, stop writers, make consistent protected recovery snapshots, set a single cutoff and clear explicit collected-history tables, verify retained data, and restore prior running services. Cross-database failure must recover snapshots before writers resume. Move DNS cutoff validation ahead of every cache/device update. Fresh-collection and internal-transfer checks are prerequisites to live reset.

Final checkpoint: complete Rust/Linux and Python tests; review privilege and update failure paths; deploy the coherent replacement to the two reachable authorized appliances; validate sensor/flow/timeline/DNS health; only then explicitly reset their histories and verify preserved settings/names and fresh collection. The third unit is excluded.
