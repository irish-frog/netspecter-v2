# Bridge compaction and management report correction

## Problem

The collector archived rows older than a moving retention cutoff into hourly bridge totals, replaced an existing hour with the newest partial batch, then deleted the raw rows. Two passes processing 5 MiB and 7 MiB for the same hour could leave 7 MiB instead of 12 MiB. SQL now/date cutoffs were also evaluated separately during the transaction. Reader SQL used a global MAX(hour) watermark, which could hide a late arrival for an older hour or a different device.

Existing missing bridge history cannot be reconstructed safely from measured application flows. The repair prevents further compaction loss; it does not invent past bridge bytes, reset history, clamp/tolerate mismatches or change the primary coverage denominator. Historical periods may continue to show unavailable bridge coverage.

## Fix and invariants

Bridge compaction adds each new raw batch to its hour and deletes exactly that batch in the same caller-owned transaction. The helper begins a transaction when necessary, supports SQLite legacy/default and isolation_level=None connections, and rejects Python autocommit=True. One raw timestamp cutoff and one retention-date cutoff are frozen for the entire run. A deferred checkpoint after a successful commit is reported as such, rather than as a rolled-back cleanup failure.

Bridge readers combine disjoint committed rollups plus every remaining raw row, including late arrivals. Both reporting consumers use the same shared source helper. NULL byte counters contribute no known bytes and cannot poison valid counters. If any live-rate sample is missing, its combined mean remains unknown (NULL) rather than guessing zero or changing with batch partitioning. Existing REAL MiB storage is retained: ordinary byte-derived multiples of 2^-20 remain exact within binary64's 2^53-integer-byte range. This is not a claim of exact arithmetic for arbitrary huge fractional REAL inputs. No schema migration is included.

The retired legacy estimated/remote/classified aggregation semantics were reviewed but are outside this bridge-only repair. The passive pipeline uses measured_internet_flows, not those legacy application facts.

## Report behavior

Passive Top Applications retains the actual primary category separately from the legacy application-name alias. HTML and Excel show e.g. TikTok / Social Media. The retired Security Events option is omitted when security features are disabled, including explicit requests and Excel sections. Category legend percentages are explicitly shares of attributed application bytes. Device-name/IP hints no longer turn all device traffic into attributed traffic in passive mode.

When bridge and flow counters disagree, primary bridge coverage remains unavailable. The report exposes the compared bridge/flow quantities and the separate measured-flow classified share. It does not hide unobserved bytes or silently replace bridge totals with application flows.

## Verification and review

Tests cover successive partial-hour batches, exact cutoff, retry/idempotence, weighted means, NULL fields, late arrivals/other devices, actual attached trafficdb/WAL readers and concurrent writes, later caller failure/rollback/retry, legacy autocommit connections and post-commit checkpoint failure. Report tests exercise real SQL category/device filtering, settled application bytes, removal of device-identity guesses and Excel category/security behavior.

A fresh-context adversarial review identified nullable counter/average and missing concurrency coverage. The operator requested Codex CLI second review. Its first pass also flagged explicit transaction boundaries, cutoff freezing and checkpoint outcome reporting. The accepted findings were corrected and reproduced in tests. The corrected public-code-only artifact passed the Codex CLI re-review with no material issues found. Previously lost history and retired legacy aggregation issues are documented limitations, not repaired by manufacturing data.

Owner rollout is pending Linux CI and temporary maintenance access. DNS configuration/process, settings, login/licence, names and collected history must be retained. Do not contact or deploy to the held client. QUIC/service-context work remains a separate proposed scope; no QUIC inspection has been added by this report fix.


Linux validation also ran in an isolated temporary checkout on the owner as the unprivileged account, with the existing test isolation/configured temporary databases: all435tests passed on Debian13. No service/settings/production data was modified by that test run. Two hosted CI attempts (44521874765) failed before tests when Ubuntu mirrors returned503, not because of code failures. CI mirror lists now prefer signed HTTPS Ubuntu mirrors with bounded retries/IPv4; no signature checks are disabled and no appliance APT/DNS configuration is changed.
