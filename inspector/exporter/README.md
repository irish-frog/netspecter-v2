# Bounded softflowd exporter build

Upstream: https://github.com/irino/softflowd at commit 433fbb7102616c671d523d4e41ae5315cd70d442 (softflowd 1.1.0). COPYING and LICENSE are retained alongside the distribution.

The one local source modification changes `pcap_set_timeout (*pcap, 0)` to `pcap_set_timeout (*pcap, 100)`. Upstream's infinite capture-buffer timeout can leave low-volume traffic unprocessed indefinitely with Linux TPACKET_V3. A 100 ms timeout bounds capture delivery without injecting traffic or changing flow byte counts. The isolated bridge test uses a few real connections to verify that exports arrive without traffic added to fill the buffer.

CI checks the exact upstream commit and original file checksum, builds with hardening flags, and records the patched exporter checksum/build identity with the Rust sensor. Appliances run the checked bundled binary; no compiler, LD_PRELOAD hook or downloaded installer is used. The stock exporter service is disabled to prevent duplicate measurements.
