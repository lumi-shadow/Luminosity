#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Oyster CVM clock drift fix:
# Enclaves often lack NTP and drift 5-30s over hours. We sync once at boot
# and then periodically in the background. ntpdate needs root, so this script
# runs as root and drops to nonroot for the actual binary.
# ---------------------------------------------------------------------------

sync_clock() {
    ntpdate -s -u pool.ntp.org 2>/dev/null && \
        echo "[entrypoint] clock synced via NTP" || \
        echo "[entrypoint] NTP sync failed (non-fatal, continuing with host clock)"
}

# Initial sync (blocking).
sync_clock

# Background loop: re-sync every 5 minutes to prevent drift.
(
    while true; do
        sleep 300
        sync_clock
    done
) &

# Drop privileges and exec the swap engine.
exec gosu nonroot /usr/local/bin/swap-engine "$@"
