#!/usr/bin/env bash
# Simulates the process-lineage pattern of a web-shell-spawned reverse shell,
# WITHOUT any real network reverse shell: copy /bin/bash to /tmp/nginx, run it
# so its comm is "nginx" (comm is derived from the executable's basename),
# then have IT fork+exec a real /bin/bash child. The child's exec event has
# comm=bash, parent_comm=nginx -- matching the detector's rule.
#
# Run the exec-monitor agent in another terminal first (needs sudo/CAP_BPF),
# then run this script. You should see an [ALERT][T1059] line.
#
# Usage: ./trigger.sh
set -euo pipefail

FAKE_BIN=/tmp/nginx

cp /bin/bash "$FAKE_BIN"
chmod +x "$FAKE_BIN"

echo "[*] Renamed bash copy at $FAKE_BIN (comm will read as 'nginx')"
echo "[*] It will fork+exec a real /bin/bash child (comm=bash, parent_comm=nginx)"

# The trailing "; true" stops bash's tail-call exec optimization so the
# child /bin/bash is a genuine fork+exec (new pid, parent = the nginx-named
# process), not an in-place exec of the current process.
"$FAKE_BIN" -c 'bash -c "echo [trigger] fake reverse shell spawned, no network involved; sleep 1"; true'

echo "[*] Done."
