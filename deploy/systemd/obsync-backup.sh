#!/usr/bin/env bash
# Nightly backup: a consistent DB snapshot + the blob store -> restic.
# Everything is already end-to-end ciphertext; restic encrypts it once more.
# Install as /usr/local/sbin/obsync-backup, root-owned, mode 0700.
# /etc/obsync/restic.env holds RESTIC_REPOSITORY and RESTIC_PASSWORD (mode 0600).
# Tip: point it at an append-only repository (rest-server --append-only), so a
# compromised server can't delete its own backups.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
. /etc/obsync/restic.env
DATA=/var/lib/obsync
SNAP=$DATA/snapshot/obsync.db
install -d -o obsync -g obsync -m 0700 "$(dirname "$SNAP")"
runuser -u obsync -- rm -f "$SNAP"
runuser -u obsync -- /usr/local/bin/obsyncd -data "$DATA" snapshot "$SNAP"
restic snapshots --quiet >/dev/null 2>&1 || restic init
restic backup --quiet --tag nightly "$DATA/snapshot" "$DATA/blobs"
restic check --quiet
echo "backup ok $(date -Is)"
