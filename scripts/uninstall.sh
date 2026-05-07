#!/usr/bin/env bash
# Reverse scripts/install.sh:
#   - Disable + stop rootkat-lkm.service (which rmmods)
#   - Remove the unit file and /usr/local/lib/rootkat/
set -euo pipefail

INSTALL_DIR="/usr/local/lib/rootkat"
UNIT_PATH="/etc/systemd/system/rootkat-lkm.service"

if systemctl list-unit-files --quiet rootkat-lkm.service 2>/dev/null \
        | grep -q rootkat-lkm.service; then
    systemctl disable --now rootkat-lkm.service 2>/dev/null || true
fi

# Belt-and-braces: unload the module if still loaded.
if [ -d /sys/module/rootkat ]; then
    rmmod rootkat 2>/dev/null || true
fi

rm -f "$UNIT_PATH"
rm -rf "$INSTALL_DIR"
systemctl daemon-reload

echo "[uninstall] rootkat removed"
