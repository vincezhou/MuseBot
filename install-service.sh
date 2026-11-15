#!/usr/bin/env bash
# MuseBot — install the resident watcher as a systemd service.
# Run as the user who will run the relay (uses sudo for systemctl).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT=/etc/systemd/system/musebot.service
echo "Installing musebot.service for $DIR"
sudo tee "$UNIT" >/dev/null <<UNIT_EOF
[Unit]
Description=MuseBot relay watcher
After=network.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=/usr/bin/python3 $DIR/relay.py watch
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT_EOF
sudo systemctl daemon-reload
sudo systemctl enable --now musebot.service
systemctl is-active musebot.service && echo "MuseBot watcher is resident."
