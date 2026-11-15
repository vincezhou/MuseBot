#!/usr/bin/env bash
# MuseBot — first-time setup on a fresh clone.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p inbox outbox processed/rejected transport/to_peer transport/from_peer \
         transport/files_to_peer transport/files_from_peer transport/pending \
         files/received files/sent tasks/incoming
REQ_FILE="requirements.lock"
[ -f "$REQ_FILE" ] || REQ_FILE="requirements.txt"
python3 -m pip install --target vendor -r "$REQ_FILE"
[ -f config.json ] || cp config.example.json config.json
echo "Setup done. Next:"
echo "1. Join your network:  python3 relay.py join   (enter the network code, your node name, and your role)"
echo "2. Announce yourself:  python3 relay.py handshake"
echo "3. Run the watcher:  python3 relay.py watch   (or install musebot.service via systemd)"
echo "4. Follow docs/master-package.md or docs/slave-package.md for your role."
