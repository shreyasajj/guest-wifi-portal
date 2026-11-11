#!/bin/sh
# Pull the latest portal image and restart the container only if it changed.
# Run from cron or the systemd timer in this folder.
set -eu
cd "$(dirname "$0")/.."

before=$(docker compose images -q portal 2>/dev/null || true)
docker compose pull --quiet portal
docker compose up -d portal
after=$(docker compose images -q portal 2>/dev/null || true)

if [ "$before" != "$after" ]; then
  echo "$(date -Is) portal updated: ${before:-none} -> $after"
  docker image prune -f >/dev/null
fi
