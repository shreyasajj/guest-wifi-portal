#!/bin/sh
# Make sure the SQLite folder is writable by the app user, then drop root.
#
# Bind mounts (e.g. ./data:/data) are owned by whoever created them on the host,
# usually root, so uid 10001 can't create portal.db there and SQLite fails with
# "unable to open database file". Running as root just long enough to fix the
# ownership avoids that. If the container was started with `user:` already set,
# we can't chown, so we only check and explain.
set -eu

APP_UID=10001
APP_GID=10001

db_dir=""
case "${DATABASE_URL:-sqlite:////data/portal.db}" in
  sqlite:///*)
    db_path="${DATABASE_URL:-sqlite:////data/portal.db}"
    db_path="${db_path#sqlite:///}"
    db_path="${db_path%%\?*}"
    db_dir="$(dirname "$db_path")"
    ;;
esac

if [ "$(id -u)" = "0" ]; then
  if [ -n "$db_dir" ]; then
    mkdir -p "$db_dir"
    # Only touch ownership when needed, so a large or shared folder isn't rechowned on every start.
    if ! setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups test -w "$db_dir"; then
      echo "entrypoint: making $db_dir writable for uid $APP_UID" >&2
      chown -R "$APP_UID:$APP_GID" "$db_dir"
    fi
  fi
  exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups "$@"
fi

if [ -n "$db_dir" ] && { [ ! -d "$db_dir" ] || [ ! -w "$db_dir" ]; }; then
  echo "entrypoint: $db_dir is not writable by uid $(id -u)." >&2
  echo "entrypoint: on the host run: sudo chown -R $(id -u):$(id -g) <your data folder>" >&2
  exit 1
fi
exec "$@"
