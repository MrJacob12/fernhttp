#!/bin/sh
# Translates conventional env vars into fernhttp CLI flags so `docker
# compose` stays declarative. Defaults mirror the binary's built-ins.
set -eu

set -- /usr/local/bin/fernhttp \
    --db   "${DB_PATH:-/data/fernhttp.db}" \
    --host "${HOST:-0.0.0.0}" \
    --port "${PORT:-7890}" \
    --poll "${POLL_MS:-500}"

# LOGS_DIR loads every *access.log in a directory (all Apache vhosts, one
# dashboard tab each) and takes precedence. When it is set, LOG_PATH is only
# added if explicitly provided, so a LOGS_DIR-only config does not also tail
# the default empty /logs/access.log.
if [ -n "${LOGS_DIR:-}" ]; then
    set -- "$@" --logs-dir "$LOGS_DIR"
    if [ -n "${LOG_PATH:-}" ]; then
        set -- "$@" --log "$LOG_PATH"
    fi
else
    set -- "$@" --log "${LOG_PATH:-/logs/access.log}"
fi

exec "$@"
