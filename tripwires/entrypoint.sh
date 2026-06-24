#!/bin/sh
set -e

# Materialize the (intentionally exposed) leaked .git clue used by level 3.
# A directory literally named ".git" cannot be tracked in version control, so it
# is seeded here from /gitseed at container start. This runs BEFORE tripwire.py
# launches the inotify watcher, so these writes do not self-trigger a canary.
if [ -d /gitseed ]; then
    mkdir -p /bait/.git/logs
    cp -f /gitseed/config /bait/.git/config
    cp -f /gitseed/HEAD /bait/.git/HEAD
    cp -f /gitseed/logs_HEAD /bait/.git/logs/HEAD
fi

exec python -u /app/tripwire.py
