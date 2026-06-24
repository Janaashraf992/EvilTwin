#!/bin/sh
# Run both HTTP and SSH servers. If either exits, kill the other.
# Docker restart: unless-stopped brings both back up.

python server.py &
HTTP_PID=$!
python ssh_banner.py &
SSH_PID=$!

# Trap SIGTERM to propagate to children
cleanup() {
    kill $HTTP_PID $SSH_PID 2>/dev/null
    wait $HTTP_PID $SSH_PID 2>/dev/null
    exit 0
}
trap cleanup TERM INT

# Wait for both — if either exits, kill the other
wait $HTTP_PID $SSH_PID 2>/dev/null
