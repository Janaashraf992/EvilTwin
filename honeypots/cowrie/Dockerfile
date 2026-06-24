FROM cowrie/cowrie:latest

USER root

COPY cowrie.cfg /cowrie/etc/cowrie.cfg

# Plant graduated bait files inside the fake SSH filesystem:
#   L4  /tmp/database_backup.sql   (read after any shell login)
#   L5  /root/.ssh/id_rsa          (root-level breach)
# Content is dropped into honeyfs and the path is registered in fs.pickle so it
# shows in `ls` and `cat` returns the real bytes. Backend log detection
# (services/canary.py) fires the matching canary token when accessed.
COPY honeyfs/ /tmp/baits-honeyfs/
COPY add_baits_to_fs.py /tmp/add_baits_to_fs.py

RUN set -eu; \
    FSP="$(find / -path '*share/cowrie/fs.pickle' 2>/dev/null | head -n1)"; \
    if [ -z "$FSP" ]; then FSP="$(find / -name fs.pickle 2>/dev/null | head -n1)"; fi; \
    if [ -z "$FSP" ]; then echo "ERROR: fs.pickle not found"; exit 1; fi; \
    HOME_DIR="$(dirname "$(dirname "$(dirname "$FSP")")")"; \
    HONEYFS="$HOME_DIR/honeyfs"; \
    echo "Cowrie fs.pickle=$FSP  home=$HOME_DIR  honeyfs=$HONEYFS"; \
    mkdir -p "$HONEYFS/tmp" "$HONEYFS/root/.ssh"; \
    cp /tmp/baits-honeyfs/tmp/database_backup.sql "$HONEYFS/tmp/database_backup.sql"; \
    cp /tmp/baits-honeyfs/root/.ssh/id_rsa "$HONEYFS/root/.ssh/id_rsa"; \
    PYBIN=/cowrie/cowrie-env/bin/python; \
    [ -x "$PYBIN" ] || PYBIN="$(command -v python3)"; \
    "$PYBIN" /tmp/add_baits_to_fs.py "$FSP" \
        "/tmp/database_backup.sql=$HONEYFS/tmp/database_backup.sql:644" \
        "/root/.ssh/id_rsa=$HONEYFS/root/.ssh/id_rsa:600"; \
    chown -R cowrie:cowrie "$HONEYFS" "$FSP" 2>/dev/null || true; \
    rm -rf /tmp/baits-honeyfs /tmp/add_baits_to_fs.py

USER cowrie

CMD ["/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie"]
