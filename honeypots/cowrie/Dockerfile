FROM cowrie/cowrie:latest

USER root

COPY cowrie.cfg /cowrie/etc/cowrie.cfg

# Plant graduated bait files inside the fake SSH filesystem so they show up in
# `ls` and `cat` returns the real bytes:
#   L4  /tmp/database_backup.sql        (read after any shell login)
#   L5  /root/.ssh/id_rsa               (root-level breach)
#       /root/credentials.txt           (visible lure in root's home)
#       /root/aws_keys.csv              (visible lure in root's home)
#       /root/backups/prod_db_dump.sql  (visible lure folder in root's home)
# The cowrie base image is shell-less, so planting runs in pure Python via the
# exec form below. Backend log detection (services/canary.py) fires the matching
# canary token when a mapped bait is accessed.
COPY honeyfs/ /tmp/baits-honeyfs/
COPY plant_baits.py /tmp/plant_baits.py

RUN ["/cowrie/cowrie-env/bin/python", "/tmp/plant_baits.py"]

USER cowrie

CMD ["/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie"]
