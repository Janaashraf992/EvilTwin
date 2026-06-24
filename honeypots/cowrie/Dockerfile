FROM cowrie/cowrie:latest

USER root

COPY cowrie.cfg /cowrie/etc/cowrie.cfg

# Plant graduated bait files inside the fake SSH filesystem so they show up in
# `ls` and `cat` returns the real bytes. Baits are scattered across realistic
# locations (not piled in /root) so a single `ls /root` no longer reveals
# everything:
#   /tmp/database_backup.sql            (staging dump, read after any shell login)
#   /root/.ssh/id_rsa                   (root-level breach)
#   /root/.bash_history                 (admin trail pointing at the other baits)
#   /home/deploy/.aws/credentials       (AWS creds in the canonical location)
#   /opt/app/.env                       (app secrets: DB/JWT/Stripe/SMTP)
#   /var/backups/db/prod_db_dump.sql    (DB dump in a realistic backup path)
# The cowrie base image is shell-less, so planting runs in pure Python via the
# exec form below. Backend log detection (services/canary.py) fires the matching
# canary token when a mapped bait is accessed.
COPY honeyfs/ /tmp/baits-honeyfs/
COPY plant_baits.py /tmp/plant_baits.py

RUN ["/cowrie/cowrie-env/bin/python", "/tmp/plant_baits.py"]

USER cowrie

CMD ["/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie"]
