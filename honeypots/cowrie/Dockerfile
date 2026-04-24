FROM cowrie/cowrie:latest

USER root

COPY cowrie.cfg /cowrie/etc/cowrie.cfg

USER cowrie

CMD ["/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie"]
