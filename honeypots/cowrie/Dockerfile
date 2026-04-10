FROM cowrie/cowrie:latest

USER root

COPY cowrie.cfg /cowrie/etc/cowrie.cfg
RUN mkdir -p /cowrie/var/lib/cowrie/downloads \
    && chown -R cowrie:cowrie /cowrie/etc /cowrie/var

USER cowrie

CMD ["/cowrie/bin/cowrie", "start", "-n"]
