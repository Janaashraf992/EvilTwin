FROM dinotools/dionaea:latest

USER root

COPY dionaea.cfg /opt/dionaea/etc/dionaea/dionaea.cfg

RUN mkdir -p /opt/dionaea/var/log \
             /opt/dionaea/var/lib/dionaea/binaries \
    && chown -R nobody:nogroup /opt/dionaea/var

USER nobody

EXPOSE 21 80 445 1433

CMD ["dionaea", "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg", "-l", "all,-debug", "-L", "*"]
