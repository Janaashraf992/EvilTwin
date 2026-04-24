FROM dinotools/dionaea:latest

# Override the template cfg so init_etc copies our version on first start
COPY dionaea.cfg /opt/dionaea/template/etc/dionaea/dionaea.cfg
COPY log_json.yaml /opt/dionaea/template/etc/dionaea/ihandlers-enabled/log_json.yaml

# Pre-create var/lib directory structure from template.
# When docker-compose mounts a named volume at var/lib/dionaea/binaries,
# Docker creates the parent var/lib/dionaea/, causing the entrypoint to skip
# init_lib. Without this RUN, required subdirs (ftp, http, sip, etc.) are
# missing and dionaea segfaults. Building them into the image avoids that.
RUN cd /opt/dionaea && cp -a template/lib var/ && chown -R dionaea:dionaea var/lib

EXPOSE 21 80 445 1433
