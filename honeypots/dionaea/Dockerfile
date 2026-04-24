FROM dinotools/dionaea:latest

# Override the template cfg so init_etc copies our version on first start
COPY dionaea.cfg /opt/dionaea/template/etc/dionaea/dionaea.cfg
COPY dionaea.cfg /opt/dionaea/etc/dionaea/dionaea.cfg

# Use the richer incident stream so SMB/MSSQL protocol annotations reach the backend.
RUN rm -f \
	/opt/dionaea/template/etc/dionaea/ihandlers-enabled/log_json.yaml \
	/opt/dionaea/etc/dionaea/ihandlers-enabled/log_json.yaml
COPY log_incident.yaml /opt/dionaea/template/etc/dionaea/ihandlers-enabled/log_incident.yaml
COPY log_incident.yaml /opt/dionaea/etc/dionaea/ihandlers-enabled/log_incident.yaml

# Pre-create var/lib directory structure from template.
# When docker-compose mounts a named volume at var/lib/dionaea/binaries,
# Docker creates the parent var/lib/dionaea/, causing the entrypoint to skip
# init_lib. Without this RUN, required subdirs (ftp, http, sip, etc.) are
# missing and dionaea segfaults. Building them into the image avoids that.
RUN cd /opt/dionaea && cp -a template/lib var/ && chown -R dionaea:dionaea var/lib

EXPOSE 21 80 445 1433
