FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir asyncssh

COPY ssh_banner.py server.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

EXPOSE 22 8080

ENTRYPOINT ["./entrypoint.sh"]
