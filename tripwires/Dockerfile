FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tripwire.py .
COPY bait/ /bait/

# Seed for the leaked ".git" clue (level 3). A literal .git dir cannot be tracked
# in git, so the entrypoint materializes /bait/.git from this seed at startup.
COPY gitseed/ /gitseed/
COPY entrypoint.sh /entrypoint.sh

EXPOSE 8080

CMD ["sh", "/entrypoint.sh"]
