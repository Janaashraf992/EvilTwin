FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tripwire.py .
COPY bait/ /bait/

EXPOSE 8080

CMD ["python", "-u", "tripwire.py"]
