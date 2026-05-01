FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user --prefer-binary --timeout 300 --retries 5 -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 eviltwin

COPY --from=builder --chown=eviltwin:eviltwin /root/.local /home/eviltwin/.local
COPY --chown=eviltwin:eviltwin . .

RUN chmod +x /app/docker-entrypoint.sh

ENV PATH=/home/eviltwin/.local/bin:$PATH

USER eviltwin

RUN python -m ai.train

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
