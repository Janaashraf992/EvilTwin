FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

FROM python:3.11-slim AS python-builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --user --prefer-binary -r requirements.txt

FROM python:3.11-slim

ENV TZ=Africa/Cairo

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    lsb-release \
    tzdata \
    && sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list' \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg \
    && apt-get update && apt-get install -y --no-install-recommends \
    postgresql-16 \
    nginx \
    supervisor \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

COPY --from=python-builder /root/.local /usr/local
COPY backend/ .

RUN python -m ai.train
RUN python -m ai.train_pre_session

RUN mkdir -p /var/log/supervisor /var/log/eviltwin /run/postgresql \
    && chown -R postgres:postgres /run/postgresql \
    && chmod 2777 /run/postgresql

RUN rm -f /etc/nginx/sites-enabled/default
COPY nginx-single.conf /etc/nginx/sites-available/default
RUN ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

COPY --from=frontend-builder /app/dist /usr/share/nginx/html

COPY .env /app/.env

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV POSTGRES_HOST=localhost
ENV POSTGRES_PORT=5432
ENV POSTGRES_DB=eviltwin
ENV POSTGRES_USER=eviltwin
ENV COWRIE_TAIL_ENABLED=false
ENV DIONAEA_TAIL_ENABLED=false
ENV PYTHONUNBUFFERED=1

EXPOSE 8000 3000

ENTRYPOINT ["/entrypoint.sh"]
