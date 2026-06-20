#!/bin/bash
set -e

if [ -f /app/.env ]; then
    set -a
    . /app/.env
    set +a
fi

export POSTGRES_HOST="localhost"
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"
export POSTGRES_DB="${POSTGRES_DB:-eviltwin}"
export POSTGRES_USER="${POSTGRES_USER:-eviltwin}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
export COWRIE_TAIL_ENABLED="false"
export DIONAEA_TAIL_ENABLED="false"

PGDATA="/var/lib/postgresql/16/main"

echo "=== EvilTwin Single-Container Startup ==="

mkdir -p /var/log/postgresql
chown postgres:postgres /var/log/postgresql

echo "Starting PostgreSQL..."
pg_ctlcluster 16 main start
sleep 3

pg_isready -q -h localhost -p 5432 || {
    echo "ERROR: PostgreSQL failed to start"
    exit 1
}

echo "Setting up database..."
su postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='$POSTGRES_USER'\" | grep -q 1 || psql -c \"CREATE ROLE $POSTGRES_USER WITH LOGIN PASSWORD '$POSTGRES_PASSWORD'\""
su postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB'\" | grep -q 1 || psql -c \"CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER\""

echo "Running database migrations..."
cd /app
alembic upgrade head

echo "Running bootstrap..."
python -m bootstrap

echo "Stopping temporary PostgreSQL..."
pg_ctlcluster 16 main stop
sleep 2

echo "Starting all services via supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
