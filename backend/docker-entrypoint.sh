#!/bin/sh
set -eu

MODEL_PATH="${MODEL_PATH:-/app/ai/model.pkl}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-eviltwin}"
POSTGRES_USER="${POSTGRES_USER:-eviltwin}"

required_tables_present() {
  PGPASSWORD="$POSTGRES_PASSWORD" psql \
    -h "$POSTGRES_HOST" \
    -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" \
    -d "$POSTGRES_DB" \
    -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users', 'attacker_profiles', 'session_logs', 'alerts')" \
    | grep -qx '4'
}

reset_alembic_version() {
  PGPASSWORD="$POSTGRES_PASSWORD" psql \
    -h "$POSTGRES_HOST" \
    -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" \
    -d "$POSTGRES_DB" \
    -c 'DROP TABLE IF EXISTS alembic_version'
}

if [ ! -f "$MODEL_PATH" ]; then
  echo "Model not found at $MODEL_PATH; training a replacement..." >&2
  python -m ai.train
fi

attempt=1
until alembic upgrade head; do
  if [ "$attempt" -ge 10 ]; then
    echo "Database migrations failed after $attempt attempts" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  echo "Database not ready for migrations yet; retrying..." >&2
  sleep 2
done

if ! required_tables_present; then
  echo "Required tables missing after alembic upgrade; resetting revision state and retrying migrations..." >&2
  reset_alembic_version
  alembic upgrade head
fi

python -m bootstrap

exec "$@"