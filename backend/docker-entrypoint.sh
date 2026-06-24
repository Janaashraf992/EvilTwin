#!/bin/sh
set -eu

MODEL_PATH="${MODEL_PATH:-/app/ai/model.pkl}"
PRE_SESSION_MODEL_PATH="${PRE_SESSION_MODEL_PATH:-/app/ai/pre_session_model.pkl}"

if [ ! -f "$MODEL_PATH" ]; then
  echo "Model not found at $MODEL_PATH; training a replacement..." >&2
  python -m ai.train
fi

if [ ! -f "$PRE_SESSION_MODEL_PATH" ]; then
  echo "Pre-session model not found at $PRE_SESSION_MODEL_PATH; training a replacement..." >&2
  python -m ai.train_pre_session
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

python -m bootstrap

exec "$@"