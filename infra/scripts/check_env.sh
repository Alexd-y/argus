#!/usr/bin/env bash
set -euo pipefail
REQUIRED_VARS=(POSTGRES_PASSWORD MINIO_SECRET_KEY JWT_SECRET)
missing=0
for var in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is not set" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "Set required variables in infra/.env before running docker compose." >&2
  exit 1
fi
echo "All required environment variables are set."
