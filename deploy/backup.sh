#!/bin/sh
set -eu

compose_file="${FORGE_COMPOSE_FILE:-docker-compose.vps.yml}"
env_file="${FORGE_ENV_FILE:-deploy/vps.env}"
root="${FORGE_DATA_ROOT:-data}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
destination="${FORGE_BACKUP_DIR:-$root/backups/$stamp}"

mkdir -p "$destination/minio"

restart_runtime() {
  docker compose --env-file "$env_file" -f "$compose_file" up -d inngest api worker >/dev/null 2>&1 || true
}
trap restart_runtime EXIT INT TERM

# Establish one cross-store boundary: no pipeline writer remains active while
# PostgreSQL, Redis, MinIO and host artifacts are captured.
docker compose --env-file "$env_file" -f "$compose_file" stop -t "${FORGE_BACKUP_STOP_TIMEOUT:-30}" api worker inngest

docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  pg_dump -U postgres --format=custom --no-owner --no-acl forge > "$destination/forge.dump"
docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  pg_dump -U postgres --format=custom --no-owner --no-acl inngest > "$destination/inngest.dump"
docker compose --env-file "$env_file" -f "$compose_file" exec -T redis \
  redis-cli --rdb /tmp/forge-backup.rdb >/dev/null
docker compose --env-file "$env_file" -f "$compose_file" cp \
  redis:/tmp/forge-backup.rdb "$destination/redis.rdb" >/dev/null
docker compose --env-file "$env_file" -f "$compose_file" exec -T redis \
  rm -f /tmp/forge-backup.rdb

absolute_destination="$(cd "$destination" && pwd)"
docker compose --env-file "$env_file" -f "$compose_file" run --rm \
  -v "$absolute_destination/minio:/backup" --entrypoint /bin/sh minio-init -c \
  'mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null && mc mirror --overwrite --preserve local/forge-artifacts /backup'

tar -C "$root" \
  --exclude='./services' \
  --exclude='./backups' \
  -czf "$destination/forge-data.tar.gz" .

(
  cd "$destination"
  sha256sum forge.dump inngest.dump redis.rdb forge-data.tar.gz > SHA256SUMS
  if [ -n "$(find minio -type f -print -quit)" ]; then
    find minio -type f -print0 | sort -z | xargs -0 sha256sum >> SHA256SUMS
  fi
)

printf 'FORGE backup created at %s\n' "$destination"
