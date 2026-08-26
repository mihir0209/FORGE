#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf 'usage: %s BACKUP_DIRECTORY\n' "$0" >&2
  exit 2
fi

compose_file="${FORGE_COMPOSE_FILE:-docker-compose.vps.yml}"
env_file="${FORGE_ENV_FILE:-deploy/vps.env}"
backup="$(cd "$1" && pwd)"
suffix="$(date -u +%s)-$$"
restore_dir="/tmp/forge-minio-restore-$suffix"
forge_db="forge_restore_$suffix"
inngest_db="inngest_restore_$suffix"
minio_bucket="forge-restore-$suffix"

cleanup() {
  docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
    dropdb -U postgres --if-exists "$forge_db" >/dev/null 2>&1 || true
  docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
    dropdb -U postgres --if-exists "$inngest_db" >/dev/null 2>&1 || true
  docker compose --env-file "$env_file" -f "$compose_file" run --rm \
    --entrypoint /bin/sh minio-init -c \
    "mc alias set local http://minio:9000 \"\$MINIO_ROOT_USER\" \"\$MINIO_ROOT_PASSWORD\" >/dev/null && mc rb --force local/$minio_bucket >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  if [ -d "$restore_dir" ]; then
    docker compose --env-file "$env_file" -f "$compose_file" run --rm \
      -v "$restore_dir:/cleanup" --entrypoint /bin/sh minio-init -c \
      'rm -rf /cleanup/*' >/dev/null 2>&1 || true
    rmdir "$restore_dir" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

(cd "$backup" && sha256sum -c SHA256SUMS)
tar -tzf "$backup/forge-data.tar.gz" >/dev/null
docker compose --env-file "$env_file" -f "$compose_file" cp \
  "$backup/redis.rdb" redis:/tmp/forge-verify.rdb >/dev/null
docker compose --env-file "$env_file" -f "$compose_file" exec -T redis \
  redis-check-rdb /tmp/forge-verify.rdb >/dev/null
docker compose --env-file "$env_file" -f "$compose_file" exec -T redis \
  rm -f /tmp/forge-verify.rdb

absolute_backup="$(cd "$backup" && pwd)"
mkdir -p "$restore_dir"
docker compose --env-file "$env_file" -f "$compose_file" run --rm \
  -v "$absolute_backup/minio:/restore:ro" -v "$restore_dir:/verified" \
  --entrypoint /bin/sh minio-init -c \
  "mc alias set local http://minio:9000 \"\$MINIO_ROOT_USER\" \"\$MINIO_ROOT_PASSWORD\" >/dev/null && mc mb local/$minio_bucket >/dev/null && mc mirror /restore local/$minio_bucket >/dev/null && mc mirror local/$minio_bucket /verified >/dev/null"
while IFS= read -r checksum path; do
  case "$path" in
    minio/*)
      restored="$restore_dir/${path#minio/}"
      [ -f "$restored" ] && [ "$(sha256sum "$restored" | cut -d ' ' -f 1)" = "$checksum" ] || {
        printf 'MinIO restored object checksum mismatch: %s\n' "$path" >&2
        exit 1
      }
      ;;
  esac
done < "$backup/SHA256SUMS"

docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  createdb -U postgres "$forge_db"
docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  createdb -U postgres "$inngest_db"
docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  pg_restore -U postgres --no-owner --no-acl --dbname "$forge_db" < "$backup/forge.dump"
docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  pg_restore -U postgres --no-owner --no-acl --dbname "$inngest_db" < "$backup/inngest.dump"
docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  psql -U postgres -d "$forge_db" -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM forge_cycles' >/dev/null
docker compose --env-file "$env_file" -f "$compose_file" exec -T postgres \
  psql -U postgres -d "$inngest_db" -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM migrations' >/dev/null

receipt_root="${FORGE_DATA_ROOT:-data}"
verified_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$receipt_root/backup-verification.json" <<EOF
{"schema_version":"forge-backup-verification-v1","verified_at":"$verified_at","backup_directory":"$(basename "$backup")","postgres_forge":true,"postgres_inngest":true,"redis_rdb":true,"artifact_archive":true,"checksums":true,"off_host":false}
EOF

printf 'FORGE backup restore verification passed for %s\n' "$backup"
