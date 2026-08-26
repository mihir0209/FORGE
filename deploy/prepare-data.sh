#!/bin/sh
set -eu

root="${FORGE_DATA_ROOT:-data}"
postgres_new=0
redis_new=0
minio_new=0
[ -d "$root/services/postgres" ] || postgres_new=1
[ -d "$root/services/redis" ] || redis_new=1
[ -d "$root/services/minio" ] || minio_new=1
mkdir -p \
  "$root/services/postgres" \
  "$root/services/redis" \
  "$root/services/minio" \
  "$root/families" \
  "$root/research" \
  "$root/objects" \
  "$root/artifacts" \
  "$root/models" \
  "$root/runs" \
  "$root/notifications" \
  "$root/backups" \
  "$root/benchmarks"

# The application image runs as uid 10001. Keep repository-backed runtime
# directories writable without requiring host-specific uid ownership.
chmod 0755 "$root"
chmod 0770 \
  "$root/families" \
  "$root/research" \
  "$root/objects" \
  "$root/artifacts" \
  "$root/models" \
  "$root/runs" \
  "$root/notifications" \
  "$root/backups" \
  "$root/benchmarks"

[ "$postgres_new" -eq 0 ] || chmod 0777 "$root/services/postgres"
[ "$redis_new" -eq 0 ] || chmod 0777 "$root/services/redis"
[ "$minio_new" -eq 0 ] || chmod 0777 "$root/services/minio"


printf 'Prepared host-backed FORGE storage under %s\n' "$root"
