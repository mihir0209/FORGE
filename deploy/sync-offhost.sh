#!/usr/bin/env bash
set -euo pipefail

# FORGE Off-Host Backup Sync Script
# Usage: ./deploy/sync-offhost.sh [TARGET_URI]
# Example TARGET_URI:
#   s3://my-backup-bucket/forge-backups/
#   user@remote-vps.example.com:/var/backups/forge/
#   /mnt/external-volume/forge-backups/

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${REPO_ROOT}/data/backups"
RECEIPT_FILE="${REPO_ROOT}/data/backup-offhost-sync.json"

TARGET_URI="${1:-${FORGE_BACKUP_TARGET_URI:-}}"

if [[ -z "${TARGET_URI}" ]]; then
  echo "Error: No backup target URI provided."
  echo "Provide as argument: ./deploy/sync-offhost.sh <TARGET_URI>"
  echo "Or set FORGE_BACKUP_TARGET_URI in environment."
  exit 1
fi

if [[ ! -d "${BACKUP_DIR}" ]]; then
  echo "No backups found at ${BACKUP_DIR}."
  exit 1
fi

LATEST_BUNDLE="$(ls -1td "${BACKUP_DIR}"/* 2>/dev/null | head -n 1 || true)"
if [[ -z "${LATEST_BUNDLE}" || ! -d "${LATEST_BUNDLE}" ]]; then
  echo "No backup bundles found in ${BACKUP_DIR}."
  exit 1
fi

BUNDLE_NAME="$(basename "${LATEST_BUNDLE}")"
echo "Syncing latest backup bundle: ${BUNDLE_NAME} -> ${TARGET_URI}"

START_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if [[ "${TARGET_URI}" =~ ^s3:// ]]; then
  if command -v aws >/dev/null 2>&1; then
    aws s3 sync "${LATEST_BUNDLE}" "${TARGET_URI%/}/${BUNDLE_NAME}/" --exact-timestamps
  else
    echo "aws CLI not found for S3 sync."
    exit 1
  fi
elif [[ "${TARGET_URI}" =~ : ]]; then
  if command -v rsync >/dev/null 2>&1; then
    rsync -avz "${LATEST_BUNDLE}" "${TARGET_URI%/}/"
  else
    echo "rsync not found for remote copy."
    exit 1
  fi
else
  mkdir -p "${TARGET_URI}"
  if command -v rsync >/dev/null 2>&1; then
    rsync -av "${LATEST_BUNDLE}" "${TARGET_URI%/}/"
  else
    cp -r "${LATEST_BUNDLE}" "${TARGET_URI%/}/"
  fi
fi

FINISH_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat <<EOF > "${RECEIPT_FILE}"
{
  "bundle_name": "${BUNDLE_NAME}",
  "target_uri": "${TARGET_URI}",
  "sync_started_at": "${START_TIME}",
  "sync_completed_at": "${FINISH_TIME}",
  "status": "synced"
}
EOF

echo "Off-host sync complete for ${BUNDLE_NAME}. Receipt written to ${RECEIPT_FILE}."
