#!/bin/sh
set -eu

: "${INNGEST_EVENT_KEY:?set INNGEST_EVENT_KEY}"
API_URL="${INNGEST_API_URL:-http://127.0.0.1:8288}"
OUTPUT="${FORGE_SUPERVISION_LOG:-/tmp/opencode/forge-one-hour-supervision.log}"
INTERVAL="${FORGE_FEED_INTERVAL_SECONDS:-90}"
DURATION="${FORGE_SUPERVISION_SECONDS:-3600}"
START=$(date +%s)
END=$((START + DURATION))
SEED=${FORGE_START_SEED:-12000}

submit() {
  curl -fsS -X POST "$API_URL/e/$INNGEST_EVENT_KEY" \
    -H 'Content-Type: application/json' \
    -d "$1" >> "$OUTPUT"
  printf '\n' >> "$OUTPUT"
}

while [ "$(date +%s)" -lt "$END" ]; do
  for FAMILY in ai_bank_impersonation ai_family_emergency ai_investment_coaching; do
    submit "{\"name\":\"cycle.requested\",\"data\":{\"seed\":$SEED,\"scenario\":\"ai_assisted_app_scam\",\"family_slug\":\"$FAMILY\"}}"
    SEED=$((SEED + 1))
  done
  submit "{\"name\":\"cycle.requested\",\"data\":{\"seed\":$SEED}}"
  SEED=$((SEED + 1))
  printf '%s submitted_through_seed=%s\n' "$(date -Iseconds)" "$SEED" >> "$OUTPUT"
  sleep "$INTERVAL"
done
