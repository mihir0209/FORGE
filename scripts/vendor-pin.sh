#!/usr/bin/env bash
# Pin/verify vendored knowledge bases (see ADR-0001 evidence + research/kb-sources file).
set -euo pipefail
cd "$(dirname "$0")/.."
git submodule update --init --recursive
echo "fight-fraud-framework @ $(git -C vendor/fight-fraud-framework rev-parse HEAD)"
echo "skills                @ $(git -C vendor/skills rev-parse HEAD) ($(git -C vendor/skills describe --tags))"
python3 - << 'EOF'
import json
f3 = json.load(open("vendor/fight-fraud-framework/public/f3-v1.1.json"))
idx = json.load(open("vendor/skills/index.json"))
assert len(f3) == 131, f"F3 entries changed: {len(f3)} (expected 131 = 8 tactics + 123 techniques)"
assert idx["total_skills"] == len(idx["skills"]) == 817, "skills index drift"
print(f"OK: F3 v1.1 ({len(f3)} entries) · skills {idx['total_skills']}")
EOF
