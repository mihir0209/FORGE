# ADR-0002: Versioned Multi-Track Detection Schema

## Status

Accepted

## Context

FORGE must retain detection of established behavioral payment fraud while adding AI-assisted authorized-push-payment scams and optional media authenticity evidence. A single unversioned feature list made old model artifacts either silently incompatible or easy to misrepresent as current. Missing evidence also risked being interpreted as a clean zero.

## Decision

FORGE uses named DetectionTracks, declared EvidenceCapabilities, and a versioned union FeatureSchema. Every recorded cycle stores the schema version, track, evidence capabilities, and exact detector vector used at scoring time. Known historical schemas are adapted into the union by name with unavailable new features set to zero. Unknown schemas are rejected.

Promotion requires a sealed attack-family-disjoint, temporal, or external holdout manifest. Legitimate control families intentionally span partitions; attack families do not. Metrics are reported for the full test set and by held-out family/track; random stratified experiments remain non-promotable.

## Consequences

- One detector can learn established and AI-assisted fraud patterns without erasing either track.
- Media and call evidence remain optional capabilities rather than universal assumptions.
- Historical vectors can be reproduced and audited without re-simulating a different trace.
- The wider feature vector is sparse by design and requires evidence-availability ablations in research reports.
