"""forge.pipeline — durable execution adapters (the ONLY inngest importer)."""

from forge.pipeline.client import client
from forge.pipeline.functions import functions
from forge.pipeline.stages import (
    stage_claim_training_corpus,
    stage_compose,
    stage_finalize,
    stage_gap_mine,
    stage_gate,
    stage_investigate,
    stage_propose_residual_variant,
    stage_simulate,
)

__all__ = [
    "client",
    "functions",
    "stage_claim_training_corpus",
    "stage_compose",
    "stage_finalize",
    "stage_gap_mine",
    "stage_gate",
    "stage_investigate",
    "stage_propose_residual_variant",
    "stage_simulate",
]
