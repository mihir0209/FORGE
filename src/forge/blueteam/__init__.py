"""forge.blueteam — trace-only investigation (blind by type, see ADR-0002)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from forge.blueteam._heuristics import all_signals
from forge.contracts.contracts import (
    BlueAssessment,
    BlueReport,
    ObservedTraceView,
    Provenance,
    Signal,
    Verdict,
)

if TYPE_CHECKING:
    from forge.reasoning import ReasoningClient

_INVESTIGATOR = "heuristic-v1"


def _heuristic_assessment(signals: list[Signal]) -> BlueAssessment:
    """Verdict policy from observed evidence strength only — no ground truth."""
    top = signals[0].strength if signals else 0.0
    if top >= 0.75:
        verdict = Verdict.DEFEATED
    elif top >= 0.35:
        verdict = Verdict.PARTIAL
    else:
        verdict = Verdict.MISSED
    return BlueAssessment(
        verdict=verdict,
        confidence=top,
        mitigations=_mitigations_for(signals),
        uncovered_gaps=[] if verdict != Verdict.MISSED else ["no observable signal"],
    )


def _mitigations_for(signals: list[Signal]) -> list[str]:
    m: list[str] = []
    names = {s.name for s in signals}
    if "velocity_burst" in names:
        m.append("rate-limit payments per customer per 30min window")
    if "new_device_payment" in names:
        m.append("step-up authentication for new-device sessions")
    if "refund_chain" in names:
        m.append("hold refunds above customer-level velocity threshold")
    if "off_hours_payments" in names:
        m.append("risk-score off-hours band higher for low-tenure customers")
    return m


def investigate(
    view: ObservedTraceView,
    reasoning: ReasoningClient | None = None,
) -> BlueReport:
    signals = all_signals(view)

    if reasoning is None:
        assessment = _heuristic_assessment(signals)
        provider, model = "none", _INVESTIGATOR
    else:
        listing = (
            "\n".join(
                f"- {s.name} ({s.strength:.2f}): {s.description} refs={s.evidence_refs[:6]}"
                for s in signals
            )
            or "- none"
        )
        assessment = reasoning.complete(
            BlueAssessment,
            "You are a blue-team fraud investigator. Assess ONLY what the events show.",
            f"Signals observed:\n{listing}\n\nGive verdict/confidence/mitigations/gaps.",
        )
        provider, model = reasoning.name, reasoning.name

    known_ids = set(view.event_ids)
    safe_signals = [
        Signal(
            name=s.name,
            description=s.description,
            strength=s.strength,
            evidence_refs=[r for r in s.evidence_refs if r in known_ids],
        )
        for s in signals
    ]

    return BlueReport(
        investigator_id=_INVESTIGATOR if reasoning is None else f"{_INVESTIGATOR}+{provider}",
        signals=safe_signals,
        motifs=[
            # v1: motifs folded into signals; kept as contract surface
        ],
        mitigations=assessment.mitigations,
        confidence=assessment.confidence,
        verdict=assessment.verdict,
        uncovered_gaps=assessment.uncovered_gaps,
        provenance=Provenance(provider=provider, model=model),
    )


__all__ = ["investigate"]
