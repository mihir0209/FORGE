"""Guarded analyst chat grounded in one CycleRecord."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from forge.config import load_env_file
from forge.reasoning import PydanticAIClient

if TYPE_CHECKING:
    from forge.kb import SQLiteRegistry


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    cycle_id: str | None = None


class ChatResponse(BaseModel):
    answer: str
    evidence_refs: list[str] = Field(default_factory=list)
    uncertainty: str = ""
    refused: bool = False


_UNSAFE = re.compile(
    r"\b(write|create|generate|build|show me how to|help me)\b.{0,45}"
    r"\b(phishing|steal credentials|bypass|target real|cash.?out|malware|exploit)\b",
    re.IGNORECASE,
)


def answer_chat(request: ChatRequest, registry: SQLiteRegistry) -> ChatResponse:
    if _UNSAFE.search(request.message):
        return ChatResponse(
            answer=(
                "I cannot provide operational attack instructions. I can explain the "
                "defensive signals, uncertainty, mitigations, or safe simulation design."
            ),
            uncertainty="Request refused by the defense-only policy.",
            refused=True,
        )

    cycles = registry.cycles()
    cycle = next((c for c in cycles if c.cycle_id == request.cycle_id), None)
    if cycle is None:
        cycle = cycles[-1] if cycles else None
    if cycle is None:
        return ChatResponse(
            answer="No cycle evidence is available yet. Run a cycle first.",
            uncertainty="No grounded case context.",
        )

    allowed_refs = {ref for signal in cycle.blue_report.signals for ref in signal.evidence_refs}
    context = {
        "family": cycle.strategy.attack_family,
        "objective": cycle.strategy.fraud_objective,
        "f3": cycle.strategy.f3.model_dump(mode="json"),
        "signals": [s.model_dump(mode="json") for s in cycle.blue_report.signals],
        "blue_verdict": cycle.blue_report.verdict.value,
        "blue_confidence": cycle.blue_report.confidence,
        "gate": cycle.gate_result.model_dump(mode="json"),
        "mitigations": cycle.blue_report.mitigations,
    }

    load_env_file()
    import os

    if not os.environ.get("OPENAI_API_KEY"):
        top = cycle.blue_report.signals[0].name if cycle.blue_report.signals else "none"
        return ChatResponse(
            answer=(
                f"The selected {cycle.strategy.attack_family.replace('_', ' ')} cycle "
                f"was {cycle.blue_report.verdict.value}; strongest signal: {top}."
            ),
            evidence_refs=sorted(allowed_refs)[:5],
            uncertainty="LLM unavailable; deterministic case summary returned.",
        )

    model = os.environ.get("FORGE_LLM_MODEL", "mimo-v2.5")
    client = PydanticAIClient(f"openai:{model}")
    response = client.complete(
        ChatResponse,
        (
            "You are FORGE's second-line fraud analyst. Answer defensively and only "
            "from the supplied case JSON. Cite only evidence_refs present in context. "
            "Never provide executable fraud, phishing, credential theft, bypass, or "
            "real-target instructions. State uncertainty explicitly."
        ),
        f"CASE={context}\n\nQUESTION={request.message}",
    )
    return response.model_copy(
        update={"evidence_refs": [r for r in response.evidence_refs if r in allowed_refs]}
    )
