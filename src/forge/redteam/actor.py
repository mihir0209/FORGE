"""Red-team actor runtime: plan and execute tools inside the sandbox."""

from __future__ import annotations

from typing import TYPE_CHECKING

from forge.actor_sandbox import ActorSandbox, SandboxResult, ai_assisted_app_scam_plan
from forge.contracts.contracts import ActionPlan, StrategySpec, WorldSeed

if TYPE_CHECKING:
    from forge.reasoning import ReasoningClient

_SYSTEM = """You are a synthetic red-team actor inside FORGE's non-routable sandbox.
Produce an ActionPlan using only the declared ToolKind values. All identities,
communications and payments are synthetic. Do not target real people or systems.
Preparation tools run off-site and are hidden from defenders. Bank-session actions
must expose only evidence realistically available to the bank or payment network."""


def plan_strategy(
    strategy: StrategySpec,
    cycle_id: str,
    reasoning: ReasoningClient | None = None,
) -> ActionPlan:
    if reasoning is None:
        return ai_assisted_app_scam_plan(strategy.strategy_id, cycle_id)
    return reasoning.complete(
        ActionPlan,
        _SYSTEM,
        f"STRATEGY={strategy.model_dump(mode='json')}\nCYCLE_ID={cycle_id}",
    )


def execute_strategy(
    strategy: StrategySpec,
    *,
    cycle_id: str,
    seed: WorldSeed,
    sandbox: ActorSandbox,
    reasoning: ReasoningClient | None = None,
) -> SandboxResult:
    plan = plan_strategy(strategy, cycle_id, reasoning)
    return sandbox.execute(plan, seed, cycle_id=cycle_id)
