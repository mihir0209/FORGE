# pyright: reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportArgumentType=false, reportUnusedFunction=false
"""FastAPI app: Inngest serve mount + health. Read-model endpoints land at P4.

Same pragma rationale as pipeline/functions.py — untyped SDK boundary.
"""

from __future__ import annotations

import os
from pathlib import Path

import inngest.fast_api
from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import forge
from forge.api import read_models
from forge.api.chat import ChatRequest, ChatResponse, answer_chat
from forge.pipeline.client import client
from forge.pipeline.functions import functions


def create_app() -> FastAPI:
    app = FastAPI(
        title="FORGE",
        description="Fraud Offense-defense Research and Generation Engine",
        version=forge.__version__,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/cycles")
    def list_cycles() -> list[dict[str, object]]:
        return read_models.cycles()

    @app.get("/api/cycles/{cycle_id}")
    def get_cycle(cycle_id: str) -> dict[str, object]:
        cycle = read_models.cycle_detail(cycle_id)
        if cycle is None:
            raise HTTPException(status_code=404, detail="cycle not found")
        return cycle

    @app.get("/api/strategies")
    def get_strategies(
        limit: int = Query(default=25, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        query: str | None = Query(default=None, max_length=120),
    ) -> dict[str, object]:
        return read_models.strategy_repository(limit=limit, offset=offset, query=query)

    @app.get("/api/coverage")
    def get_coverage() -> dict[str, object]:
        return read_models.coverage()

    @app.get("/api/gaps")
    def get_gaps() -> list[dict[str, object]]:
        return read_models.gaps()

    @app.get("/api/model")
    def get_model() -> dict[str, object]:
        return read_models.model_card()

    @app.get("/api/families")
    def get_families() -> list[dict[str, object]]:
        return read_models.families()

    @app.get("/api/f3-matrix")
    def get_f3_matrix() -> dict[str, object]:
        return read_models.f3_view()

    @app.get("/api/operations")
    def get_operations() -> dict[str, object]:
        return read_models.operations()

    @app.get("/api/variants")
    def get_variants() -> list[dict[str, object]]:
        return read_models.variants()

    def require_operator_token(token: str | None) -> None:
        expected = os.environ.get("FORGE_OPERATOR_TOKEN")
        if not expected:
            raise HTTPException(status_code=503, detail="operator actions are disabled")
        if token != expected:
            raise HTTPException(status_code=403, detail="invalid operator token")

    @app.post("/api/demo", status_code=status.HTTP_202_ACCEPTED)
    async def trigger_demo(x_forge_operator: str | None = Header(default=None)) -> dict[str, object]:
        from forge.pipeline.dispatch import enqueue_competition_demo

        require_operator_token(x_forge_operator)
        return await enqueue_competition_demo()

    @app.post("/api/workers/probe", status_code=status.HTTP_202_ACCEPTED)
    async def probe_workers(x_forge_operator: str | None = Header(default=None)) -> dict[str, object]:
        from forge.pipeline.dispatch import enqueue_worker_probes

        require_operator_token(x_forge_operator)
        return await enqueue_worker_probes(
            int(os.environ.get("FORGE_WORKER_REPLICAS", "5"))
        )

    @app.post("/api/chat")
    def chat(request: ChatRequest) -> ChatResponse:
        return answer_chat(request, read_models.registry())

    if os.environ.get("FORGE_INNGEST_MODE", "serve") == "serve":
        inngest.fast_api.serve(app, client, functions)

    dist = Path(
        os.environ.get(
            "FORGE_FRONTEND_DIST",
            Path(__file__).resolve().parents[3] / "frontend" / "dist",
        )
    )
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    return app


app = create_app()
