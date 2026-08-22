# pyright: reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportArgumentType=false, reportUnusedFunction=false
"""FastAPI app: Inngest serve mount + health. Read-model endpoints land at P4.

Same pragma rationale as pipeline/functions.py — untyped SDK boundary.
"""

from __future__ import annotations

import os
from pathlib import Path

import inngest.fast_api
from fastapi import FastAPI, HTTPException
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

    @app.get("/api/coverage")
    def get_coverage() -> dict[str, object]:
        return read_models.coverage()

    @app.get("/api/gaps")
    def get_gaps() -> list[dict[str, object]]:
        return read_models.gaps()

    @app.get("/api/model")
    def get_model() -> dict[str, object]:
        return read_models.model_card()

    @app.get("/api/f3-matrix")
    def get_f3_matrix() -> dict[str, object]:
        return read_models.f3_view()

    @app.post("/api/chat")
    def chat(request: ChatRequest) -> ChatResponse:
        return answer_chat(request, read_models.registry())

    if os.environ.get("FORGE_INNGEST_MODE", "serve") == "serve":
        inngest.fast_api.serve(app, client, functions)

    dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    return app


app = create_app()
