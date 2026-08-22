# pyright: reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportArgumentType=false, reportUnusedFunction=false
"""FastAPI app: Inngest serve mount + health. Read-model endpoints land at P4.

Same pragma rationale as pipeline/functions.py — untyped SDK boundary.
"""

from __future__ import annotations

import logging

import inngest.fast_api
from fastapi import FastAPI

import forge
from forge.pipeline.client import client
from forge.pipeline.functions import functions

logging.basicConfig(level=logging.DEBUG)


def create_app() -> FastAPI:
    app = FastAPI(
        title="FORGE",
        description="Fraud Offense-defense Research and Generation Engine",
        version=forge.__version__,
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    inngest.fast_api.serve(app, client, functions)
    return app


app = create_app()
