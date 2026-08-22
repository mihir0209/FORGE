"""Inngest client instance — the ONLY module importing inngest besides functions."""

from __future__ import annotations

import logging

import inngest

client = inngest.Inngest(
    app_id="forge",
    is_production=False,  # self-hosted dev server; flip via env at deploy
    logger=logging.getLogger("forge.inngest"),
)
