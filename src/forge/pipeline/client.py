"""Inngest client instance — the ONLY module importing inngest besides functions."""

from __future__ import annotations

import logging
import os

import inngest

client = inngest.Inngest(
    app_id="forge",
    app_version=os.environ.get("FORGE_APP_VERSION"),
    is_production=os.environ.get("INNGEST_DEV", "1") not in {"1", "true", "yes"},
    api_base_url=os.environ.get("INNGEST_BASE_URL"),
    event_api_base_url=os.environ.get("INNGEST_BASE_URL"),
    event_key=os.environ.get("INNGEST_EVENT_KEY"),
    signing_key=os.environ.get("INNGEST_SIGNING_KEY"),
    logger=logging.getLogger("forge.inngest"),
)
