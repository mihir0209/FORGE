"""Fidelity metrics v1: does the generated world behave like its own spec?

These are implementation-honesty checks, not external realism benchmarks: they
verify the generator matches the declared category profiles (PSI), that timing
gaps stay bursty-but-bounded (KS vs exponential), that hourly volume is roughly
memoryless (lag-1 autocorrelation), and that attack injection barely moves the
customer-merchant graph (density delta). Tuning against external reference
statistics comes later; bounds for now live in tests.
"""

from __future__ import annotations

import itertools

import numpy as np

from forge.contracts.contracts import FidelityReport, TraceEvent


def psi(observed: np.ndarray, reference: np.ndarray, bins: int = 10) -> float:
    """Population Stability Index between two samples (quantile bins of reference)."""
    if len(observed) == 0 or len(reference) == 0:
        return 0.0
    edges = np.quantile(reference, np.linspace(0.0, 1.0, bins + 1))
    edges[0], edges[-1] = -np.inf, np.inf
    ref_counts = np.histogram(reference, bins=edges)[0] / len(reference)
    obs_counts = np.histogram(observed, bins=edges)[0] / len(observed)
    eps = 1e-6
    return float(
        np.sum((obs_counts - ref_counts) * np.log((obs_counts + eps) / (ref_counts + eps)))
    )


def ks_statistic(a: np.ndarray, b: np.ndarray) -> float:
    """Two-sample Kolmogorov-Smirnov statistic without scipy."""
    if len(a) == 0 or len(b) == 0:
        return 0.0
    combined = np.sort(np.concatenate([a, b]))
    cdf_a = np.searchsorted(np.sort(a), combined, side="right") / len(a)
    cdf_b = np.searchsorted(np.sort(b), combined, side="right") / len(b)
    return float(np.max(np.abs(cdf_a - cdf_b)))


def lag1_autocorr(series: np.ndarray) -> float:
    x = series.astype(float) - float(np.mean(series))
    denom = float(np.dot(x, x))
    if denom <= 0 or len(x) < 2:
        return 0.0
    return float(np.dot(x[:-1], x[1:]) / denom)


def payment_graph_density(events: list[TraceEvent]) -> float:
    """Density of the customer -> merchant bipartite payment graph."""
    customers = {e.actor_id for e in events if e.kind == "payment"}
    merchants = {str(e.payload["merchant"]) for e in events if e.kind == "payment"}
    edges = {(e.actor_id, str(e.payload["merchant"])) for e in events if e.kind == "payment"}
    n, m = len(customers), len(merchants)
    if n == 0 or m == 0:
        return 0.0
    return len(edges) / (n * m)


def compute_fidelity(
    events: list[TraceEvent],
    *,
    reference_amounts: np.ndarray,
    gap_reference_rng: np.random.Generator,
    pre_attack_density: float | None = None,
    reachability_ok: bool,
) -> FidelityReport:
    legit = [e for e in events if not e.is_attack_step]
    payments = [e for e in legit if e.kind == "payment"]
    amounts = np.array([float(p.payload["amount"]) for p in payments])

    ordered = sorted(legit, key=lambda e: e.ts)
    gaps = np.array(
        [
            (b.ts - a.ts).total_seconds()
            for a, b in itertools.pairwise(ordered)
            if b.kind == "payment"
        ]
    )

    # hourly counts across the full horizon for autocorrelation
    if payments:
        t0 = ordered[0].ts
        hours = np.array([(p.ts - t0).total_seconds() // 3600 for p in payments])
        span = int(hours.max()) + 1 if len(hours) else 1
        counts = np.bincount(hours.astype(int), minlength=span)
    else:
        counts = np.zeros(1)

    density_now = payment_graph_density(events)

    notes: list[str] = []
    if pre_attack_density is not None and abs(density_now - pre_attack_density) > 0.05:
        notes.append("graph density moved >5% after injection")

    # memorylessness check: observed gaps vs exponential fitted on their own mean
    gap_scale = float(np.mean(gaps)) if len(gaps) else 1.0

    return FidelityReport(
        psi_amount=psi(amounts, reference_amounts),
        ks_timestamp_gap=ks_statistic(
            gaps,
            gap_reference_rng.exponential(scale=gap_scale, size=len(gaps)),
        ),
        graph_density_delta=float(density_now - pre_attack_density)
        if pre_attack_density is not None
        else 0.0,
        temporal_autocorr=lag1_autocorr(counts),
        reachability_ok=reachability_ok,
        notes=notes,
    )
