"""Parity: trace_features must derive burst/new_device from forge.signals."""

from forge.contracts.contracts import WorldSeed
from forge.detect import trace_features
from forge.signals import FEATURE_NAMES, all_signals
from forge.simulate import build_legit_trace, simulate
from tests.fixtures_spec import make_spec


def test_trace_features_derives_from_signals() -> None:
    attack_view = simulate(make_spec(), WorldSeed(master_seed=7)).trace.observed_view()
    legit_view = build_legit_trace(WorldSeed(master_seed=7)).observed_view()

    for view in (attack_view, legit_view):
        sigs = {s.name: s.strength for s in all_signals(view)}
        feats = trace_features(view)
        assert feats["burst"] == sigs.get("velocity_burst", 0.0)
        assert feats["new_device"] == (1.0 if "new_device_payment" in sigs else 0.0)
        # FEATURE_NAMES is the single source
        assert set(feats) == set(FEATURE_NAMES)
