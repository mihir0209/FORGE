import pytest
from forge.fx_smurfing_sentinel import FxSmurfingSentinel, FxTransaction

def test_normal_fx_transactions():
    sentinel = FxSmurfingSentinel()
    txs = [
        FxTransaction("tx_1", "ent_1", 120.0, "USD", "EUR", 1700000000),
        FxTransaction("tx_2", "ent_1", 250.0, "USD", "GBP", 1700003600),
    ]
    res = sentinel.analyze("ent_1", txs)
    assert res.risk_tier == "NORMAL"
    assert not res.structuring_detected
    assert res.recommended_action == "ALLOW"

def test_smurfing_and_structuring_detection():
    sentinel = FxSmurfingSentinel()
    # 3 structured transactions just under 0,000 threshold
    txs = [
        FxTransaction("tx_1", "ent_smurf", 9500.0, "USD", "EUR", 1700000000),
        FxTransaction("tx_2", "ent_smurf", 9800.0, "EUR", "JPY", 1700003600),
        FxTransaction("tx_3", "ent_smurf", 9200.0, "JPY", "USDT", 1700007200),
        FxTransaction("tx_4", "ent_smurf", 9400.0, "USDT", "USD", 1700010800),
    ]
    res = sentinel.analyze("ent_smurf", txs)
    assert res.risk_tier == "CRITICAL_AML_FLAG"
    assert res.structuring_detected
    assert res.recommended_action == "FILE_SAR_AND_FREEZE"
    assert len(res.suspicious_transaction_ids) == 4
