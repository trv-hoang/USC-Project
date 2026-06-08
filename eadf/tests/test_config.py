from eadf.config import WEIGHTS, CONFIDENCE_THRESHOLD, SLITHER_DETECTORS

def test_weights_sum_to_one():
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

def test_confidence_threshold():
    assert CONFIDENCE_THRESHOLD == 0.6

def test_slither_detectors_match_spec():
    expected = {
        "uninitialized-local",
        "uninitialized-state",
        "controlled-delegatecall",
        "suicidal",
        "missing-zero-check",
        "reentrancy-eth",
        "reentrancy-no-eth",
    }
    assert set(SLITHER_DETECTORS) == expected
