"""Static configuration: weights, threshold, detector list.

Spec references: SPEC.md §5.4 (Slither detectors), §5.5 (confidence weights).
"""

WEIGHTS = {
    "pos": 0.25,
    "pattern": 0.20,
    "semantic": 0.25,
    "type": 0.15,
    "slot": 0.15,
}

CONFIDENCE_THRESHOLD = 0.6

SLITHER_DETECTORS = [
    "uninitialized-local",
    "uninitialized-state",
    "controlled-delegatecall",
    "suicidal",
    "missing-zero-check",
    "reentrancy-eth",
    "reentrancy-no-eth",
]

DYNAMIC_SOLIDITY_TYPES = frozenset({"mapping", "array_dynamic"})

SOLC_VERSION = "0.8.24"
