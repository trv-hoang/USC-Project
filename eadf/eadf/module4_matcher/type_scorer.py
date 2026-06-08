OPERATION_VULN_MAP = {
    ("INSERT", "StateVariable"): {
        "storage-collision-cross-version": 1.0,
        "uninitialized-state": 0.7,
    },
    ("DELETE", "StateVariable"): {
        "storage-collision-cross-version": 0.8,
    },
    ("UPDATE", "StateVariable"): {
        "storage-collision-cross-version": 0.9,
    },
    ("INSERT", "Function"): {
        "controlled-delegatecall": 0.6,
        "suicidal": 0.6,
        "missing-zero-check": 0.4,
    },
}


def calc_type_score(change_op: str, node_kind: str, detector_id: str) -> float:
    return OPERATION_VULN_MAP.get((change_op, node_kind), {}).get(detector_id, 0.0)
