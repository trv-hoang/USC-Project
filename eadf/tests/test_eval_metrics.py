from eadf.evaluation.metrics import (
    Sample, compute_detection_metrics, compute_behavior_accuracy,
)


def test_detection_metrics_pooled():
    in_scope = {"A", "B", "C"}
    samples = [
        # predicted, expected
        Sample("p1", "v2", predicted={"A", "B"}, expected={"A"}),      # TP A, FP B
        Sample("p2", "v2", predicted={"C"}, expected={"C", "B"}),       # TP C, FN B
        Sample("p3", "v1", predicted=set(), expected=set()),            # nothing
    ]
    m = compute_detection_metrics(samples, in_scope)
    assert (m.tp, m.fp, m.fn) == (2, 1, 1)
    assert round(m.precision, 4) == 0.6667
    assert round(m.recall, 4) == 0.6667
    assert round(m.f1, 4) == 0.6667
    assert m.per_detector["B"]["fp"] == 1
    assert m.per_detector["B"]["fn"] == 1


def test_detection_metrics_filters_out_of_scope():
    in_scope = {"A"}
    samples = [Sample("p1", "v2", predicted={"A", "STYLE"}, expected={"A"})]
    m = compute_detection_metrics(samples, in_scope)
    assert (m.tp, m.fp, m.fn) == (1, 0, 0)  # STYLE ignored


def test_detection_metrics_zero_safe():
    m = compute_detection_metrics([], {"A"})
    assert (m.precision, m.recall, m.f1) == (0.0, 0.0, 0.0)


def test_behavior_accuracy():
    bm = compute_behavior_accuracy([
        ("Introduce Vulnerability", "Introduce Vulnerability"),
        ("Fix Vulnerability", "Invalid Upgrade"),
        ("Smooth Upgrade", "Smooth Upgrade"),
    ])
    assert bm.total == 3
    assert bm.correct == 2
    assert round(bm.accuracy, 4) == 0.6667
    assert bm.confusion["Fix Vulnerability"]["Invalid Upgrade"] == 1
