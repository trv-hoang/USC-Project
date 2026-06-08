import statistics
from pathlib import Path
from eadf.evaluation.ground_truth import BenchmarkPair
from eadf.evaluation.eda import ContractStats, compute_eda


def _pair(pid, behavior, v1, v2, pattern, n_vars):
    # n_vars used by the fake analyzer to vary structural stats
    return BenchmarkPair(
        id=pid, name=pid, category="c",
        v1_path=Path(f"/{pid}/v1.sol"), v2_path=Path(f"/{pid}/v2.sol"),
        behavior=behavior, vulns_v1=set(), vulns_v2={"storage-collision-cross-version"} if v2 else set(),
        proxy_pattern=pattern, notes="",
    )


def test_compute_eda_distributions():
    pairs = [
        _pair("P1", "Introduce Vulnerability", False, True, "UUPS", 2),
        _pair("P2", "Smooth Upgrade", False, False, "Transparent", 3),
    ]
    # fake analyzer: LOC = 10*n, vars = n, slots = n, packed False, dynamic False
    sizes = {"P1": 2, "P2": 3}
    def fake_analyze(path: Path) -> ContractStats:
        n = sizes[Path(path).parts[1]]
        return ContractStats(loc=10 * n, n_state_vars=n, n_slots=n,
                             packed=False, has_dynamic=False)

    tables = compute_eda(pairs, fake_analyze)
    assert tables.behavior_dist["Introduce Vulnerability"] == 1
    assert tables.behavior_dist["Smooth Upgrade"] == 1
    assert tables.proxy_dist["UUPS"] == 1
    assert tables.vuln_dist["storage-collision-cross-version"] == 1
    # LOC across 4 implementations: P1 v1+v2 (20,20), P2 (30,30)
    assert tables.loc_stats["min"] == 20
    assert tables.loc_stats["max"] == 30

    # rendering returns markdown containing the section anchors
    md = tables.render_all()
    assert "B.1" in md and "B.5" in md
