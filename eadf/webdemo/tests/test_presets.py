import presets


def test_four_presets_with_expected_behaviors():
    ids = [p.id for p in presets.PRESETS]
    assert ids == ["storage_collision", "uninitialized", "unauthorized", "smooth"]
    by_id = {p.id: p for p in presets.PRESETS}
    assert by_id["storage_collision"].expected_behavior == "Introduce Vulnerability"
    assert by_id["smooth"].expected_behavior == "Smooth Upgrade"


def test_preset_source_files_exist():
    for p in presets.PRESETS:
        assert p.v1.is_file(), f"missing {p.v1}"
        assert p.v2.is_file(), f"missing {p.v2}"


def test_get_returns_preset_or_none():
    assert presets.get("unauthorized").label == "Unauthorized Upgrade"
    assert presets.get("nope") is None
