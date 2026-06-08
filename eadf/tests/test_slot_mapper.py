"""Tests for compute_slot_mapping and size_of.

Spec reference: SPEC.md §5.3 + design spec §9.1.
"""
from eadf.models import StateVar
from eadf.module2_ast_diff.slot_mapper import compute_slot_mapping, size_of


def _sv(name, t, dynamic=False):
    return StateVar(name=name, type=t, is_dynamic=dynamic, visibility="public")


def test_single_uint256_at_slot_0():
    m = compute_slot_mapping([_sv("a", "uint256")])
    assert list(m.keys()) == [0]
    assert m[0].name == "a"
    assert m[0].size == 32 and m[0].offset == 0


def test_three_uint256_each_own_slot():
    m = compute_slot_mapping([_sv("a", "uint256"), _sv("b", "uint256"), _sv("c", "uint256")])
    assert list(m.keys()) == [0, 1, 2]


def test_address_then_bool_pack_into_slot_0():
    m = compute_slot_mapping([_sv("o", "address"), _sv("f", "bool")])
    assert list(m.keys()) == [0]
    assert m[0].name == "o"   # only first var per slot tracked (MVP limitation)


def test_address_then_uint256_uses_two_slots():
    m = compute_slot_mapping([_sv("o", "address"), _sv("v", "uint256")])
    assert list(m.keys()) == [0, 1]
    assert m[1].name == "v"


def test_mapping_takes_full_slot():
    m = compute_slot_mapping([_sv("balances", "mapping(address => uint256)", dynamic=True)])
    assert list(m.keys()) == [0]
    assert m[0].name == "balances"


def test_uint128_then_uint128_packs():
    m = compute_slot_mapping([_sv("a", "uint128"), _sv("b", "uint128")])
    assert list(m.keys()) == [0]


def test_bool_then_uint256_starts_new_slot():
    m = compute_slot_mapping([_sv("f", "bool"), _sv("v", "uint256")])
    assert list(m.keys()) == [0, 1]
    assert m[1].name == "v"


def test_storage_gap_uses_50_slots():
    # Foundry contracts use uint256[50] __gap
    m = compute_slot_mapping([_sv("__gap", "uint256[50]")])
    # MVP simplification — gap is a static array of 50 uint256, treated as single
    # entry of size 32*50 starting at slot 0. Slot index advances by 50.
    # See size_of for the rule.
    assert 0 in m
    # Next slot would be 50 if we were to add another var (verified indirectly below)
    m2 = compute_slot_mapping([_sv("__gap", "uint256[50]"), _sv("next", "uint256")])
    assert 50 in m2


def test_size_of_known_elementary():
    assert size_of("uint256") == 32
    assert size_of("address") == 20
    assert size_of("bool") == 1
    assert size_of("uint128") == 16
    assert size_of("bytes32") == 32


# ---------------------------------------------------------------------------
# Tests for diff_slot_maps + classify_severity (Task 18)
# ---------------------------------------------------------------------------
from eadf.module2_ast_diff.slot_mapper import diff_slot_maps  # noqa: E402


def _sv_d(name, t):
    return StateVar(name=name, type=t, is_dynamic=False, visibility="public")


def test_no_collision_when_layouts_match():
    m1 = compute_slot_mapping([_sv_d("v", "uint256")])
    m2 = compute_slot_mapping([_sv_d("v", "uint256")])
    diff = diff_slot_maps(m1, m2)
    assert diff.collisions == []


def test_critical_collision_when_owner_overwritten():
    m1 = compute_slot_mapping([_sv_d("owner", "address")])
    m2 = compute_slot_mapping([_sv_d("attacker", "address")])
    diff = diff_slot_maps(m1, m2)
    assert len(diff.collisions) == 1
    assert diff.collisions[0].severity == "Critical"
    assert diff.collisions[0].slot == 0


def test_high_collision_when_balance_overwritten_not_at_slot_0():
    # balance at slot 1 (after a uint256 at slot 0) — High via name rule, not slot rule
    m1 = compute_slot_mapping([_sv_d("x", "uint256"), _sv_d("balances", "mapping(address => uint256)")])
    m2 = compute_slot_mapping([_sv_d("x", "uint256"), _sv_d("config", "mapping(address => uint256)")])
    diff = diff_slot_maps(m1, m2)
    coll = next(c for c in diff.collisions if c.slot == 1)
    assert coll.severity == "High"


def test_slot_0_uint256_collision_is_critical():
    # Patched §9.2: slot 0 + value-shaped type (uint256/address/bytes32) → Critical
    # This is the local Scenario 1 fixture's exact shape: value:uint256 → collisionVar:uint256
    m1 = compute_slot_mapping([_sv_d("value", "uint256")])
    m2 = compute_slot_mapping([_sv_d("collisionVar", "uint256")])
    diff = diff_slot_maps(m1, m2)
    assert diff.collisions[0].severity == "Critical"
    assert diff.collisions[0].slot == 0


def test_slot_0_bool_collision_is_high():
    # Slot 0, but bool isn't in the privileged-shape set {address, uint256, bytes32}
    # → falls to the High rule (slot == 0 OR mapping/balance/allow names).
    m1 = compute_slot_mapping([_sv_d("ready", "bool")])
    m2 = compute_slot_mapping([_sv_d("flag", "bool")])
    diff = diff_slot_maps(m1, m2)
    assert diff.collisions[0].severity == "High"


def test_medium_collision_for_generic_value_at_non_zero_slot():
    # uint256 at slot 1 (after uint256 at slot 0), renamed → Medium (no name/type/slot trigger)
    m1 = compute_slot_mapping([_sv_d("a", "uint256"), _sv_d("counter", "uint256")])
    m2 = compute_slot_mapping([_sv_d("a", "uint256"), _sv_d("renamedCounter", "uint256")])
    diff = diff_slot_maps(m1, m2)
    coll = next(c for c in diff.collisions if c.slot == 1)
    assert coll.severity == "Medium"
