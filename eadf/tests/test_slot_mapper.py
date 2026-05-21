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
