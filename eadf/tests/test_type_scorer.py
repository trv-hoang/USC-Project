from eadf.module4_matcher.type_scorer import calc_type_score

def test_insert_state_var_vs_collision_high():
    assert calc_type_score("INSERT", "StateVariable", "storage-collision-cross-version") == 1.0

def test_irrelevant_pair_zero():
    assert calc_type_score("UPDATE", "Function", "storage-collision-cross-version") == 0.0
