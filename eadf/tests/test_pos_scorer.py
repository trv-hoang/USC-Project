from eadf.module4_matcher.pos_scorer import calc_pos_score

def test_distance_0_scores_1(): assert calc_pos_score(10, 10) == 1.0
def test_distance_2_scores_08(): assert calc_pos_score(10, 12) == 0.8
def test_distance_5_scores_05(): assert calc_pos_score(10, 15) == 0.5
def test_distance_10_scores_02(): assert calc_pos_score(10, 20) == 0.2
def test_distance_far_scores_01(): assert calc_pos_score(10, 100) == 0.1
