from eadf.module4_matcher.pattern_scorer import calc_pattern_score

def test_no_keywords_for_unknown_detector():
    assert calc_pattern_score(["foo bar"], "unknown") == 0.0

def test_match_increases_score():
    score = calc_pattern_score(["function initialize() public {"], "uninitialized-state")
    assert score >= 0.1

def test_max_score_caps_at_one():
    score = calc_pattern_score(["selfdestruct selfdestruct selfdestruct"] * 100, "suicidal")
    assert score <= 1.0
