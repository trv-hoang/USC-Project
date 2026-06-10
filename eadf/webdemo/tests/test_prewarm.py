import prewarm


def test_prewarm_exposes_main_and_cache_dir():
    assert callable(prewarm.main)
    assert prewarm.CACHE_DIR.name == "cache"
