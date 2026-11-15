import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def _fresh_run_caches():
    """Per-run caches in script.py must not leak between tests."""
    import script
    cache = getattr(script, "_veracode_teams_cache", None)
    if cache is not None:
        cache.clear()
    yield
