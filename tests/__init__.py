# Marks `tests` as a package so `from tests.conftest import ...` resolves
# consistently under a bare `pytest` invocation (as CI runs it), not only under
# `python -m pytest` which implicitly adds the repo root to sys.path.
