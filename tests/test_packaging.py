"""Packaging sanity checks: the version recorded in the code must match
the version declared in pyproject.toml, so a release never ships with
two different versions."""

from pathlib import Path

import llm_sentinel


def _pyproject_version() -> str:
    # Plain line scan on purpose: keeps the test stdlib-only on every
    # supported Python (tomllib is 3.11+; the package supports 3.10+).
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    for line in pyproject.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith('version = "') and stripped.endswith('"'):
            return stripped[len('version = "') : -1]
    raise AssertionError("version not found in pyproject.toml")


def test_version_matches_pyproject():
    assert llm_sentinel.__version__ == _pyproject_version(), (
        "bump the version in both pyproject.toml and "
        "src/llm_sentinel/__init__.py before cutting a release"
    )
