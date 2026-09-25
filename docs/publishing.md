# Publishing llm-sentinel

Releases are cut from the `develop` branch via GitHub Releases. Publishing
to PyPI uses [trusted publishing](https://docs.pypi.org/trusted-publishers/),
so no API token is stored anywhere.

## One-time setup

Before the first release, register this repo as a trusted publisher for the
`llm-sentinel` project on PyPI (about two minutes, in the browser):

1. Log in to PyPI and open **Your publishing** under account settings.
2. Add a pending publisher:
   - PyPI project name: `llm-sentinel`
   - Owner: `anushamukka9`
   - Repository name: `llm-sentinel`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. That is it. The first publish from a GitHub Release claims the project
   name automatically.

For dry runs, do the same on TestPyPI with environment name `testpypi`.

## Cutting a release

1. Bump the version in **both** places (a test enforces they match):
   - `pyproject.toml` (`version = "..."`)
   - `src/llm_sentinel/__init__.py` (`__version__ = "..."`)
2. Push to `develop`, open a PR to `main` if one is due, merge on green CI.
3. On GitHub, draft a new Release from the `main` branch (or `develop` for
   pre-releases) and publish it. The `publish.yml` workflow builds the sdist
   and wheel, runs `twine check`, and uploads to PyPI.

## Dry run

Run the workflow manually from the Actions tab. Manual runs always publish
to TestPyPI, never to real PyPI, so the pipeline can be exercised safely.
