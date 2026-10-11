# Releasing

Pushing a `v*` tag on `main` runs [the release workflow](.github/workflows/release.yml). It checks the tag, runs the tests, builds the package, and after approval publishes it to PyPI. It then creates the GitHub release from the changelog and deploys the docs.

## Release a version

1. On a branch, prepare the release:

   ```bash
   invoke release 0.5.0
   ```

   This sets `__version__`, turns `[Unreleased]` in `CHANGELOG.md` into a dated `[0.5.0]` section with its comparison link, and runs flake8, mypy and the tests. Review the changelog, then open a PR titled "Bump version to 0.5.0".

2. Before merging, run the hardware tests on a 3.x and a 4.x card, since CI has no card:

   ```bash
   KEYCARD_READER=0 KEYCARD_DESTRUCTIVE=1 pytest tests/hardware
   ```

3. After the PR is merged, tag the merge on `main`:

   ```bash
   git switch main
   git pull
   git tag v0.5.0
   git push origin v0.5.0
   ```

4. Approve the `pypi` deployment on the workflow run in GitHub Actions.

The workflow stops before publishing if the tag is not on `main`, the tag does not match `__version__`, `CHANGELOG.md` has no section for the version, or a test fails. PyPI never accepts the same version twice, so a failed upload after that point needs a new version.

## Release candidates

A tag such as `v0.5.0rc1`, with `__version__ = "0.5.0rc1"`, publishes to TestPyPI only. It skips the changelog check, the GitHub release and the docs.

## One-time setup

- **PyPI**: on the `keycard` project, under Publishing, add a trusted publisher: owner `mmlado`, repository `keycard-py`, workflow `release.yml`, environment `pypi`. After the first release published this way, delete the `PYPI_API_TOKEN` repository secret.
- **TestPyPI**: add the same trusted publisher on test.pypi.org with environment `testpypi`.
- **GitHub**: under Settings, Environments, create `pypi` (and `testpypi`) with yourself as a required reviewer and a deployment rule allowing tags matching `v*`.
