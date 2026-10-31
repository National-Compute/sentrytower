# Contributing to SentryTower

Thank you for your help. This document tells you how to set up the project,
which rules apply to a change, and how to send it.

By taking part, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Report a security problem privately (see [SECURITY.md](SECURITY.md)).

## Set up

You need Python 3.11 or later. For a whole local audit you also need
Node.js 22.19 or later, the Pi CLI, ripgrep and fd (`sentrytower doctor`
tells you what is missing). The tests need none of them.

```sh
git clone https://github.com/National-Compute/sentrytower.git
cd sentrytower
make install        # .venv with the package and the development tools
make test           # the whole suite; fake models only, no key
make lint           # ruff and mypy
```

`make test-fast` leaves out the tests that run whole audits.

## Rules for a change

1. **The model requests are pinned.** The prompt files, the
   request policies, the engine parameters and the code that builds a
   message or an agent command decide what the model sees. The golden
   fixtures in `tests/golden` hold the model requests of four synthetic
   scenarios, byte for byte, and `tests/test_golden.py` fails when one
   changes. Do not change a request by accident. When you change one on
   purpose:
   - say so in the pull request;
   - regenerate the fixtures (`make golden`) and commit them;
   - add an entry to `CHANGELOG.md`.

   Such a change leaves the measured configuration. It can be an option,
   but it can become the default only after a new measurement.
2. **No secrets and no private code.** Do not put a key, customer code or
   the content of an agent session in a change, a test fixture or a log.
   The tests use synthetic repositories (`tests/synthetic.py`) and fake
   models (`tests/fakes.py`).
3. **The standard library only.** The package has no runtime dependency.
   The engines run as child processes that import only the standard
   library. Discuss a new dependency in an issue first.
4. **Tests for each change.** A fix comes with a test that fails without
   it.
5. **Types and style.** `ruff` formats and lints the code; `mypy` checks
   the types. Write docstrings and documentation in short, clear sentences.

## Send a change

1. Open an issue first for a large change.
2. Make a branch, make the change with its tests and documentation, and run
   `make lint test`.
3. Open a pull request and fill in its checklist.

The CI runs the lint, the tests on Python 3.11 to 3.14 on Linux and macOS,
the container build, and a smoke test of the image and of the GitHub Action
with a fake model endpoint.

## License of a contribution

SentryTower is licensed under the Apache License 2.0 or the MIT License, at
your option. Unless you state otherwise, each contribution that you submit
for inclusion in SentryTower is licensed under both, as defined in the Apache
License 2.0, without additional terms or conditions.

## Release

1. Update the version in `pyproject.toml` and `src/sentrytower/__init__.py`,
   and each pin of the version (the README, `docs/`, `examples/`,
   `action.yml`, the `Makefile`, `docker-compose.yml`, the Dockerfile,
   `CITATION.cff` and `SECURITY.md`). `tests/test_release.py` fails on a
   pin that you missed. Add the section `## [X.Y.Z]` of the version to
   `CHANGELOG.md`: the release workflow refuses a tag without it, and the
   section becomes the release notes.
2. Run the real-model smoke (below), and tag the commit only when it
   passes.
3. Tag the commit (`vX.Y.Z`) and push the tag. The release workflow
   (`.github/workflows/release.yml`) checks the tag and runs the tests,
   pushes the image for linux/amd64 and linux/arm64 to
   `ghcr.io/national-compute/sentrytower`, and attaches the wheel and the
   source distribution to the GitHub release, each with a build provenance
   attestation.
4. Move the major tag (`v1`) of the GitHub Action to the new release.

### Real-model smoke

The test suite and the CI use fake models only. Before a release tag, the
maintainer starts a short smoke test with real models and a real key. It
covers a standard run and a deep run on both routes (the funnel and the
agent route), a key without credit, an invalid key and a more expensive
model. It passes when no run is falsely clean (a refused key or a failed
run never ends with exit code 0 and an empty result), every run stays
within its cost cap, and the $2 cap gives depth factor 1.

Run it from a checkout of the release commit, with Docker:

```sh
python3 scripts/release/smoke.py --build --image sentrytower:smoke --yes
```

It reads two keys from the environment: `SENTRYTOWER_API_KEY` (a key with
credit) and `SMOKE_NOCREDIT_KEY` (a second key with a credit limit of
$0.01). It spends at most $25 and writes `smoke-report.md` to the folder
of the runs (default `~/sentrytower-smoke`). Each run has a wall clock: one
hour for the $2 and $1 runs, two hours for the $10 runs. By default the two
deep runs go one after the other, beside the other runs (up to about four
hours). `--lanes all` starts every run at the same time (up to about two
hours), and `--lanes 1` runs one audit at a time (up to about seven and a
half hours). The deep runs start up to one agent session for each CPU: with
more than one lane, give Docker 16 GB of memory. `--fake` runs the same
plan against local fake endpoints, with no key and no cost.
