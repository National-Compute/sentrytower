# Contributing to SentryTower

Thank you for your help. This document explains how to set up the project,
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
   message or an agent command determine what the model sees. The golden
   fixtures in `tests/golden` hold the model requests of four synthetic
   scenarios, byte for byte, and `tests/test_golden.py` fails when one
   changes. Do not change a request by accident. When you change one on
   purpose:
   - say so in the pull request;
   - regenerate the fixtures (`make golden`) and commit them;
   - add an entry to `CHANGELOG.md`.

   After such a change, the configuration is no longer the measured one. It can be an option,
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
6. **The data contracts are vendored.** `src/sentrytower/contracts/` holds
   a release of the National Compute data contracts: the JSON Schemas of
   the Finding and the other entities, and `nc_contracts`, their mappings
   in Python (standard library only). Do not edit these files; the tests
   check each one against `SHA256SUMS`. A change of the contracts is a new
   release of them: vendor it with
   `make vendor-contracts BUNDLE=path/to/contracts-<version>.tar.gz`, which
   checks the tarball against the `SHA256SUMS` of the release and each file
   against the `SHA256SUMS` in the tarball, and name the version and the
   digest of the tarball (`BUNDLE.sha256`) in the pull request.

## Send a change

1. Open an issue first for a large change.
2. Make a branch, make the change with its tests and documentation, and run
   `make lint test`.
3. Open a pull request and fill in its checklist.

The CI runs the lint, the tests on Python 3.11 to 3.14 on Linux and macOS,
the container build, a smoke test of the image and of the GitHub Action
with a fake model endpoint, and a secret scan (Gitleaks) of the tree and
of the history: a pull request's own commits, and the full history of each
push.

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
4. Before 1.0 the GitHub Action has no major tag: the documentation pins
   the release tag (`@vX.Y.Z`). `tests/test_release.py` accepts a major tag
   only when it names the major version of the package.
5. A release is complete only when it has all three of these:
   1. the tag `vX.Y.Z`;
   2. the container image `ghcr.io/national-compute/sentrytower:X.Y.Z`,
      which the release workflow publishes from the tag;
   3. sentrytower.com showing and linking the new version. The maintainers
      update it in the website's source after the image is published.

### Real-model smoke

The test suite and the CI use fake models only. Before a release tag, the
maintainer starts a short smoke test with real models and a real key. By
default it runs five short runs: a standard run on both routes (the funnel
and the agent route), a key without credit, an invalid key and a more
expensive model. `--deep` adds a deep run on each route. The smoke passes
when no run is falsely clean (a refused key or a failed run never ends with
exit code 0 and an empty result), every run stays within its cost cap, the
$2 cap gives depth factor 1 and, with `--deep`, the $10 cap gives a depth
above 1 with the preview label.

Run it from a checkout of the release commit, with Docker:

```sh
python3 scripts/release/smoke.py --build --image sentrytower:smoke --yes
```

It reads two keys from the environment: `SENTRYTOWER_API_KEY` (a key with
credit) and `SMOKE_NOCREDIT_KEY` (a second key with a credit limit of
$0.01). By default it spends at most $5. It writes `smoke-report.md` to the
folder of the runs (default `~/sentrytower-smoke`). Each run has a
wall-clock time limit: one hour for the $2 and $1 runs, two hours for the
$10 runs. The five short runs go one after the other (up to about three and
a half hours); `--lanes all` starts them at the same time (up to about one
hour).

Add `--deep` only when the release changes the depth, the pacing or the
deep agent route: `src/sentrytower/budget.py` (the depth factor, the token
plan and the limits that grow with the depth), `src/sentrytower/funnel/pacing.py`
(the pools and the clock of the funnel) or `src/sentrytower/agent/deep.py`
(the slice sessions of the agent route). The two deep runs cost $10 each, so
the smoke then spends at most $25. They go one after the other, in parallel
with the short runs (up to about four hours). `--lanes all` starts every
run at the same time (up to about two hours), and `--lanes 1` runs one
audit at a time (up to about seven and a half hours). The deep runs start
up to one agent session for each CPU: with more than one lane, give Docker
16 GB of memory.

`--fake` runs the same plan against local fake endpoints, with no key and
no cost.
