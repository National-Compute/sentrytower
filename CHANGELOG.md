# Changelog

All notable changes of SentryTower are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before
1.0, a minor version can change the command line, the settings and the
output formats. A change of the model requests (prompts, request policies,
engine parameters) is always a notable change.

## [Unreleased]

## [0.2.0] - 2026-11-14

`findings.json` is schema version 2.0.0, a breaking change of the output
format (see Changed), and the agent engine runs Pi 1.5.0. A tool that reads
`findings.json` 1.0.0 needs the migration below; `sentrytower last` and the
GitHub Action read both versions.

### Added

- `src/sentrytower/contracts/`: the National Compute data contracts 2.0.0,
  vendored unchanged from the release `contracts-2.0.0.tar.gz` (SHA-256
  `1f487323047e627d0d3ed83d8036ab104657a9b370103a325c57c5ac843b1c51`): the
  JSON Schemas of the shared entities and `nc_contracts`, their mappings
  in Python (standard library only, so no new runtime dependency). They
  are licensed Apache-2.0 OR MIT; the OSV schema v1.9.2 in them is
  Apache-2.0 (see NOTICE). The test suite checks each vendored file
  against `SHA256SUMS`. `make vendor-contracts BUNDLE=path/to/contracts-<version>.tar.gz`
  (`scripts/vendor_contracts.py`) vendors a release after it checks the
  tarball against the `SHA256SUMS` of the release and each file against
  the `SHA256SUMS` in the tarball.

### Changed

- **Breaking: `findings.json` is schema version 2.0.0.** Each finding is a
  `Finding` of the data contracts, version 1, the finding format of the
  hosted product, so the CLI and the hosted product share one finding
  format, one severity scale, one evidence ladder and one SARIF mapping.
  `src/sentrytower/schemas/findings-v2.schema.json` replaces
  `findings-v1.schema.json` and refers to the contract schema
  `https://nationalcompute.io/schemas/finding/1.json`. The document keeps
  `tool`, `run` and `summary`. Migration of a finding (version 1 → version 2):
  - `id`, `title`, `severity`, `cwe` → the same;
  - `rank`, `route`, `tier` → `properties.rank`, `properties.route`,
    `properties.tier`;
  - `location` (`path`, `start_line`, `end_line`, `note`; null without a
    location) → `location` (`path`, `startLine`, `endLine`, `note`; left
    out without a location);
  - `related_locations` → `relatedLocations` (left out when empty);
  - `explanation` → `description`;
  - `evidence` and `exploit_conditions` (text) → `description`, which
    holds the evidence, then `Attack conditions, as the model states them:` and the conditions;
  - `engine` (`free-roaming`, `deep-check`, `single-agent`) →
    `engine.mode`, with `engine.name` `SentryTower` and `engine.version`;
  - `confidence` and `verification.keep_score` → `evidence.verification.score`;
  - `verification.verdict` (`exploitable`, `safe`, `unclear`) →
    `evidence.verification.outcome` (`supports`, `refutes`, `inconclusive`);
  - `verification.status`, `verification.reason` →
    `evidence.verification.status`, `evidence.verification.reason`;
  - `verification.votes` → `properties.votes`;
  - `fingerprint` (`sha256:<32 hex digits>`) → `fingerprint.value` (the
    same 32 hex digits) with `fingerprint.scheme` `sentrytowerFindingHash/v1`,
    so a history of fingerprints across runs carries over;
  - new: `kind` (`code`), `evidence.class` (`defective` when a verified
    majority of the blind model verification judged the finding
    exploitable, else `suspected`), `ruleId` (the first CWE), `target` (the audited
    folder).

  `sentrytower last` and the GitHub Action read both versions; the Action
  runs the image of its own release unless the input `image` names
  another. `sentrytower version` names findings schema 2.0.0.
- `findings.sarif`: each result is the SARIF mapping of the data contracts
  applied to the finding of `findings.json`. The flat properties stay; the
  property `nationalcompute/finding` adds the fields of the finding that
  SARIF has no place for (kind, title, engine, rule, evidence, target), so
  a reader of the contracts gets the finding back from the result. The
  primary location carries its note as its message, and a verified slice
  finding has the property `votes`.
- The agent engine runs the Pi coding agent 1.5.0 (was 0.84.1): the
  container image, `docker/pi/package-lock.json`, the version that
  `sentrytower doctor` and `install.sh` check, and the install commands of
  the documentation. The command, the agent configuration files and the
  prompts stay the same. Pi 1.5.0 changes the agent requests: it writes
  another system prompt and leaves `"strict": false` out of each tool
  definition. The task prompt, the tool descriptions and parameters, the
  tool results and the requests of the funnel's direct calls are the same.
  The image runs the `bin` of the Pi package, `dist/bundle/cli.js`.
- The check of the release against the benchmarked behaviour is now a
  behavioral parity check with 0.1.1. The byte-for-byte parity tests against
  the benchmarked harness ran with Pi 0.84.1 and cannot run again: the
  harness is in no repository, and Pi 1.5.0 changes the agent requests by
  design. On 2026-11-13, the 0.1.1 image and an image of the main branch
  (`bb23f8a`, Pi 1.5.0) each ran once on 50 synthetic issues with planted
  flaws (a vulnerable and a fixed snapshot each), with the default model and
  a $0.50 cap. Both detected 50 of 50; on the fixed snapshots, 0.1.1 raised
  20 false alarms and main 22, within the variation of one run. This shows
  parity on planted flaws, not a detection rate on real code
  ([benchmarks](docs/benchmarks.md#how-the-release-relates-to-the-benchmarked-harness)).
- The outputs label the exploit conditions of a finding "Attack conditions,
  as the model states them" (was "Exploit conditions"): in the
  `description` of `findings.json` and the SARIF message, `report.md` and
  `report.html`. The footers of the reports say that the verification of a
  finding is the judgment of a second model call, by default to the same
  model, which never runs the code. The field names and the verdict values
  (`exploitable`, `safe`, `unclear`) stay.
- The guided setup gives the cost of the default model as an estimate from
  its prices, as for every other model (was "95 in 100 audits cost less
  than $1.75 with this model (measured)", a figure without a published
  record). The help of `--depth` and `--max-cost-usd` and the setup call
  the standard depth the 20M-token plan of the benchmarked build (was "the
  measured run"): the detection of the default model is not measured.
- The documentation states the benchmark with its limits: an earlier
  internal build with GLM 5.3 Flash, over the 117 advisories with answer
  keys, a lead not separated from Clearwing or Visa VVAH, and no
  measurement of a release or its default model. Codex Security and
  Clearwing ran in other sandboxes than the other harnesses; the
  sensitivity views of every rival have `"holds": false`, which the
  documentation and `benchmarks/results.json` now explain; and the
  aggregates show that the benchmarked build missed about 7 in 10 of the
  vulnerabilities, not what any harness found.
- `install.sh` prints the install command of the pinned Pi when another
  version is installed. It does not replace that version.

### Fixed

- The settings folder of a given environment that sets neither
  `XDG_CONFIG_HOME` nor `HOME` is the settings folder of the process, so
  its `XDG_CONFIG_HOME` comes before its home folder. The test suite runs
  with a temporary home folder and without the `SENTRYTOWER_*` variables
  of the shell, so the settings of the person who runs it cannot change a
  result.

## [0.1.1] - 2026-11-09

### Added

- `install.sh`: installs the `sentrytower` command from a clone on macOS
  and Linux with uv, gets the tools of the agent where it can without
  administrator rights, then starts the guided setup.

### Changed

- The release attests the build provenance of the files and the image only
  when the repository is public. GitHub keeps the attestations of a private
  repository only on an Enterprise plan. The attestation of the image is
  kept in the attestation store of GitHub (`gh attestation verify` reads it
  there), not in the registry. The image keeps its BuildKit provenance and
  SBOM.

## [0.1.0] - 2026-11-01

The first public release, a beta.

### Added

- `sentrytower audit`: a security audit of a repository by a swarm of AI
  agents. Up to 1,000 files go to the funnel engine: an inventory of the
  code units and their security signals, a check of each unit in the order
  of its signals, a blind triage of each lead, deep-check agent sessions, a
  free-roaming session, a blind verification of each finding and a ranked
  list. Larger repositories go to one deep agent. The file count leaves out
  version control, installed dependencies, build output and virtual
  environments.
- A budget in dollars. Each audit has a cost cap of $2 by default, the
  measured standard run, and the model gateway stops new calls at the cap.
  A larger cap buys a deeper audit, with the preview label; `--depth` gives
  presets.
- Results that say what happened. Each report gives the status, why the run
  stopped, the spend and how much of the code it checked. A refused key, an
  account without credit, failed calls or a crash end the run with exit
  code 4, never with an empty result and exit code 0.
- Five outputs: `findings.json`, SARIF 2.1.0 for GitHub code scanning,
  `report.md`, `report.html` and `run.json`. Exit codes for release gates
  (`--fail-on`).
- Any OpenAI-compatible model: OpenRouter, another endpoint, or a model
  server on the same computer (Ollama, LM Studio, vLLM or llama.cpp). One
  model for every role, or a fast and a strong model.
- `sentrytower setup`, `sentrytower doctor` and `sentrytower last`.
- A GitHub Action that runs the published image. It uploads SARIF only for
  a complete run, and on a public repository it shows counts only.
- A container image for linux/amd64 and linux/arm64, with Pi, ripgrep and
  fd at pinned versions and with provenance attestations.

### Security

- The agents get four read-only tools that cannot leave the repository,
  and no program from the repository runs. The provider key stays in the
  parent process. The engines get an environment without the key and
  without repository paths in `PATH` or in the loader variables.
- The built-in OpenRouter routes set `data_collection: "deny"`.
- The outputs are written without following symbolic links, and the
  terminal output and `report.md` carry no control characters from the
  repository or the model.
