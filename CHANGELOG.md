# Changelog

All notable changes of SentryTower are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before
1.0, a minor version can change the command line, the settings and the
output formats. A change of the model requests (prompts, request policies,
engine parameters) is always a notable change.

## [Unreleased]

### Changed

- The agent engine runs the Pi coding agent 1.5.0 (was 0.84.1): the
  container image, `docker/pi/package-lock.json`, the version that
  `sentrytower doctor` and `install.sh` check, and the install commands of
  the documentation. The command, the agent configuration files and the
  prompts stay the same. Pi 1.5.0 changes the agent requests: it writes
  another system prompt and leaves `"strict": false` out of each tool
  definition. The task prompt, the tool descriptions and parameters, the
  tool results and the requests of the funnel's direct calls are the same.
  The image runs the `bin` of the Pi package, `dist/bundle/cli.js`.
- Before the next release, run the benchmark parity check again (the
  benchmark harness is private): its results were measured with Pi 0.84.1.
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
