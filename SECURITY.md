# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | Yes |

A fix goes into a new patch release of the supported version. The fix
covers the command line, the GitHub Action and the container image of that
release.

## Report a vulnerability

Do not report a vulnerability of SentryTower in a public issue.

Use the private vulnerability reporting of GitHub for this repository: the
**Report a vulnerability** button on the Security tab, or the form at
[github.com/National-Compute/sentrytower/security/advisories/new](https://github.com/National-Compute/sentrytower/security/advisories/new).
Only the maintainers can read the report.

Give the version (`sentrytower version`), how you run SentryTower (the
command line, the container image or the GitHub Action), the steps to
reproduce and the effect. Do not send a key, private source code or the
content of an agent session.

The maintainers confirm the report within 5 working days, and they keep you
informed until a fix is available. They publish a security advisory with
the fix, and they credit you when you agree.

## Scope

These parts of this repository are in scope:

- the command line `sentrytower` (the Python package in `src/`);
- the GitHub Action (`action.yml` and its helper `scripts/github_action.py`);
- the container image `ghcr.io/national-compute/sentrytower` of
  `docker/Dockerfile`, with the pinned components as the image uses them.

A vulnerability of SentryTower is, for example:

- a way for the audited repository to make SentryTower read or send data
  outside the repository, run a command, or change a file;
- a leak of the provider key into a log, an output file, an error message or
  the environment of an engine process;
- a way for another local process to use the model gateway of a run;
- a SARIF or report output that executes content in a viewer;
- a way for the GitHub Action to show the findings of a public repository
  (titles, files, lines or evidence) to its readers without the input
  `public-findings`.

These are not vulnerabilities of SentryTower:

- A finding that SentryTower misses or reports wrongly. Report it as a
  normal issue, with a public example.
- A vulnerability of a component (the Pi CLI, Node.js, Python, ripgrep, fd
  or a base image) that SentryTower does not make worse. Report it to that
  project. Tell us when the image holds a version with a known
  vulnerability.
- What the model provider does with the requests. Its data policy applies.
  The built-in routes ask OpenRouter for the endpoints of an allowlist that
  do not store or train on the data (`data_collection: "deny"`).

## Threat model

SentryTower reads code that it does not trust and sends it to a model
endpoint that you choose. It protects your key, your computer and your
other data from the audited code.

- **The audited repository is untrusted.** Its code and its text can try to
  instruct the model (prompt injection). The agents have four read-only
  tools: `read`, `grep`, `find` and `ls`. They have no shell, no write tool,
  no web tool and no other extension. The gateway removes each server-side
  tool (for example web search) from each request. A repository guard
  refuses each tool path outside the repository after symbolic links, for
  example `/proc/1/environ`, a home folder, or a link in the repository that
  points out of it. The tools also reach the documentation of the Pi
  package. One write can happen at the start of an agent session: Pi
  1.5.0 renames a folder `.pi/commands` of the repository to `.pi/prompts`
  when no `.pi/prompts` exists (a migration of Pi). The migration runs at
  the start of Pi, before Pi reads any settings, so `--no-approve` does not
  stop it. It stays in the repository's own `.pi` folder, and the
  read-only mount of the container image and the GitHub Action prevents
  it; to keep a working copy unchanged, audit a copy or use the image.
- **No program of the repository runs.** SentryTower never runs a program
  of the audited repository and never reads a configuration file from it.
  A tool path (`[tools]`, `SENTRYTOWER_RG` and similar) in the repository is
  a usage error. The Python processes of the engines run in the repository
  folder without it on the module path (`-P`, `PYTHONSAFEPATH`), so a module
  of the repository is never imported. Give the configuration with
  `--config` or `SENTRYTOWER_CONFIG`.
- **The key stays in the parent process.** The key comes from the
  environment (`SENTRYTOWER_API_KEY` or `OPENROUTER_API_KEY`) or from the
  keychain of your user, never from a file. The engines get the URL of a
  loopback gateway and a random credential of the run, never the key. The
  environment of each engine process holds no variable whose name looks
  like a secret, no key variable of the configuration, no value that holds
  the key, no URL with a password, and no proxy setting. On Linux the
  parent process is not dumpable, so another process of the same user
  cannot read its memory or its environment.
- **The gateway listens on the loopback address only.** It serves model
  calls only as `POST /chat/completions` with the credential of the run,
  and only for the models of the run. Besides, it answers `GET /budget`
  with the credential (the money of the run, numbers only) and
  `GET /healthz` (a status). It enforces the token ceiling and the cost
  cap of the run on the usage that the provider reports. After the
  provider refuses the key, the account or the route (HTTP 401, 402, 403
  or 404), it sends no more upstream calls in that run.
- **No program of the repository runs through PATH.** The engines, the
  agent sessions, Pi and its tools get only the absolute PATH entries
  outside the audited repository (an empty entry, `.` or
  `node_modules/.bin` would name a folder of the repository). The program
  lookups of the parent read only the absolute entries and run each
  program by its absolute path. The search paths of code (PYTHONPATH,
  NODE_PATH, LD_LIBRARY_PATH and the DYLD search paths) keep the same
  entries, and NODE_OPTIONS, RIPGREP_CONFIG_PATH, LD_PRELOAD, LD_AUDIT and
  DYLD_INSERT_LIBRARIES do not reach the engines.
- **No write goes through a link.** The output folder must not be a
  symbolic link, no folder on its path inside the audited repository may
  be a link, and it must belong to the user of the run; a link or another
  file that is not a regular file at the name of an output file is
  refused. Each refusal is exit code 2, before any model call. Each file is
  written to a new private staging file and renamed in one step, so a link
  at a final name is replaced, never followed. The same link rule applies
  to the state folder (`--state-dir`, `SENTRYTOWER_STATE_DIR`), and
  `sentrytower last` opens only regular files of a folder with no link on
  its path.
- **No control character reaches the terminal.** Each control character
  (C0, DEL, C1, and the bidirectional embeddings, overrides and isolates)
  of model text, of file names of the repository and of error messages is
  written as `?`, so a finding or a file name cannot move the cursor, set
  the window title or write the clipboard. `report.md` keeps only its line
  feeds and tabs, so `cat report.md` is safe too.
- **The outputs hold no key and no prompt.** `run.json` holds numbers,
  codes, model IDs and paths, and after a provider refusal the cleaned
  error message of the provider (at most 200 characters, never with
  request text). The findings files hold the findings: each is a claim of
  a language model about the audited code. The run state (`--keep-state`)
  holds the agent sessions, which hold code: treat it as source code.
- **The code goes to the configured endpoint only.** SentryTower sends no
  telemetry and makes no update check, and each agent session runs Pi with
  `PI_OFFLINE=1`. The built-in OpenRouter routes set
  `data_collection: "deny"`
  ([where your code goes](README.md#where-your-code-goes)).

The container image adds these layers, and the GitHub Action and
`docker-compose.yml` use them:

- the repository mounted read only (`/workspace/repo:ro`);
- a read-only root file system, with a `tmpfs` for `/home/dev` (the run
  state) and `/tmp`;
- no capabilities (`--cap-drop ALL`) and `no-new-privileges`;
- a non-root user.

Also limit the network access of the container to the model endpoint:
`docker-compose.yml` uses an egress proxy with an allowlist, and Kubernetes
can use a NetworkPolicy ([docs/deployment.md](docs/deployment.md#hardening)).
A GitHub-hosted runner has no egress restriction.

In the container, the key is in the environment of the container, as for
each secret that a container gets. The repository guard keeps it out of
reach of the agent tools.

The GitHub Action adds these rules:

- The key goes from the input `api-key` into the environment of the
  container only, never onto a command line.
- On `pull_request_target`, the Action refuses the input `config`, because
  the file would come from the checked-out code of the pull request.
- The inputs `path` and `config` must be in the workspace.
- On a public repository, every reader can see the job summary, the
  annotations and the log, and can download the workflow artifacts. So the
  Action shows counts only there, puts only `run.json` into the artifact,
  and uploads the SARIF file only for a run of the default branch (GitHub
  shows the alert list of a repository to people with write access only,
  but the alerts of a pull request to every reader). The input
  `public-findings` turns the details on.

Each finding is a claim of a language model. Confirm it in the code before
you act on it. An empty result is not a proof that the code is safe.
