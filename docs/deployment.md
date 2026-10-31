# Deployment

SentryTower runs in three ways: as a command line on your computer,
as a container image, and as a GitHub Action. The container image is the
recommended deployment: it has the pinned Pi CLI, ripgrep and fd, and it
shows the model the paths of the measured runs (`/workspace/repo` and
`/home/dev`).

| Way | Command | What it needs |
| --- | --- | --- |
| [Command line](#command-line) | `uv tool install git+https://github.com/National-Compute/sentrytower@v0.1.0` | Python 3.11 or later, uv, Node.js 22.19 or later, the Pi CLI 0.84.1, ripgrep and fd |
| [Container image](#container-image) | `docker run --rm ghcr.io/national-compute/sentrytower:0.1.0 --version` | Docker (or another OCI runtime) on Linux, macOS or Windows; linux/amd64 or linux/arm64 |
| [GitHub Action](#github-action) | `uses: National-Compute/sentrytower@v0.1.0` | A Linux runner with Docker and Python 3.9 or later (each GitHub-hosted Linux runner has both) |

Each way needs a key of the model provider in the environment
(`SENTRYTOWER_API_KEY` or `OPENROUTER_API_KEY`), except a model server on
your own machine. The same version runs the same audit in each way.

- [Command line](#command-line)
- [Container image](#container-image)
- [Docker Compose with an egress allowlist](#docker-compose)
- [GitHub Action](#github-action)
- [GitLab CI](#gitlab-ci)
- [Kubernetes Job](#kubernetes-job)
- [Hardening](#hardening)

## Command line

Requirements: Python 3.11 or later, [uv](https://docs.astral.sh/uv/)
(or pipx), Node.js 22.19 or later, the Pi CLI 0.84.1, ripgrep and fd.

```sh
uv tool install git+https://github.com/National-Compute/sentrytower@v0.1.0
# or: pipx install git+https://github.com/National-Compute/sentrytower@v0.1.0
npm install -g @earendil-works/pi-coding-agent@0.84.1
# ripgrep and fd: brew install ripgrep fd | apt install ripgrep fd-find | ...

sentrytower --version                          # sentrytower 0.1.0
export SENTRYTOWER_API_KEY=...                 # an OpenRouter key
sentrytower doctor                             # checks each requirement and sends one tiny request
sentrytower audit path/to/repo --out ~/sentrytower-results   # keep the outputs outside the repository
```

`sentrytower doctor --offline` checks the tools and the key without a
request. The GitHub release of each version also has the wheel, the source
distribution and `SHA256SUMS`; the wheel and the source distribution each
have a build provenance attestation
(`gh attestation verify sentrytower-0.1.0-py3-none-any.whl --repo National-Compute/sentrytower`).
`uv tool install ./sentrytower-0.1.0-py3-none-any.whl` installs the
downloaded wheel. From a clone of this repository: `uv tool install .` or
`pipx install .`. The package has no runtime dependency: it uses the Python
standard library only.

The image pins ripgrep 15.2.0 and fd 10.5.0, the versions of the measured
runs; `doctor` warns when other versions are installed. On a workstation
the model sees the real paths of the repository and of the run state, so
the requests differ from the requests of the measured runs in these
paths.

## Container image

The release workflow publishes the image for linux/amd64 and linux/arm64.
It needs no other tool: Python, Node.js, the Pi CLI, ripgrep and fd are in
the image.

```sh
docker run --rm ghcr.io/national-compute/sentrytower:0.1.0 --version

mkdir -p ~/sentrytower-results                 # outside the audited repository
docker run --rm \
  -e SENTRYTOWER_API_KEY --user "$(id -u):$(id -g)" \
  --read-only --tmpfs "/home/dev:size=4g,uid=$(id -u),gid=$(id -g)" --tmpfs /tmp:size=1g \
  --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD:/workspace/repo:ro" \
  -v ~/sentrytower-results:/workspace/out \
  ghcr.io/national-compute/sentrytower:0.1.0 audit /workspace/repo --out /workspace/out
```

Each published image has a signed build provenance attestation and an SBOM.
Check the provenance with the GitHub CLI, and pin the digest that it shows
when you want an image that cannot change:

```sh
gh attestation verify oci://ghcr.io/national-compute/sentrytower:0.1.0 --repo National-Compute/sentrytower
```

To build the image yourself, from a clone of this repository:

```sh
docker build -f docker/Dockerfile -t sentrytower:0.1.0 .
make docker-smoke      # the image against a fake model endpoint: no key, no model call
```

The image:

- is built in stages: Node.js 24.19.0, Pi 0.84.1 from `docker/pi/package-lock.json`
  (`npm ci`, integrity checked), ripgrep 15.2.0 and fd 10.5.0 from their
  release archives (SHA-256 of each archive and binary checked), and the
  SentryTower wheel on Python 3.12.15; each base image is pinned by digest;
- runs as the user `dev` (uid 1000), with `tini` as the init process;
- keeps the run state in `/home/dev` (`SENTRYTOWER_STATE_DIR`) and expects
  the repository at `/workspace/repo`: the layout of the measured runs;
- runs `sentrytower doctor --offline` as its default command and as its
  health check.

The output folder must belong to the user of the run: SentryTower refuses
a folder of another user with exit code 2, before any model call, and names
the `--user` option. The commands above run the container as your own user
(`--user`) with a `/home/dev` tmpfs of the same `uid` and `gid`; without
`--user`, the container runs as uid 1000. The output folder must also not
be a symbolic link ([the output folder](configuration.md#the-output-folder)).

## Docker Compose

[`docker-compose.yml`](../docker-compose.yml) runs the published image on an
internal network without a route to the internet. Its only way out is a
Squid egress proxy that allows TLS connections to `openrouter.ai` and
refuses everything else
([`docker/egress/squid.conf`](../docker/egress/squid.conf)). The gateway of
SentryTower sends its upstream requests through `HTTPS_PROXY`; the engines
reach only the loopback gateway.

```sh
export SENTRYTOWER_API_KEY=...
mkdir -p sentrytower-results
REPO=/path/to/repository HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm sentrytower
```

`HOST_UID` and `HOST_GID` run the container as your user, so that the
output folder belongs to the user of the run; without them it runs as the
user 1000 of the image, and a folder of another user is refused (exit code
2). `docker compose build` builds the image from `docker/Dockerfile`
instead of the published one.

For another endpoint, add its host to the `model_endpoint` list of
`squid.conf` and set `SENTRYTOWER_BASE_URL`.

## GitHub Action

The action at the root of this repository pulls the published image of its
version (`ghcr.io/national-compute/sentrytower:0.1.0` for `@v0.1.0`), runs
the audit with the repository mounted read only, writes a summary of the
run to the job summary, uploads `findings.sarif` to GitHub code scanning,
and uploads the outputs as a workflow artifact. It does not build an image.

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 270
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: National-Compute/sentrytower@v0.1.0
        with:
          api-key: ${{ secrets.OPENROUTER_API_KEY }}
          fail-on: high                 # optional
```

| Input | Default | Meaning |
| --- | --- | --- |
| `api-key` | (required) | The provider key, from a secret |
| `path` | `.` | The folder to audit, in the workspace |
| `model`, `base-url`, `config` | | As the options of `sentrytower audit`; `config` is a file of the checked-out code, and the action refuses it on `pull_request_target` |
| `max-cost-usd` | (empty) | The cost cap of the run in US dollars. Empty passes no value, and SentryTower applies its default of $2 when each model of the run has prices; `0` means no cap. A cap for a model without prices is a usage error (exit code 2) |
| `depth` | | `quick`, `standard`, `deep` or `max` (a cap of $0.50, $2, $10 or $50); above $2 the run is a preview: more checks; effect on findings not yet measured |
| `max-tokens`, `wall-clock` | | An upper limit of the tokens, and the wall clock of the run |
| `fail-on` | | Fail the step at this severity or a higher one |
| `upload-sarif` | `auto` | Upload to code scanning: `auto`, `true` or `false` (see below) |
| `sarif-category` | `sentrytower` | The code-scanning category (give each audit of one repository its own) |
| `upload-artifact` | `true` | Upload the outputs as an artifact (on a public repository: `run.json` only, unless `public-findings` is true) |
| `artifact-name` | `sentrytower-results` | The name of the artifact (each use of the action in one workflow run needs its own) |
| `public-findings` | `false` | On a public repository, also show the findings in the job summary and the artifact, and upload the SARIF file for pull requests |
| `image` | | Another image, for example a mirror or a digest pin (empty: the published image of the action version) |
| `docker-args` | | Extra arguments of `docker run` |

The outputs are `findings`, `sarif`, `report`, `report-html`, `count`,
`route`, `status` and `exit-code`. The job summary gives the status of the
run, the spend and the cap, why the run stopped, the units that it checked
and the findings by severity. Exit code 4 (a failed or incomplete run, for
example a key that the provider refuses) fails the step with an error
annotation that gives the stop and the failure of the run, whatever
`fail-on` says. A usage error (2) and an environment problem (3) also fail
it, and exit code 1 fails it when `fail-on` is set.

For a `path` other than `.`, the action puts the folder in front of each
SARIF path, because code scanning reads paths from the root of the
repository. The words of `docker-args` are split at spaces; quotes in it
are not supported. [`examples/github-workflow.yml`](../examples/github-workflow.yml)
is a complete workflow. A run of a pull request from a fork has no access to
the secret; run the audit on `pull_request_target` only when you understand
its risks, or on a schedule.

### Public repositories

Every reader of a public repository can see its job summaries, annotations
and logs, and can download its workflow artifacts. GitHub shows the alert
list of code scanning to people with write access only, but it shows the
alerts of a pull request, as annotations and check results, to every reader
who can see the pull request. So on a public repository, by default:

- the job summary, the annotations and the log show counts only: no titles,
  files, lines or evidence;
- the artifact holds `run.json` only (the record of the run, without
  findings);
- `upload-sarif: auto` uploads only for a run of the default branch that is
  not a pull request run, for example a scheduled run; the findings of a
  pull request run are not uploaded. GitHub also maps the results of a
  branch to the open pull requests from that branch, so an open pull
  request from the default branch to another branch shows them.

Set `public-findings: "true"` to show the findings to every reader. A
private or internal repository always gets the findings in the summary, the
artifact and code scanning. Code scanning in a private repository needs
GitHub Advanced Security (GitHub Code Security). Without it, set
`upload-sarif: "false"` and use the artifact or the job summary.

A GitHub-hosted runner has no egress restriction. Use a self-hosted runner
with a firewall, or the compose setup, when the network policy matters.

## GitLab CI

[`examples/gitlab-ci.yml`](../examples/gitlab-ci.yml) runs the image as the
job image and keeps the outputs as artifacts. Set `OPENROUTER_API_KEY` as a
masked and protected CI/CD variable. The job sets
`SENTRYTOWER_STATE_DIR=/tmp/sentrytower-state` because GitLab runs the job
as a different user.

## Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: sentrytower-audit
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 16200          # the wall clock of the run and a margin
  template:
    metadata:
      labels:
        app: sentrytower
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: checkout
          image: alpine/git:2.54.0
          args: ["clone", "--depth", "1", "https://github.com/example/repository.git", "/workspace/repo"]
          volumeMounts:
            - { name: repo, mountPath: /workspace/repo }
      containers:
        - name: sentrytower
          image: ghcr.io/national-compute/sentrytower:0.1.0   # or the image of docker/Dockerfile in your registry
          args: ["audit", "/workspace/repo", "--out", "/workspace/out/results"]
          env:
            - name: SENTRYTOWER_API_KEY
              valueFrom:
                secretKeyRef: { name: sentrytower, key: api-key }
          resources:
            requests: { cpu: "1", memory: 2Gi }
            limits: { cpu: "4", memory: 4Gi }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: [ALL] }
          volumeMounts:
            - { name: repo, mountPath: /workspace/repo, readOnly: true }
            - { name: out, mountPath: /workspace/out }
            - { name: home, mountPath: /home/dev }
            - { name: tmp, mountPath: /tmp }
      volumes:
        - { name: repo, emptyDir: {} }
        - { name: out, emptyDir: {} }     # or a PersistentVolumeClaim to keep the outputs
        - { name: home, emptyDir: { sizeLimit: 4Gi } }
        - { name: tmp, emptyDir: { sizeLimit: 1Gi } }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sentrytower-egress
spec:
  podSelector:
    matchLabels:
      app: sentrytower
  policyTypes: [Egress]
  egress:
    - to:                               # DNS
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - { protocol: UDP, port: 53 }
    - to:                               # the model endpoint only; or route through an egress proxy
        - ipBlock:
            cidr: 0.0.0.0/0             # replace with the addresses of your endpoint or egress gateway
      ports:
        - { protocol: TCP, port: 443 }
```

The output folder is a subfolder of the `out` volume: SentryTower creates
it as the user of the run, and the mount point of an `emptyDir` belongs to
root, so `--out /workspace/out` would be refused (exit code 2).

A NetworkPolicy matches addresses, not host names. For a host-name
allowlist, send the upstream traffic through an egress proxy (set
`HTTPS_PROXY`) or use an egress gateway of your service mesh or CNI. The
init container needs network access to clone; give it its own policy, or
clone outside the pod.

## Hardening

The audited code is untrusted input for the model. SentryTower limits the
agent to four read-only tools, keeps these tools in the audited repository
(a repository guard refuses each path outside it, also through a symbolic
link), and keeps the provider key out of each engine process
([SECURITY.md](../SECURITY.md)). On a workstation, the other files of your
user stay out of reach of the tools, but the container is the stronger
boundary. Add these layers in production:

| Layer | Setting |
| --- | --- |
| Repository | Mount it read only (`:ro`, `readOnly: true`) |
| File system | A read-only root file system; a tmpfs (or an `emptyDir`) for `/home/dev` and `/tmp` |
| User | A non-root user (`dev`, uid 1000), no privilege escalation, no capabilities |
| Network | Access only to the model endpoint: an egress proxy with an allowlist, a NetworkPolicy, or a firewall |
| Secrets | The key from a secret store into `SENTRYTOWER_API_KEY`; never in a file, an image or a command line |
| Budget | The cost cap ($2 by default) and a job timeout above the wall clock of the run |
| Data | The endpoint receives source code: use a provider whose data policy you accept, or a local endpoint. The built-in routes ask OpenRouter for endpoints that do not store or train on the data (`data_collection: "deny"`); see [where your code goes](../README.md#where-your-code-goes) |
| Outputs | `run.json` and the findings files hold no key. The output folder must not be a symbolic link and must belong to the user of the run. The run state (`--keep-state`) holds the agent sessions, which hold code: treat it as source code |
