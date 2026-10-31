# Benchmarks

> [!IMPORTANT]
> **Our own benchmark, not an independent test.** We designed, ran and
> scored this comparison ourselves, and we also ran each of the other
> harnesses. The numbers are for an earlier internal build of SentryTower
> with GLM 5.3 Flash, not for this release and its default model.

With the same model, budget and sandbox, SentryTower detected more real
vulnerabilities than each open-source harness it was compared with: 29%
on 123 fresh advisories, against 11% for Piolium, 18% for deepsec, 7% for 0
and 17% for OpenHack, at a false-alarm rate of 11%. Against Clearwing and
Visa VVAH, the lead is not separated: its interval crosses zero.

This page gives the method, the numbers and their limits. The aggregate
numbers are also in [`benchmarks/`](../benchmarks/) as CSV and JSON.

## Conditions

Each harness ran under the same conditions:

- **Model:** `z-ai/glm-5.3-flash` through OpenRouter, the same model for
  every harness and, in SentryTower, for every role.
- **Budget:** 20,000,000 tokens and 4 hours (14,400 s) of wall clock for
  each run.
- **Sandbox:** the same offline sandbox for each harness. The harness could
  reach the model endpoint and nothing else.
- **Runs:** one run for each repository version.

These were the defaults of the internal builds that ran the test. A run of
this release with `--model z-ai/glm-5.3-flash --max-tokens 20000000` sends the
same model requests as the benchmarked harness, apart from the data policy
of the provider settings (see
[How the release keeps the benchmarked behaviour](#how-the-release-keeps-the-benchmarked-behaviour)).
The default model of this release is `deepseek/deepseek-v4.1-flash-1017`,
and a cost cap sets the token ceiling; the numbers on this page are for GLM 5.3
Flash.

### Scoring

- **Detection:** a finding whose location is within 10 lines of the true
  vulnerable operation. The location matcher is strict: a location spans at
  most 31 lines, and a finding has at most 3 locations. The matcher was
  calibrated on development data so that no harness wins by chance matches.
- **False alarm:** a finding on the fixed lines of the fixed version of the
  repository.
- **Intervals:** 90% paired cluster-bootstrap intervals over repositories.
  A difference is in percentage points (pp).

## Confirmation test

The confirmation test was pre-registered on 2026-10-20, before any data was
collected.

- **Advisories:** the 123 security advisories that were published from
  2026-10-10 to 2026-10-20, after the training cutoff of the model. 117 of
  them have answer keys; they are in 93 repositories.
- **Versions:** each repository runs at its vulnerable version and at its
  fixed version.
- **Answer keys:** drafted by models of two model families, with a review of
  the flagged drafts.

### Results

| Harness | Detection | False alarms | Mean cost per run |
| --- | --- | --- | --- |
| **SentryTower hybrid** | **29.1%** [21.8, 36.5] | 11.1% | $0.30 |
| Piolium | 11.1% [6.6, 16.2] | 9.4% | $0.10 |
| Single-agent engine alone | 22.2% [15.3, 29.7] | 8.5% | $0.08 |

The hybrid against Piolium:

- **Detection:** +17.9 pp [+10.4, +25.4].
- **False alarms:** +1.7 pp [−4.5, +8.2].

All three pre-registered conditions passed. They also pass in each
sensitivity view:

| View | Hybrid | Piolium |
| --- | --- | --- |
| Standard matcher | 33.3% | 13.7% |
| Stricter answer key | 24.6% | 8.2% |
| Both | 26.2% | 8.2% |

### By repository size

| Repository size | Hybrid − Piolium |
| --- | --- |
| Under 1,000 files | +24.0 pp [+15.3, +32.5] |
| 1,000 to 9,999 files | +7.5 pp [−5.7, +21.7] (not significant) |

The hybrid sends a repository of 1,000 files or fewer to the funnel engine.
Most of its gain comes from these repositories.

### Chance matches

A finding can match a true location by chance. The chance-match rates on
this set are: hybrid 8.8%, Piolium 5.5%, single agent 6.1%. All three are
above the 5% target. The difference between the hybrid and Piolium (3.3
points) is far below the detection gap (17.9 points).

### Cost

The mean cost of a run at OpenRouter prices in October 2026: hybrid $0.30,
Piolium $0.10, single agent $0.08. The funnel engine makes more model calls
than a single agent, so a run of the hybrid costs more. `run.json` of each
run gives its tokens and its cost.

## Open harnesses

The second test, registered on 2026-10-24 before any run, compared the
hybrid with the open-source harnesses that audit the source code of a whole
repository, run their own or an open agent, and accept any model. Each
rival ran at its documented default settings on the same 123 advisories,
under the conditions above, with the same scorer and the same frozen answer
keys. The hybrid did not run again; its runs are those of the confirmation
test.

**The rule for each rival**, fixed before the runs: the hybrid's detection
is above the rival's; the 90% lower bound of the difference is above zero;
and the hybrid's false-alarm rate is at most the rival's plus 5 points. A
rival that reached its cost cap is scored on the fixtures it completed,
paired with the hybrid's runs on the same fixtures.

| Rival | Version | Fixtures | Hybrid detection | Rival detection | Difference | False alarms, hybrid / rival | Cost a run, rival | Rule |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Vercel deepsec | `17e37f7` | 117 | 29.1% | 17.9% [11.2, 25.2] | +11.1 pp [+1.8, +20.0] | 11.1% / 21.4% | $0.25 | holds |
| 0 (0sec-labs/0) | v0.24.1 | 117 | 29.1% | 6.8% [3.3, 11.0] | +22.2 pp [+15.7, +28.8] | 11.1% / 6.8% | $0.06 | holds |
| OpenHack | `6a0675e` | 113 | 29.2% | 16.8% [11.0, 23.1] | +12.4 pp [+5.3, +19.8] | 11.5% / 6.2% | $0.21 | false-alarm margin missed by 0.3 pp |
| OpenAI Codex Security | npm 0.6.0 | 29 | 31.0% | 10.3% [3.1, 20.7] | +20.7 pp [+6.7, +35.7] | 6.9% / 17.2% | $0.40 | holds on the partial campaign |
| Clearwing | `b6e8eae` | 53 | 32.1% | 24.5% [15.1, 35.2] | +7.5 pp [−3.8, +19.2] | 15.1% / 39.6% | $0.54 | lead not separated |
| Visa VVAH | `3d972f6` | 50 | 34.0% | 28.0% [17.6, 38.8] | +6.0 pp [−4.0, +16.0] | 16.0% / 26.0% | $1.02 | lead not separated |

The hybrid's detection in each row is its rate on that rival's fixtures.
The aggregates are in [`benchmarks/open-harnesses-2026-10.csv`](../benchmarks/open-harnesses-2026-10.csv).

Notes on the campaigns:

- **deepsec and 0** completed every run.
- **OpenHack** completed every run; its cost cap ended the last 6 fixtures,
  which are left out. In the sensitivity views (the standard matcher and
  the stricter answer key), the detection lead holds and the false-alarm
  margin fails.
- **Codex Security** needs the OpenAI Responses API and its own Bubblewrap
  sandbox; both ran inside the sandbox. Its campaign was stopped twice by
  the executor's key-exposure rule, which fails closed on a path it cannot
  read (no key was found in any run). The 29 fixtures are the runs that
  ended before the stop; a third campaign is in progress.
- **Clearwing** ran its default `standard` depth with a local
  implementation of its sandbox protocol, because the run container has no
  Docker daemon. 90 of its 246 runs reached the 20M-token ceiling. Its cost
  cap ended the campaign after 53 fixtures.
- **VVAH** reached its cost cap after 50 fixtures; a run costs 3.4 times a
  run of the hybrid.
- **Google Mantis** ran with its shipped `static-only` sandbox tier; its
  campaign is in progress. Its result will be added here.

The sensitivity views of each rival (the standard matcher, the stricter
answer key, and both) are in the CSV. In every view the hybrid's detection
is above every rival's.

### What was not compared

Harnesses that need Claude Code or a Codex-only setup (Anthropic's
defending-code-reference-harness, Capital One VulnHunter, evilsocket/audit,
RAPTOR, Open Kritt), skill packs (the Cloudflare security-audit skill, Trail
of Bits skills), single-language harnesses, pull-request reviewers, and
closed products. A claim of "best harness" cannot cover them.

## VulnGym

Tencent VulnGym v0.1.4: all 157
human-verified advisories that the scorer supports. The benchmark ran the
vulnerable versions only, so it has no false-alarm measure. This test was
also pre-registered.

| Harness | Detection |
| --- | --- |
| Funnel engine | 8.9% |
| Single-agent engine | 12.1% |
| Piolium | 4.5% |

- **Funnel engine − Piolium:** +4.5 pp [+1.3, +16.4].
- The hybrid as a whole was not run on VulnGym; each of its two engines was.
- One repository holds 94 of the 157 advisories.

## Limits

Read the numbers with these limits:

- The answer keys of the fresh advisory sets are drafted by models (with a
  review of the flagged drafts), not written by people.
- The open-harness comparison covers the harnesses listed above, each at
  its defaults with the parts that need Docker or the internet off. Several
  of them are built for frontier models and may do better with them.
- One model: GLM 5.3 Flash. The results of another model, or of a
  multi-LLM configuration, are not measured.
- Large repositories (10,000 files or more) remain hard for every harness.
- The costs are at OpenRouter prices in October 2026.
- About 7 of 10 vulnerabilities in the confirmation test were not
  detected. An empty result is not a proof that the code is safe.

## How the release keeps the benchmarked behaviour

The code of the release comes from the benchmarked harness. The project
checks that the default configuration sends the same model requests:

- Parity tests (outside this repository, because the benchmark harness is
  not public) ran the benchmarked harness and the release side by side on
  synthetic repositories, with a fake model and the real Pi CLI. The
  upstream request bodies (prompts, message content, settings and the set
  of calls), the agent commands and configuration files, and the findings
  were the same, byte for byte.
- The golden request fixtures of this repository (`tests/golden`) hold the
  model requests of four of those scenarios. The benchmarked harness sent
  the same requests, apart from the data policy of the provider settings. `tests/test_golden.py` fails when a request changes.
- The prompt files are the benchmarked files; `tests/test_golden.py` checks
  their SHA-256 values.

The release differs from the benchmarked harness in these points. Only the
first changes a request body, and only in its provider settings:

- The built-in OpenRouter routes add `data_collection: "deny"` to the
  provider settings of each request: OpenRouter then uses only the
  endpoints that do not store or train on the data.

- The gateway checks a random credential of the run on each local request.
  The benchmarked proxy accepted any local request.
- A repository guard refuses each agent tool call whose path is outside
  the audited repository and the Pi package. The benchmarked sandbox held
  nothing else to read; a release run can have the provider key and other
  files next to the repository. A refused call gets an error result.
- The gateway sends `X-Title` and `HTTP-Referer` headers to identify
  SentryTower to OpenRouter.
- A model path that starts with the repository folder of a local run is
  read as a repository path. In the benchmark the repository folder was
  always `/workspace/repo`, which the container image of the release also
  uses.
- The release leaves out code paths that were off in the benchmarked
  version (a second pass, a second review lens, an evidence step and
  Semgrep).
