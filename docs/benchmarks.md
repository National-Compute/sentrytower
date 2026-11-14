# Benchmarks

> [!IMPORTANT]
> **Our own benchmark, not an independent test.** We designed, ran and
> scored this comparison ourselves, and we also ran each of the other
> harnesses. The numbers are for an earlier internal build of SentryTower
> with GLM 5.3 Flash, not for this release and its default model.

In our own pre-registered test, an earlier internal build of SentryTower
with GLM 5.3 Flash detected 29.1% of the 117 advisories with answer keys (of
123 fresh advisories), at a false-alarm rate of 11.1%. With the same model
and budget, its detection was above that of each open-source harness it was
compared with, on the fixtures that harness completed: 11% for Piolium, 18%
for deepsec, 7% for 0 and 17% for OpenHack. Against Clearwing and Visa VVAH,
the lead is not separated: its interval crosses zero. The test does not
measure release 0.1.1, the next release or their default model
(`deepseek/deepseek-v4.1-flash-1017`), and the build missed about 7 in 10 of
the vulnerabilities.

This page gives the method, the numbers and their limits. The aggregate
numbers are also in [`benchmarks/`](../benchmarks/) as CSV and JSON.

## Conditions

Each harness ran under the same conditions:

- **Model:** `z-ai/glm-5.3-flash` through OpenRouter, the same model for
  every harness and, in SentryTower, for every role.
- **Budget:** 20,000,000 tokens and 4 hours (14,400 s) of wall clock for
  each run.
- **Sandbox:** the same offline sandbox for each harness, which could reach
  the model endpoint and nothing else. Two rivals differ: Codex Security ran
  in its own Bubblewrap sandbox inside it, and Clearwing ran with a local
  implementation of its sandbox protocol in place of Docker
  ([notes](#open-harnesses)).
- **Runs:** one run for each repository version.

These were the defaults of the internal builds that ran the test. A run of
the current code with `--model z-ai/glm-5.3-flash --max-tokens 20000000`
sends the same direct model requests as the benchmarked harness, apart from
the data policy of the provider settings, but its agent sessions run Pi
1.5.0, whose requests differ from those of the benchmarked Pi 0.84.1 (see
[How the release relates to the benchmarked harness](#how-the-release-relates-to-the-benchmarked-harness)).
The default model is `deepseek/deepseek-v4.1-flash-1017`, and a cost cap
sets the token ceiling; the numbers on this page are for GLM 5.3 Flash.

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
  the stricter answer key), the hybrid's detection stays above OpenHack's
  and the false-alarm margin fails.
- **Codex Security** needs the OpenAI Responses API and its own Bubblewrap
  sandbox; both ran inside the sandbox. Its campaign was stopped twice by
  the executor's key-exposure rule, which fails closed on a path it cannot
  read (no key was found in any run). The 29 fixtures are the runs that
  ended before the stop, and the result covers them only.
- **Clearwing** ran its default `standard` depth with a local
  implementation of its sandbox protocol, because the run container has no
  Docker daemon. 90 of its 246 runs reached the 20M-token ceiling. Its cost
  cap ended the campaign after 53 fixtures.
- **VVAH** reached its cost cap after 50 fixtures; a run costs 3.4 times a
  run of the hybrid.
- **Google Mantis** ran with its shipped `static-only` sandbox tier; no
  result of it is published.

The sensitivity views of each rival (the standard matcher, the stricter
answer key, and both) are in [`benchmarks/results.json`](../benchmarks/results.json),
under `open_harnesses.rivals[].sensitivity_views`, with the detection of the
hybrid and of the rival on that rival's fixtures. In every view the hybrid's
detection is above the rival's, but each view of each rival has
`"holds": false`: the pre-registered rule above does not hold in any
sensitivity view, for any rival. The rule needs more than a higher detection
(the 90% lower bound of the difference above zero and the false-alarm
margin), and the file publishes only the detection of each view, not its
interval or false alarms, so it does not show which part fails. Read the
sensitivity views as a higher point estimate, not as a confirmed lead.

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
- The benchmarked build missed about 7 in 10 of the vulnerabilities of the
  confirmation test (it detected 29.1%). The aggregates do not show how many
  vulnerabilities any harness found. An empty result is not a proof that the
  code is safe.
- The test measures an earlier internal build with GLM 5.3 Flash. It does
  not measure a release or the default model of a release.

## How the release relates to the benchmarked harness

The code of the release comes from the benchmarked harness. Two kinds of
check tie them together.

**Request parity, up to release 0.1.1.** Parity tests (outside this
repository, because the benchmark harness is in no public repository) ran
the benchmarked harness and the code of 0.1.x side by side on synthetic
repositories, with a fake model and Pi 0.84.1. The upstream request bodies
(prompts, message content, settings and the set of calls), the agent
commands and configuration files, and the findings were the same, byte for
byte. These tests cannot run again: the benchmarked harness is in no
repository.

**What this repository still checks.** The golden request fixtures
(`tests/golden`) hold the direct model requests of the funnel and the agent
commands and configuration files of four of those scenarios.
`tests/test_golden.py` fails when one changes, and it checks the SHA-256
value of each prompt file against the benchmarked files.

**Behavioral parity of the Pi 1.5.0 code with 0.1.1.** Pi 1.5.0 changes the
agent requests by design, so byte-for-byte parity no longer applies. On
2026-11-13 the project compared the released 0.1.1 image with an image
built from the main branch at `bb23f8a` (Pi 1.5.0, `findings.json` 2.0.0):

- the corpus: 50 synthetic issues, each with a vulnerable snapshot and a
  fixed snapshot (100 small repositories with planted flaws);
- one run of each snapshot with each image, with the default model
  (`deepseek/deepseek-v4.1-flash-1017`) and a $0.50 cap, in the hardened
  container of the [deployment guide](deployment.md#hardening);
- the same scorer for both: a vulnerable snapshot is detected when a result
  of `findings.sarif` lies in a planted file within 5 lines of a planted
  line; a fixed snapshot raises a false alarm when any result lies in a file
  that the fix changed.

| Image | Runs complete | Detected (of 50) | False alarms (of 50) | Model cost, all runs |
| --- | --- | --- | --- | --- |
| 0.1.1 | 100 | 50 | 20 | $1.06 |
| main (Pi 1.5.0) | 100 | 50 | 22 | $0.97 |

Both images detected every planted flaw. On the fixed snapshots both
flagged 18, only 0.1.1 flagged 2 and only main flagged 4: 6 discordant
pairs, within the variation of one run each. The false-alarm rule counts any
result in a changed file, so it overstates the false alarms of both images
alike.

This check shows that the Pi 1.5.0 code finds what 0.1.1 finds on small
repositories with planted flaws. It is not a detection rate on real code,
and it says nothing about the confirmation test or the open-harness test
above. The corpus and the scorer are in the private benchmark repository.

The release differs from the benchmarked harness in these points. Only the
first two change a request body:

- The built-in OpenRouter routes add `data_collection: "deny"` to the
  provider settings of each request: OpenRouter then uses only the
  endpoints that do not store or train on the data.
- The agent sessions run Pi 1.5.0; the benchmarked harness ran Pi 0.84.1
  with the same command and configuration files. Pi 1.5.0 writes another
  system prompt for each agent request and leaves `"strict": false` out of
  each tool definition. The task prompt, the tool descriptions and
  parameters, the tool results and the requests of the funnel's direct
  calls are the same.
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
