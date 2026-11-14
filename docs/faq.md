# Frequently asked questions

### What does SentryTower find?

Vulnerabilities in source code that a language model can show with a path
from attacker-controlled input to a harmful operation: injections, path
traversal, unsafe deserialization, server-side request forgery, missing
authorization and similar weaknesses. Each finding has a file and a line
range, CWE identifiers, a severity and an explanation.

### How good is it?

Its detection with the default model is not measured. **In our own
pre-registered test, not an independent one,** an earlier internal build of
SentryTower with GLM 5.3 Flash detected 29% of the 117 fresh advisories with
answer keys, at a false-alarm rate of 11%. With the same model and budget,
its detection was above that of each open-source harness it was compared
with (Piolium 11%, deepsec 18%, 0 7%, OpenHack 17%; Clearwing, VVAH and
Codex Security on the fixtures they completed). Against Clearwing and VVAH,
the lead is within the margin of error. The build missed about 7 in 10 of
the vulnerabilities in that test. We designed, ran and scored the test
ourselves, and the numbers are for GLM 5.3 Flash, not for a release or its
default model. See [benchmarks](benchmarks.md) for the method and the
limits.

### Is an empty result a proof that the code is safe?

No. The engines read a part of the code within a budget, and a language
model can miss a vulnerability or report a wrong one. Use SentryTower in
addition to code review, tests and other analysis tools.

### Can I pay more for a deeper audit?

Yes. Give a larger budget: `--depth deep` ($10), `--depth max` ($50) or
`--max-cost-usd`. Above the standard run ($2) the funnel checks more units,
runs more and deeper deep checks, sends focus sessions after one weakness
family each and verifies each finding three times; a repository of more
than 1,000 files gets one agent session for each slice of its code. Such a
run is a [preview](#what-does-preview-mean). Its first findings are the
standard selection, and its further findings come after them, in a second
tier. When the work ends first, a small repository ends with money left.
See [depth](configuration.md#depth-what-a-larger-budget-buys).

### What does a run cost?

Each audit has a cost cap: $2 by default, when each model of the route has
prices. The gateway stops new calls at the cap, and each report states the
spend. With the default model (`deepseek/deepseek-v4.1-flash-1017`), $2 is
the standard run with the plan of 20M tokens; at the model's list prices,
20M tokens of the funnel cost about $1.78 (an estimate from the prices and
a fixed token mix), so the cap is an upper limit and a run can stop well
below it. You set another budget with `--depth`, `--max-cost-usd` or the setup
([the budget](configuration.md#the-budget-dollars-and-tokens)). The cap
counts the usage that the provider reports: a model call that fails or
times out without a usage report counts nothing, so the spend at the
provider can be a little higher. `run.json` gives the tokens and the cost
of each run.

### How do I run without a cap?

Give a cap of 0: `--max-cost-usd 0`, `max_cost_usd = 0` in the settings
file, `SENTRYTOWER_MAX_COST_USD=0`, `max-cost-usd: "0"` in the GitHub
Action, or "No cap" in the setup. The run then has the token plan of
20,000,000 tokens (or `--max-tokens`), and its cost follows the prices of
the models. A model without prices always runs without a cap.

### What does preview mean?

A run above the standard depth (`--depth deep`, `--depth max`, or a cap
that buys more than one standard run) carries the label "preview: more
checks; effect on findings not yet measured". The run makes more checks than
the standard run, and the effect of these checks on the findings is not yet
measured. The findings of the standard selection come first, by the same
rule as at $2. The further findings are tier 2: they come after the others,
under the preview label, in `report.md`, `report.html` and the result
screen, and with the property `"tier": 2` in `findings.json` and in the SARIF
properties.

### Why did my run exit with code 4?

The run failed or is incomplete. The last lines of the log, the result
section of `report.md` and `result.failure` in `run.json` give the reason in
one sentence:

- HTTP 401: the provider refused the key. Check `SENTRYTOWER_API_KEY`, or
  the variable or the keychain entry that the run used.
- HTTP 402: the provider account has no credit. Add credit, then run again.
- HTTP 403: the provider refused the account or the request. Check the key
  and the limits of the account. OpenRouter can also answer 403 for a
  moderation refusal of one request; SentryTower treats each 403 as fatal.
- HTTP 404: no endpoint serves the model on the route. On OpenRouter with a
  built-in model, no endpoint of the allowlist serves it under
  `data_collection: "deny"`; on another endpoint, check the model ID and
  the base URL.
- More than 20% of the model calls failed (from 10 calls on), or each call
  failed. The reason names the main kinds, for example `HTTP 429` or
  `malformed answer`.
- The engine crashed, or the agent of a large repository gave no answer.
- The funnel did not do its work: its inventory (phase 0) failed, it
  checked no code unit (for example "No code unit was checked: 13 of 13
  unit checks failed." when the model answers in prose), more than 20% of
  its unit checks failed, or more than half of its agent sessions ended
  without an answer (for example an endpoint that refuses tool
  definitions).

After a refusal of the provider, SentryTower sends no more calls in that
run. The outputs are written anyway, with the findings that the run has.
The GitHub Action fails the step with the same reason, whatever `fail-on`
says.

### Why does a run on a public repository show counts only?

Every reader of a public repository can see its job summaries, annotations
and logs, and can download its workflow artifacts. A finding can describe a
vulnerability that is not fixed yet. So on a public repository (and when the
visibility is unknown) the GitHub Action shows counts only, the artifact
holds `run.json` only, and `upload-sarif: auto` uploads the SARIF file only
for a run of the default branch that is not a pull request run. GitHub
shows the alert list of code scanning only to people with write access, but
it shows the alerts of a pull request to every reader. Set
`public-findings: "true"` to show the findings to every reader
([deployment](deployment.md#public-repositories)).

### How long does a run take?

The wall clock of a run is at most 4 hours by default (`--wall-clock`). The
funnel stops when its queue is empty; on a small repository a run usually
ends long before the limit.

### Can I use another model or provider?

Yes. Any OpenAI-compatible endpoint works (`--base-url`), and each role can
have its own model ([configuration](configuration.md#single-llm-and-multi-llm)).
The detection rate and the cost depend on the models. Give each model a
[request policy](configuration.md#model-request-policies) with its prices,
so that the cost cap works: a model without prices runs without a cap, and
a cap that you give for it is a usage error (exit code 2).

### Can I use a local model?

Yes: vLLM, Ollama, LM Studio and other servers with an OpenAI-compatible
`/chat/completions` endpoint. See
[`examples/local-endpoint.toml`](../examples/local-endpoint.toml). The agent
roles need a model that calls tools reliably. A local model has no prices,
so a run has no cost cap and the standard plan of 20M tokens (or
`--max-tokens`).

### Where does my code go?

To the model endpoint that you configure, and nowhere else: the README
section [Where your code goes](../README.md#where-your-code-goes) gives the
whole path. On the built-in routes, OpenRouter uses only the endpoints of an
allowlist that do not store or train on the data
(`data_collection: "deny"`). SentryTower has no telemetry and no update
check. The outputs and `run.json` hold no prompt and no answer text; the
findings quote code. The run state (removed after a complete run unless you
give `--keep-state`) holds the agent sessions, which hold code.

### Can the audited code attack SentryTower?

The code can hold text that tries to instruct the model (prompt injection).
The agent has only the read-only tools `read`, `grep`, `find` and `ls`; it
has no shell, no write tool and no web tool. A repository guard keeps the
tools in the audited repository: a path outside it, also through a
symbolic link, gets an error. The engines never get the provider key. A
link in the repository cannot redirect the outputs or the run state, a
program of the repository never runs in place of `node`, `rg` or `fd`, and a
control character of a finding or a file name reaches the terminal as `?`.
Run the container with the repository mounted read only and with network
access only to the model endpoint ([deployment](deployment.md#hardening)).
A prompt injection can still change the findings of a run.

### Why does the router use 1,000 files?

It is the large-repository rule of the funnel engine, fixed before the
benchmark and not tuned. The count (rule `size-route-v2`) leaves out the
folders that hold no code of the project: version control, installed
dependencies and caches, vendored, generated and build output, and virtual
environments ([the router](architecture.md#the-router)). `run.json` records
the count, the skipped folders and the route.

### Why are there at most 6 findings on the funnel route?

The funnel has a cap of 6 findings for a run and 2 for each file. The cap
was chosen on development data, before the confirmation test: more findings
gave few more detections and more false alarms. `[funnel] max_findings_total`
changes it. A deeper run keeps these 6 findings and adds a second tier after
them, under the preview label. The single-agent route has no cap.

### Why a pinned Pi version?

The Pi CLI builds the requests of the agent sessions. Another version can
send other requests and give other results. `sentrytower doctor` warns when
another version is installed; the container image pins 1.5.0.

### Does it work on Windows?

Use the container image (Docker Desktop or WSL 2). The engines use POSIX
process groups and signals.

### How do I report a vulnerability of SentryTower?

Privately, through the security advisory form of the repository. See
[SECURITY.md](../SECURITY.md).
