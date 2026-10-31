# Output format

`sentrytower audit` writes up to five files into the output folder (`--out`,
default `./sentrytower-results`):

| File | Format | For |
| --- | --- | --- |
| `findings.json` | JSON, schema version 1.0.0 | Tools and scripts |
| `findings.sarif` | SARIF 2.1.0 | GitHub code scanning and other SARIF viewers |
| `report.md` | Markdown | People, in a ticket or a job summary |
| `report.html` | HTML | People, in a browser |
| `run.json` | JSON, schema version 1.0.0 | The record of the run: the result, the route, the models, the usage, the cost, the timings |

`--format json,sarif,markdown,html` selects the first four files; `run.json`
is always written. A run that starts writes its outputs in every case, also
when it fails, is incomplete or is interrupted. Each file is written to a
new private staging file and renamed in one step, so a reader never sees a
partial file, and a link at the name of a file is replaced, never followed.
The output folder must pass its checks before any model call
([the output folder](configuration.md#the-output-folder)).

## The result

Each run has one result: `result` in `run.json`, and the same object in the
`run` part of `findings.json`. `report.md`, `report.html`, the result screen
of a terminal and the last lines of the plain log state it in the same
plain sentences: the spend, why the run stopped, how many units it checked,
the depth of a deeper run, and the failure.

```json
{
  "status": "complete",
  "stop_reason": "budget",
  "stop_text": "The run spent 85% of the $10.00 cost cap, so no new work started; the running work finished.",
  "failure": null,
  "spent_usd": 8.93,
  "cap_usd": 10.0,
  "units": {"kind": "code units", "checked": 2950, "failed": 4, "total": 3400},
  "calls": {"total": 4180, "failed": 31, "failed_share": 0.0074},
  "depth_factor": 5.0,
  "preview": true,
  "sessions": {"answered": 61, "failed": 2}
}
```

| Field | Meaning |
| --- | --- |
| `status` | `complete`; `incomplete` (the engine crashed; the agent of the agent route gave no answer; more than 20% of the model calls failed, from 10 calls on, or each call failed; or the funnel did not do its work: its inventory, phase 0, failed, it checked no code unit, more than 20% of its unit checks failed, from 10 tried checks on, or more than half of its agent sessions ended without an answer while no wall clock or interrupt stopped the run); `failed` (the provider refused the key, the account or the route with HTTP 401, 402, 403 or 404, or the output of the engine cannot be read); `interrupted` (Ctrl-C or SIGTERM) |
| `stop_reason` | `done` (the engine ended on its own); `budget` (85% of the cap is spent, the money left buys no next task, or the gateway refused a call at the cap); `token-ceiling`; `wall-clock`; `provider-error`; `engine-error`; `interrupted` |
| `stop_text` | One plain sentence: why the run stopped. An incomplete run whose engine ended on its own says "The engine ended, but its work is incomplete." |
| `failure` | One plain sentence: why the status is not `complete` (for example "No code unit was checked: 13 of 13 unit checks failed." or "12 of 13 agent sessions ended without an answer."); after a provider refusal also what to do (for example "The provider refused the key (HTTP 401): check SENTRYTOWER_API_KEY."); null for a complete run |
| `spent_usd` | The cost of the run in US dollars; 0.0 when the run counted no token (for example a run that the provider refused at once); null only when tokens were counted and no cost is known |
| `cap_usd` | The cost cap of the run; null without a cap |
| `units` | `kind` (`code units` on the funnel route, `agent sessions` on the agent route), `checked`, `failed` and `total` (null when unknown). A unit that failed is not checked: a unit whose file cannot be read, or a unit check that failed after its one retry or whose answer cannot be read. The agent route also gives `files_read`, the files that its sessions read |
| `calls` | `total`: the model calls that reached the provider; `failed`: those whose last attempt ended with an HTTP error, a provider error or a malformed answer; `failed_share`. A budget refusal of the gateway and a call after a provider refusal are not in it |
| `depth_factor`, `preview` | The count of standard runs that the budget buys; `preview` is true when it is above 1 |
| `sessions` | The agent sessions that gave an answer (`answered`) and that ended without one (`failed`) |
| `provider_message` | Only after a provider refusal: the error message of the provider, at most 200 characters, cleaned of control characters and key-like text, and left out when a part of it is in the request |

The exit code follows the status: 0 for a complete run (1 when a finding is
at or above `--fail-on`), 4 for a failed or incomplete run, 130 for an
interrupted run ([exit codes](configuration.md#exit-codes)).

## findings.json

The JSON Schema is
[`src/sentrytower/schemas/findings-v1.schema.json`](../src/sentrytower/schemas/findings-v1.schema.json).
A minor version (1.x) adds optional fields, and a field keeps its meaning
within version 1.

```json
{
  "$schema": "https://raw.githubusercontent.com/National-Compute/sentrytower/v1/src/sentrytower/schemas/findings-v1.schema.json",
  "schema_version": "1.0.0",
  "tool": {"name": "SentryTower", "version": "0.1.0"},
  "run": {
    "id": "5f0c3b1e9d2a4c7f8e6b1a2d3c4e5f60",
    "route": "funnel",
    "started_at": "2026-11-01T10:00:00+00:00",
    "repository": "webapp",
    "files_counted": 412,
    "result": {
      "status": "complete",
      "stop_reason": "done",
      "stop_text": "The run finished its work: no code unit, lead or finding was left to check.",
      "failure": null,
      "spent_usd": 0.38,
      "cap_usd": 2.0,
      "units": {"kind": "code units", "checked": 140, "failed": 0, "total": 140},
      "calls": {"total": 412, "failed": 3, "failed_share": 0.0073},
      "depth_factor": 1.0,
      "preview": false,
      "sessions": {"answered": 9, "failed": 0}
    }
  },
  "summary": {"findings": 2, "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0}},
  "findings": [
    {
      "id": "ST-001",
      "rank": 1,
      "title": "Command injection in ping",
      "severity": "critical",
      "cwe": ["CWE-78"],
      "location": {"path": "app.py", "start_line": 60, "end_line": 60},
      "related_locations": [{"path": "app.py", "start_line": 57, "end_line": 59, "note": "the route takes the host"}],
      "explanation": "The host parameter goes to os.system without a check.\n\nExploit conditions: The attacker controls the host parameter.",
      "evidence": "The host parameter goes to os.system without a check.",
      "exploit_conditions": "The attacker controls the host parameter.",
      "engine": "free-roaming",
      "route": "funnel",
      "confidence": null,
      "verification": {"verdict": null, "keep_score": null, "status": "none", "reason": null},
      "tier": 1,
      "fingerprint": "sha256:337ab3133333efa8483a144d4fb131ff"
    },
    {
      "id": "ST-002",
      "rank": 2,
      "title": "Path traversal in read",
      "severity": "high",
      "cwe": ["CWE-22"],
      "location": {"path": "files.py", "start_line": 51, "end_line": 53},
      "related_locations": [],
      "explanation": "open(os.path.join(BASE, name)) takes the name of the request.\n\nExploit conditions: The attacker sends ../ in the name.",
      "evidence": "open(os.path.join(BASE, name)) takes the name of the request.",
      "exploit_conditions": "The attacker sends ../ in the name.",
      "engine": "deep-check",
      "route": "funnel",
      "confidence": 0.84,
      "verification": {"verdict": "exploitable", "keep_score": 0.84, "status": "verified", "reason": null},
      "tier": 1,
      "fingerprint": "sha256:c37f70f0ad0617cbd6d6b15aa9435059"
    }
  ]
}
```

### Fields of a finding

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | `ST-001`, `ST-002`, … in rank order (unique in the run, not across runs) |
| `rank` | integer | The place in the ranked output of the run |
| `title` | string | A short name of the vulnerability (at most 300 characters) |
| `severity` | `critical`, `high`, `medium`, `low`, `unknown` | The severity that the engine gave; `unknown` when the answer gave none |
| `cwe` | list of strings | CWE identifiers (`CWE-<n>`, no leading zeros), the most specific first; can be empty |
| `location` | object or null | The primary location: the critical operation. `path` is relative to the repository root with `/` separators; `start_line` and `end_line` are 1-based and inclusive; `note` when the engine gave one. Null when the engine gave no valid location |
| `related_locations` | list | Up to 3 more locations in the order of the engine (for example the source of the data, the route); each can have a `note` |
| `explanation` | string | The evidence and the exploit conditions as one text |
| `evidence` | string | The code at the locations and why it is vulnerable |
| `exploit_conditions` | string | What an attacker must control, and what the attacker can then do |
| `engine` | `free-roaming`, `deep-check`, `single-agent` | The engine that found it (see below) |
| `route` | `funnel`, `agent` | The route of the run |
| `confidence` | number or null | The keep score (0 to 1) of the blind verification of a deep-check finding or of a verified slice finding; null for the other findings |
| `verification` | object | `status`: `verified`; `unverified` when the verification failed, was refused or did not run, with a short `reason`; `none` when the route does not verify the source of the finding (the free-roaming session, the single agent). `verdict` (`exploitable`, `safe`, `unclear` or null) and `keep_score` of the verification; `votes`, the verdicts of the three votes of a slice finding |
| `tier` | 1 or 2 | 1: the findings of the standard selection; 2: the further findings of a deeper run, under the label "preview: more checks; effect on findings not yet measured" |
| `fingerprint` | string | `sha256:` and 32 hex digits of the file, the first CWE and the title: a stable identity across runs while the line numbers change |

### Engines

| Engine | Route | Meaning |
| --- | --- | --- |
| `free-roaming` | funnel | The agent session of the funnel on the whole repository. Its findings come first in the output, in the order of the agent, with the locations that the agent gave |
| `deep-check` | funnel | An agent session of the funnel on one code unit with a lead (in a deeper run, also the sweep and the focus sessions). The first location is the resolved critical-operation line; the findings rank by their verification score |
| `single-agent` | agent | The agent of a repository with more than 1,000 files, and in a deeper run each slice session. The findings of the whole-repository session are in the order of the agent, with no output cap |

Tier 1 of the funnel route has at most 6 findings, and at most 2 for each
file: the same selection at every budget. A deeper run adds tier 2 after
it: first the findings that the majority of their verification votes calls
"exploitable", then those whose verification did not run. On the agent
route, the findings of the whole-repository session are tier 1, and the
findings of the slices are tier 2. A finding without a verification stays
in the output with the status `unverified` and its reason.

### How the locations are read

The answer of an agent lists the locations of each finding. SentryTower
keeps each valid location in the order of the agent and records each
deviation from the answer schema: a path alias (`file`, `file_path`), a line
alias (`line`, `lines`, `line_range`), a `path:N` suffix, and a reversed
range. A path that starts with the repository folder becomes relative to the
repository root. A finding without a valid location stays a finding, with
`location: null`.

## findings.sarif

The SARIF file follows [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) and the
[GitHub code scanning requirements](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).
The test suite validates it against the OASIS JSON Schema.

| SARIF | From |
| --- | --- |
| `runs[0].tool.driver` | `name` SentryTower, `version`, `semanticVersion`, `informationUri` |
| `runs[0].tool.driver.rules[]` | One rule for each CWE of the findings (`id` `CWE-<n>`, the name of the weakness, `helpUri` to MITRE, `tags` `security` and `external/cwe/cwe-<n>`); `SENTRYTOWER-UNCLASSIFIED` for a finding without a CWE |
| `rules[].properties.security-severity` | The highest severity of the findings of the rule: critical 9.5, high 8.0, medium 5.5, low 3.0 (GitHub shows it as the alert severity) |
| `results[].ruleId`, `ruleIndex` | The first CWE of the finding |
| `results[].level` | `error` for critical and high, `warning` for medium and unknown, `note` for low |
| `results[].message.text` | The title, then the explanation |
| `results[].locations[0]` | The primary location: `artifactLocation.uri` relative to `%SRCROOT%` (percent-encoded, with the `--sarif-path-prefix` folder in front), `region.startLine` and `endLine` |
| `results[].relatedLocations[]` | The related locations, with their notes |
| `results[].partialFingerprints` | `sentrytowerFindingHash/v1`: the fingerprint of the finding |
| `results[].properties` | `id`, `rank`, `severity`, `security-severity`, `cwe`, `engine`, `route`, `tier` (1 or 2), `verification` (`verified`, `unverified` or `none`); `confidence` when the finding has a keep score; `verificationReason` for an unverified finding |
| `runs[0].automationDetails.id` | `<category>/` (`--sarif-category`, default `sentrytower`): one category for each audit, so a repository that crosses the size threshold keeps its alerts, and two audits of one repository keep theirs |
| `runs[0].properties` | `route`, `filesCounted`, `findingsWithoutLocation`, `models` |

A finding without a location in the repository (no location, or only a
path outside the repository) is not a SARIF result: code scanning needs a
location. `findingsWithoutLocation` counts it, and `findings.json` and
`report.md` keep it.

Code scanning reads each path from the root of the repository. For the
audit of a subfolder, give the folder with `--sarif-path-prefix` (the
GitHub Action does it for its `path` input); `findings.json` keeps the
paths relative to the audited folder.

## report.md

The report for people. The GitHub Action writes its own summary of the run
to the job summary.

- A summary of the run: the repository, the route, the models, the tokens
  and the cost, the duration and the stop, and the findings by severity.
- `## Result`: the sentences of the result, the spend against the cap, why
  the run stopped, the checked units, the depth of a deeper run (with the
  preview label) and the failure.
- `## Findings`: a table of the findings of tier 1, then the details of
  each finding with its locations, its engine, its verification score, the
  label of an unverified finding (`Verification: unverified: <reason>`) and
  its explanation.
- `## More findings (preview: more checks; effect on findings not yet
  measured)`: the findings of tier 2 of a deeper run, in the same form.

A run without findings says that no vulnerability was reported, and that
this is not a proof that the code is safe.

## report.html

The same report as one web page, for a browser: the agent, the facts of the
run, a note with the result (for a failed or incomplete run, "The audit did
not finish."), the warnings, the findings by severity with links to their
details, and each finding with its locations, its explanation, its exploit
conditions, the label of an unverified finding and a link to the CWE entry
of MITRE. The findings of tier 2 follow in a section "More findings" with
the preview label. In a terminal, SentryTower opens the page when the audit
ends (`--no-open`, or `run.open_report = false`, turns this off; CI, an SSH
session and a computer without a screen never open it).

The page is one self-contained file. It loads nothing and runs no script:
its Content-Security-Policy allows only inline styles and `data:` images.
Each text of the model, the repository and the run is escaped; an
explanation keeps code blocks, inline code, bold text, lists and
paragraphs. It reads on light and dark screens and prints on paper.

## run.json

The record of the run. It holds numbers, codes, model IDs and paths; it holds
no prompt, no answer text and no key. The one text of a provider is
`result.provider_message` after a provider refusal (see [the result](#the-result)).

| Field | Meaning |
| --- | --- |
| `schema_version`, `tool` | `1.0.0`; the name and the version of SentryTower |
| `run_id`, `started_at`, `ended_at`, `seconds` | The identity and the time of the run |
| `status`, `failure` | The status and the failure of `result` |
| `result` | The result of the run ([the result](#the-result)) |
| `repository` | `name`, `path`, `files_counted`, `counted_up_to` |
| `route`, `router` | The route and the record of the size rule: `rule` (`size-route-v2`), `route`, `files_counted`, `counted_up_to`, `large_repo_files`, `skipped` (the folders that the count left out: `folders`, `files` counted up to `counted_up_to`, and at most 50 `names`), `seconds` |
| `models` | The model of each role of the route |
| `configuration` | The resolved configuration: models, provider (without a key), budget (the settings as given), router, funnel parameters, the policy of each model, `sources` |
| `usage` | `total` and `models`: `calls`; `upstream_calls` (the calls that reached the provider); `attempts`, `retries`; `refusals` (budget refusals of the gateway); `failures` and `failed_by` (the failed calls by the outcome of their last attempt, for example `HTTP 429` or `malformed answer`); `blocked` (the calls after a provider refusal, which never went upstream); `length_stops` (attempts that ended at the completion ceiling); input, output, reasoning, cached and total tokens; `cost_usd` and `cost_source` (`provider`, `estimate`, `mixed`, `partial`, `unknown`, or `none` for a run without a model call). `usage.total` also has `budget_refusals`, `committed_tokens` and `provider_error` (the status, the model, the time and the cleaned message of the first provider refusal, else null) |
| `budget` | The limits and whether the run reached them: `max_tokens` (the token plan of the run), `token_ceiling_source` (`standard run`, `cost cap`, `max_tokens` or `default`), `max_tokens_setting`, `price_per_million_estimate` (the blended price of the route), `cost_cap_tokens` (what the cap buys), `gateway_token_ceiling` (null when dollars end the run, unless `max_tokens` is set), `depth_factor`, `preview`, `completion_ceilings` (the ceiling of a call of each model in this run), `wall_clock_seconds`, `max_cost_usd` (the cap of the run, also the default cap), `max_cost_usd_setting` (the setting as given: null when none, 0 for no cap), `soft_stop_usd` (85% of the cap when dollars end the run and on the agent route, else null), `refusals`, `token_ceiling_reached`, `cost_cap_reached`, `wall_clock_reached` |
| `stop`, `engine` | The stop of the engine (for example `queue-empty`, `budget-stop`), and a summary of the engine (the funnel counts and pools, or the agent turns; `engine.slices` for the slice sessions of a deeper run of the agent route) |
| `timings` | `router_seconds`, `engine_seconds`, `total_seconds` |
| `tools`, `key_variable` | The Pi and Python versions; the name (never the value) of the key variable |
| `findings`, `warnings`, `outputs` | The count by severity, the warnings, the output files |

The budget part of a run with `--depth deep` and the default model on the
funnel route:

```json
{
  "max_tokens": 100000000,
  "token_ceiling_source": "cost cap",
  "price_per_million_estimate": 0.08916,
  "cost_cap_tokens": 112157918,
  "gateway_token_ceiling": null,
  "max_tokens_setting": null,
  "depth_factor": 5.0,
  "preview": true,
  "completion_ceilings": {"deepseek/deepseek-v4.1-flash-1017": 327680},
  "wall_clock_seconds": 14400,
  "max_cost_usd": 10.0,
  "max_cost_usd_setting": 10.0,
  "soft_stop_usd": 8.5,
  "refusals": 0,
  "token_ceiling_reached": false,
  "cost_cap_reached": false,
  "wall_clock_reached": false
}
```

A standard run of the funnel with the default cap has `max_tokens` 20,000,000,
`token_ceiling_source` `standard run`, `gateway_token_ceiling` 20,000,000,
`max_cost_usd` 2.0, `max_cost_usd_setting` null and `soft_stop_usd` null.
