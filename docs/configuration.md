# Configuration

SentryTower runs without a configuration file. `sentrytower setup` writes a
settings file for you in about a minute. This page is the full reference of the settings
file, the environment variables, the commands and their options.

## Sources and order

SentryTower reads the configuration in this order. A later source overrides
an earlier one.

1. The defaults.
2. One TOML file, the first of:
   - `--config FILE`;
   - the file that `SENTRYTOWER_CONFIG` names;
   - the file of a profile, `--profile NAME` or `SENTRYTOWER_PROFILE`:
     `~/.config/sentrytower/profiles/NAME.toml`;
   - the user's settings file `~/.config/sentrytower/config.toml`, when it
     exists (`sentrytower setup` writes it).

   `$XDG_CONFIG_HOME/sentrytower` replaces `~/.config/sentrytower` when
   `XDG_CONFIG_HOME` is set.
3. The `SENTRYTOWER_*` environment variables.
4. The command-line options of `sentrytower audit`.

SentryTower never reads a configuration file from the audited repository or
from the working folder. A repository could hold a file that sends your key
to another endpoint.

`run.json` records the sources of each run (`configuration.sources`).

## The provider key

The key comes from the environment:

- `SENTRYTOWER_API_KEY`, else `OPENROUTER_API_KEY` (the default variables);
- or the variables that `provider.api_key_env` names, in order;
- else, with `provider.keychain = true`, the system keychain.

`sentrytower setup` saves a pasted key in the keychain only when you ask
for it: the macOS Keychain, or the Secret Service of Linux (`secret-tool`).
The key goes to the keychain tool on stdin, never as an argument. The entry
has the service `sentrytower` and the account `provider-key`. To remove it:

```sh
security delete-generic-password -s sentrytower -a provider-key       # macOS
secret-tool clear service sentrytower account provider-key           # Linux
```

SentryTower never prints, logs or writes the key. The key stays in the
parent process; the engines get a random credential of the local gateway
(in their variable `OPENROUTER_API_KEY`), and their environment holds no
provider key. A configuration file with a key
(`api_key`, `token`, `secret`, `password` and similar names, or a
credential header in `[provider.headers]` such as `Authorization` or
`X-Api-Key`) is an error, and so is a base URL with a user or a password.

A local endpoint without authentication can run without a key:
`provider.require_api_key = false`. The gateway then sends no authorization
header.

## Single-LLM and multi-LLM

**Single-LLM** is the default: one model runs every role. The default model
is `deepseek/deepseek-v4.1-flash-1017` (DeepSeek V4.1 Flash, the snapshot of
October 17, 2026).

```toml
[models]
default = "deepseek/deepseek-v4.1-flash-1017"
```

**Multi-LLM** gives a role its own model. Each role that the file does not
name runs the default model.

| Role | Engine | Work | Calls and tokens |
| --- | --- | --- | --- |
| `rating` | funnel | Rates unit cards when the queue is larger than the unit-check budget | A few calls with short answers |
| `unit_check` | funnel | One plain question for each code unit | The most calls (up to 1,500 in a run), each with one code unit |
| `triage` | funnel | A blind verification of each lead | One short call for each lead |
| `verify` | funnel | A blind verification of each deep-check finding | Up to 60 short calls |
| `deep_check` | funnel | An agent session on one code unit with a lead | Up to 250,000 tokens for each session; the largest pool (50% of the spendable budget) |
| `free_roaming` | funnel | An agent session on the whole repository | Its own pool of 60% of the token ceiling |
| `agent` | single agent | The agent session of a repository with more than 1,000 files | The whole token ceiling |

```toml
[models]
default = "deepseek/deepseek-v4.1-flash-1017"
unit_check = "vendor/small-model"
triage = "vendor/small-model"
deep_check = "vendor/agentic-model"
free_roaming = "vendor/agentic-model"
agent = "vendor/agentic-model"
```

`--model ID` runs one model everywhere: it clears the role overrides of the
file and of the environment. `SENTRYTOWER_MODEL` changes only the default
model; the role overrides stay.

### Guidance

- **The detection rate and the cost of a multi-LLM configuration depend on
  its models.** Compare it with the default on your own repositories before
  you rely on it.
- The agent roles (`deep_check`, `free_roaming`, `agent`) need a model that
  calls tools reliably over many turns and follows the JSON answer contract.
  A weak agent model makes sessions end without an answer.
- The short roles (`unit_check`, `triage`, `verify`, `rating`) answer with
  one JSON object. A smaller model can be enough; its judgment decides
  which units get a deep check and how the output ranks.
- Give each model a [request policy](#model-request-policies): its
  completion ceiling, its reasoning effort, its context window and its
  prices. Without a policy, a model gets the generic policy, which has no
  prices: a route with such a model runs without a cost cap, and a cap
  that you give for it is a usage error.

### The budget: dollars and tokens

The budget of a run is a cost cap in US dollars.

- **The default cap is $2**, when no setting gives a cap and each model of
  the route has prices. It is the standard depth.
- **No cap:** `--max-cost-usd 0`, `max_cost_usd = 0` in the settings file,
  or `SENTRYTOWER_MAX_COST_USD=0`. The run then has a token ceiling of
  `max_tokens`, else 20,000,000.
- **A cap needs prices.** When a model of the route has no prices (a model
  without a policy, or a local model) and no setting gives a cap, the run
  has no cap, the ceiling of `max_tokens` (else 20,000,000) and a warning.
  A cap that you give for such a route (also with `--depth`) is a usage
  error, exit code 2, before any model call. The message names the model
  and both fixes: add `input_cost_per_million` and
  `output_cost_per_million` to its `[policies."<model>"]` table, or give
  `--max-cost-usd 0`.
- **A cap must pay for one model call.** The gateway reserves the worst
  case of each call: for a small request, the completion ceiling at the
  output price. With the default model that is 65,536 tokens at $0.60 for
  one million, about $0.04. A cap (also the default cap) that is not above
  the worst case of the most expensive model of the route is a usage error,
  exit code 2, before the run; the message names the amount that is needed.
  A cap below $0.50 leaves little room for the final turns of the agent
  sessions.
- **`max_tokens` is an upper limit** of the tokens of the run
  (`--max-tokens`, `SENTRYTOWER_MAX_TOKENS`).

The engines plan their work in tokens. The funnel splits its token plan
into pools and stops new work at 90% of it; the agent runner stops its
first turn at 75% of its token budget and every turn at 95%. The plan comes
from the cap and the prices of the models of the route:

1. The tokens that the cap buys: the cap divided by the price of a token on
   the route (see below).
2. The depth factor `m`, the count of standard runs that the cap buys:
   `m = max(1, min(cap / $2, the tokens that the cap buys / 20,000,000))`,
   and at most `max_tokens / 20,000,000` when `max_tokens` is set. A cap of
   $2 or less never adds depth, whatever the model, and an expensive model
   gets depth only when the cap buys its tokens.
3. The token plan: `m` × 20,000,000 tokens when `m` is above 1; else
   20,000,000 tokens, or the tokens that the cap buys when they are fewer.
   It is never more than `max_tokens`.

With the default model, $2 buys about 22M tokens on the funnel route and
about 85M on the agent route: depth 1 on both routes. Two kinds of run
follow from the plan:

| Run | When | What ends it |
| --- | --- | --- |
| The token plan ends the run | The standard run: `m` = 1 and the cap buys at least 20,000,000 tokens (with the built-in models, the $2 default). Also a run with a `max_tokens` below what the cap buys | The pacing of the benchmarked build: the funnel starts no new work at 90% of the token plan, and the gateway refuses each call that would pass the plan. On the funnel route the cap is an upper limit only: there is no soft stop. On the agent route the soft stop at 85% of the cap applies too, so that the agent writes its answer before the cap refuses its calls |
| Dollars end the run | `m` above 1 (a deeper run), or a cap that buys fewer than 20,000,000 tokens (`--depth quick`, an expensive model) | The cap. The gateway applies no token ceiling, only `max_tokens` when you set it. At 85% of the cap no new work starts, and the running agent sessions get their final turn. The funnel grows its token plan while money is left, at the observed price of a token |

In a run that dollars end, "spent" is the committed cost of the finished
model calls. The calls in flight do not count; the last 15% of the cap is
for them and for the final turns. At 85% no new unit check, triage, deep
check, verification, focus session, sweep or slice starts, and the stop
reason of the run is `budget`. The plain log names the kind of run at the
start (`cost cap $10.00: no new work starts at 85% of it ($8.50)`, or
`cost cap $2.00, an upper limit: the token plan of the standard run
(20,000,000 tokens) ends the run`).

**The hold.** The gateway reserves the worst case of each model call: the
request size / 3 input tokens plus the completion ceiling, at the policy
prices. A call that fits under the cap (and the token ceiling) only after
the calls in flight settle waits for them, up to 600 s (10 minutes). The
hold is first in, first out: while earlier calls wait, a new call queues
behind them, so a long agent call never loses its room to later, smaller
calls. The parallel requests of the gateway take the calls in the same
order. Only a call that cannot fit with nothing in flight, or that still
does not fit after 600 s, gets the budget refusal: HTTP 402 from the local
gateway, which never goes to the provider. The engines treat it as final;
a refused unit check goes back to the queue. After a provider refusal, and
when the run ends, each waiting call is refused at once and never goes to
the provider.

The price of a token blends the input, cached-input and output prices of the
policy with a fixed token mix of the engine, set from internal runs of the
default model that this repository does not publish: in the funnel, 10% of
the tokens are output and 80% of the input comes from the cache; in the
single agent, 1% and 90% (both rounded toward a higher price). A route with more than one model takes the
highest price. The funnel route has the higher price of a token, so
`sentrytower settings` shows its plan.

`run.json` records the plan (`budget.max_tokens`), where it comes from
(`budget.token_ceiling_source`: `standard run`, `cost cap`, `max_tokens` or
`default`), the ceiling of the gateway (`budget.gateway_token_ceiling`:
null when dollars end the run, unless `max_tokens` is set), the soft stop
(`budget.soft_stop_usd`: null without a cap, and when the token plan ends a
run of the funnel), the depth factor and the preview label
([output format](output-format.md#runjson)).

### Depth: what a larger budget buys

A larger budget on the same repository gives a deeper audit. A run of depth
1 keeps the parameters of the benchmarked build. A run of depth `m` above 1 changes them:

| What | Standard | A run of `m` standard runs |
| --- | --- | --- |
| The completion ceiling of a call | the policy (DeepSeek: 65,536) | the same: the ceiling of the policy at every depth |
| Unit checks, inventory units, verifications | 1,500, 5,000, 60 | × m |
| Deep checks at the same time | 4 | × m, up to one for each CPU |
| Calls and sessions at the same time, gateway requests | 8 | × m |
| The tokens and the time of one deep check | 250,000, 900 s | × √m |
| Blind verifications of each finding | 1 | 3: the verdict is the majority, the score the mean |
| Output findings, and for each file | 6, 2 | tier 1 keeps 6 and 2; tier 2 adds up to 6 × m − 6 findings, and a file holds up to 2 × √m in both tiers (each rounded up) |
| After the queues (funnel) | none | focus sessions, then the sweep |
| Large repositories (agent route) | one session | the whole-repository session, then slice sessions |

- **Preview.** Each run of depth above 1 carries the label "preview: more
  checks; effect on findings not yet measured": in the help of `--depth`,
  the choices of the setup, the plain log at the start, the result lines,
  `report.md`, `report.html`, the result screen and the headings of tier
  2. The deeper parameters are not yet measured.
- **Two tiers.** Tier 1 is the selection of the standard run: at most 6
  findings, 2 for each file, ranked with the first verification vote; the
  findings of the focus sessions and the sweep are never in it. It is the
  same rule at every budget. Tier 2 comes after it, under the preview
  label: the further findings that the majority of their model votes
  judges "exploitable" first, then those whose verification did not run. On the
  agent route, tier 1 is the whole-repository session and the slice
  findings are tier 2. `--fail-on` counts the findings of both tiers.
- **Focus sessions.** When the unit queue and the leads are done, the
  funnel starts agent sessions on the whole repository, each with one
  weakness family: injection; authentication and authorization; files,
  paths, requests and redirects; parsers and deserialization; memory safety
  (first in a repository with C, C++ or Rust); cryptography, secrets and
  configuration; output encoding and browser security. Each has the token
  budget of the standard free-roaming session (12,000,000).
- **The sweep.** Then deep checks of the checked units without a lead, in
  queue order, with the signals of the inventory as lines of interest.
- **Slices.** On a repository of more than 1,000 files, the whole-repository
  agent session runs with the budget of a standard run. The rest buys agent
  sessions of the same size that each audit one slice: folders with about
  the same amount of source code (no tests, docs, examples, vendored,
  generated or build code). A finding of a slice that repeats an earlier
  one (the same file, within 10 lines) goes; each other finding gets three
  blind verifications and stays unless the majority verdict is "safe". A
  finding whose verification did not run stays with the label
  "unverified".
- The work stops when the budget, the wall clock or the work ends: a small
  repository can end with money left.

`--depth quick|standard|deep|max` sets a cost cap of $0.50, $2 (the
standard run), $10 or $50 (the setup offers the same) when `--max-cost-usd`
is not given. With the built-in models, quick buys fewer tokens than the
standard run, so dollars end it. Without a cap, a run has the standard plan
of 20,000,000 tokens; `--max-tokens` sets another one, and a larger one adds
depth. A `[funnel]` value of the settings stays as it is.

### Cost notes

- In the funnel, the deep checks have the largest pool (50% of the
  spendable budget) and the free-roaming session has its own pool (60% of
  the token plan). The unit checks (25%) make the most calls.
- With the default model and 20M tokens (the standard run), the funnel
  route costs up to about $1.78 at the model's list prices, an estimate from
  the prices and the token mix above; `run.json` gives the cost of each
  run. A more expensive model costs more in proportion to its prices.
- The cap is a hard limit on new calls: the gateway refuses each call whose
  worst case does not fit, after the hold. The gateway counts the cost that
  the provider reports, else the estimate at the policy prices; a model
  without prices counts only the reported cost.
- The token ceiling and the cost cap count the usage that the provider
  reports. An attempt that fails or times out without a usage report counts
  nothing, so the spend at the provider can be a little higher than
  `run.json` shows.
- `run.json` gives the spend of the run (`result.spent_usd`, null only when
  tokens were counted and no cost is known), and the tokens and the cost of
  each model (`usage.models`) and of the run (`usage.total`, with
  `cost_source`).

## Model request policies

The gateway rewrites each request with the policy of its model:

1. It removes the keys `routes`, `plugins`, `transforms`,
   `reasoning_effort`, `thinking`, `enable_thinking`,
   `thinking_token_budget`, `models`, `route`, `web_search_options` and
   `preset`, and each tool that is not a function tool.
2. It sets the completion ceiling (`max_completion_tokens`, or `max_tokens`).
3. It sets the reasoning effort (`reasoning: {"effort": ...}`), or removes
   `reasoning` when the policy has no effort.
4. It sets the OpenRouter provider route (`provider`), or removes it when
   the policy has none.

The provider route of each built-in model is an allowlist of endpoints with
`data_collection = "deny"`: OpenRouter then uses only the endpoints of the
list that do not store or train on the data. When no endpoint of the list
serves the model under this policy, OpenRouter answers HTTP 404, and the run
fails with exit code 4. A `provider` table in the settings replaces the
whole route, this field too: copy `data_collection = "deny"` into your table
to keep it. A model without a built-in policy gets no provider object
unless its table gives one.

The built-in policy of the default model:

```toml
[policies."deepseek/deepseek-v4.1-flash-1017"]
name = "DeepSeek V4.1 Flash 1017"
reasoning_effort = "medium"
max_completion_tokens = 65_536
max_output_tokens = 384_000
context_window = 1_024_000
token_field = "max_completion_tokens"
input_cost_per_million = 0.15
output_cost_per_million = 0.6
cache_read_cost_per_million = 0.003
attempt_timeout_seconds = 300
max_retries = 2
input_modalities = ["text", "image"]

[policies."deepseek/deepseek-v4.1-flash-1017".provider]
only = ["deepseek", "streamlake/fp8", "novita/fp8", "atlas-cloud/fp8", "gmicloud/fp8"]
allow_fallbacks = true
data_collection = "deny"
```

Some calls of this model reason without end. The completion ceiling of
65,536 tokens stops such a call after about 400 s, at every depth; no
complete answer of the measured runs had more than 48,607 tokens.
`max_output_tokens` (384,000, the largest output that each endpoint of the
route takes) is for the record only: it does not change the ceiling.

The built-in policy of `z-ai/glm-5.3-flash` (the default model of 1.0 and
1.1):

```toml
[policies."z-ai/glm-5.3-flash"]
name = "Z.ai GLM 5.3 Flash"
reasoning_effort = "medium"
max_completion_tokens = 131_072
context_window = 1_310_720
token_field = "max_completion_tokens"
input_cost_per_million = 0.018
output_cost_per_million = 0.14
cache_read_cost_per_million = 0.018
attempt_timeout_seconds = 240
max_retries = 2

[policies."z-ai/glm-5.3-flash".provider]
only = ["z-ai/fp8", "atlas-cloud/fp8", "streamlake/fp8", "novita/fp8", "gmicloud/fp8"]
allow_fallbacks = true
data_collection = "deny"
```

The prices are the OpenRouter list prices of October 30, 2026. A table for a
built-in model changes only the keys that it gives. A table for another
model starts from the generic policy.

| Key | Type | Generic default | Meaning |
| --- | --- | --- | --- |
| `name` | string | the model ID | The display name in the agent model catalog |
| `reasoning_effort` | `minimal`, `low`, `medium`, `high`, `xhigh`, or `none` | `none` | The reasoning effort; `none` removes the `reasoning` object |
| `max_completion_tokens` | integer | 32,768 | The completion ceiling of each request, at every depth |
| `max_output_tokens` | integer | `max_completion_tokens` | The largest output of the model on its route, for the record only (`run.json`); it does not change the completion ceiling |
| `token_field` | `max_completion_tokens` or `max_tokens` | `max_completion_tokens` | The request key of the completion ceiling |
| `context_window` | integer | 131,072 | The context window in the agent model catalog |
| `provider` | table | none | The OpenRouter provider object of each request (for example `only`, `order`, `allow_fallbacks`, `sort`, `data_collection`); it replaces the whole route of a built-in model |
| `input_cost_per_million` | number | none | US dollars for each million input tokens |
| `output_cost_per_million` | number | none | US dollars for each million output tokens |
| `cache_read_cost_per_million` | number | none | US dollars for each million cached input tokens |
| `attempt_timeout_seconds` | number | 660 | The longest wait for a byte of the endpoint in one attempt; a streamed answer can take longer as a whole |
| `max_retries` | integer | 2 | New attempts after a transient failure |
| `input_modalities` | list of strings | `["text"]` | The input modalities in the agent model catalog |

## Reference of the configuration file

All tables are optional.

```toml
[models]
default = "deepseek/deepseek-v4.1-flash-1017"   # the model of each role without an override
# rating, unit_check, triage, verify, deep_check, free_roaming, agent = "<model ID>"

[provider]
base_url = "https://openrouter.ai/api/v1"   # any OpenAI-compatible endpoint
api_key_env = ["SENTRYTOWER_API_KEY", "OPENROUTER_API_KEY"]
require_api_key = true
max_parallel_requests = 8                    # upstream attempts at the same time
keychain = false                             # true: read the key from the system keychain when the environment has none

[provider.headers]                           # the extra request headers; a table replaces these two (never authorization)
X-Title = "SentryTower"
HTTP-Referer = "https://github.com/National-Compute/sentrytower"

[budget]
wall_clock_seconds = 14_400
# max_cost_usd = 2.0                         # the cost cap of a run in US dollars (default: 2 when each model has prices; 0: no cap)
# max_tokens = 20_000_000                    # an upper limit of the tokens of a run; without a cap: the token plan

[router]
large_repo_files = 1000                      # 1,000 counted files or fewer: funnel; more: single agent

[tools]                                      # default: found on PATH
# pi = "/opt/pi/dist/bundle/cli.js"
# rg = "/usr/local/bin/rg"
# fd = "/usr/local/bin/fd"

[run]
# state_dir = "~/.cache/sentrytower"         # default: a new private temporary folder for each run (no link in the repository on its path)
# out_dir = "~/sentrytower-results"          # without --out: the results of each repository in out_dir/<repository>
# fail_on = "high"                           # exit 1 on a finding at or above: critical, high, medium, low (off: never)
# open_report = true                         # open report.html in the browser when an audit in a terminal ends

[ui]                                         # the interactive terminal; no effect on an audit
agent_name = "Juno"                          # 1 to 24 characters
agent_color = "sand"                         # cobalt, moss, coral, plum or sand
theme = "auto"                               # auto, dark or light (the background of the terminal)

[policies."<model ID>"]
# see "Model request policies"

[funnel]
# advanced: see "Funnel parameters"
```

### Funnel parameters

The `[funnel]` table changes the parameters of the funnel engine. The
defaults are the values of the benchmarked build; change them only to experiment. The most
useful parameters:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `max_findings_total` | 6 | The findings of a run |
| `extra_findings_total`, `extra_findings_per_file` | 0, 0 | The slots of tier 2 after the standard selection: first the findings that the majority of their model votes judges "exploitable", then those whose verification did not run |
| `verify_votes` | 1 | The blind model verifications of each finding (a larger budget: 3); by default the verification model is the model of the finding |
| `depth_passes`, `focus_tokens` | false, 0 | The focus sessions and the sweep after the queues, and the tokens of one focus session (a larger budget: true, 12,000,000) |
| `max_findings_per_file` | 2 | The findings of one file |
| `max_locations` | 4 | The locations of one finding |
| `max_unit_checks` | 1,500 | The unit checks of a run |
| `worker_tokens` | 250,000 | The token budget of one deep check |
| `worker_seconds` | 900 | The wall clock of one deep check |
| `max_workers` | 4 | Deep checks at the same time |
| `max_concurrency` | 8 | Model calls and agent sessions at the same time |
| `verify_max_findings` | 60 | Deep-check findings that get a verification |
| `free_token_fraction` | 0.6 | The pool of the free-roaming session (share of the token ceiling) |
| `stop_fraction` | 0.9 | The stop level (share of the token ceiling and of the wall clock) |
| `use_rating` | true | Phase 1 for a queue that does not fit |
| `share_rating`, `share_unit_check`, `share_triage`, `share_deep_check`, `share_verify`, `share_reserve` | 0.05, 0.25, 0.08, 0.50, 0.05, 0.07 | The pools (shares of the spendable budget; their sum is 1) |
| `call_temperature` | 1.0 | The temperature of the direct calls (the agent also sends 1.0) |

`src/sentrytower/funnel/pacing.py` (`Parameters`) lists each parameter with
its meaning. The router threshold is `[router] large_repo_files`, not a
funnel parameter. The router counts the files with the rule
`size-route-v2`: it leaves out dependency, cache, vendor, generated and
build folders ([architecture](architecture.md#the-router)).

## Environment variables

| Variable | Meaning |
| --- | --- |
| `SENTRYTOWER_API_KEY`, `OPENROUTER_API_KEY` | The provider key |
| `SENTRYTOWER_CONFIG` | The configuration file |
| `SENTRYTOWER_MODEL` | The default model |
| `SENTRYTOWER_MODEL_<ROLE>` | The model of a role: `RATING`, `UNIT_CHECK`, `TRIAGE`, `VERIFY`, `DEEP_CHECK`, `FREE_ROAMING`, `AGENT` |
| `SENTRYTOWER_BASE_URL` | The provider base URL |
| `SENTRYTOWER_MAX_TOKENS` | An upper limit of the tokens of a run |
| `SENTRYTOWER_WALL_CLOCK` | The wall clock of a run, in seconds |
| `SENTRYTOWER_MAX_COST_USD` | The cost cap of a run in US dollars (default: 2 when each model of the route has prices; `0`: no cap) |
| `SENTRYTOWER_PI`, `SENTRYTOWER_RG`, `SENTRYTOWER_FD` | The Pi CLI, ripgrep and fd |
| `SENTRYTOWER_STATE_DIR` | The folder of the run state (the container image uses `/home/dev`); no folder on its path in the audited repository may be a symbolic link |
| `SENTRYTOWER_PROFILE` | The profile of the settings (`profiles/NAME.toml`) |
| `SENTRYTOWER_PLAIN` | Any value: the plain lines, also in a terminal (as `--plain`) |
| `SENTRYTOWER_THEME` | `dark` or `light`: the background of the terminal (default: `COLORFGBG`, else dark) |
| `NO_COLOR` | Any value: no colour |
| `SENTRYTOWER_RECORD` | A file: the screen of the interactive terminal, one JSON line for each change (`scripts/render_demo.py` renders it) |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME` | The folders of the settings, of the last run and of the model lists |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | A proxy for the upstream requests of the gateway: an `http://` URL, optionally with a user and a password |

## Commands

| Command | What it does |
| --- | --- |
| `sentrytower` | In a terminal: the home screen (audit, set up, check the setup, the last report, settings). Else: the help |
| `sentrytower setup [--profile NAME]` | The guided setup: the agent, the models, the key, the budget, the results folder. It writes the settings file and can start an audit |
| `sentrytower audit [PATH]` | Audit a repository (a terminal asks for PATH when it is missing) |
| `sentrytower last` | The summary of the last audit that ran in a terminal, and its report |
| `sentrytower settings` | The settings in use and where they come from |
| `sentrytower doctor` | Check the tools, the key and the endpoint (`--offline`: no request) |
| `sentrytower version` | The versions of SentryTower, the engines and Pi |

`--profile NAME` before the command selects a profile for every command.

### The interactive terminal

The commands are interactive when stdin and stdout are a terminal, no CI
variable is set (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI` and others), `TERM` is
not `dumb`, and neither `--plain` nor `SENTRYTOWER_PLAIN` is set. Then an
audit shows a live view and a summary. Otherwise SentryTower prints plain
lines, as in a CI job. The pixel art of the agent needs a terminal with 256
colours or more; with fewer colours the screens show the agent's name only.

Files of the interactive terminal:

| File | Content |
| --- | --- |
| `~/.config/sentrytower/config.toml` | The settings (`sentrytower setup`); never the key |
| `~/.local/state/sentrytower/last-run.json` | The output folder, the repository name, the end time and the finding count of the last audit in a terminal; no finding text |
| `~/.cache/sentrytower/models/` | The model list of each endpoint, for one day (`sentrytower setup`, `--model` with a short name) |

## Command-line options of `sentrytower audit`

| Option | Meaning |
| --- | --- |
| `PATH` | The repository to audit (read only); a terminal asks when it is missing |
| `--out DIR` | The output folder (default `run.out_dir/<repository>` of the settings, else `./sentrytower-results`); see [the output folder](#the-output-folder) |
| `--config FILE` | A TOML configuration file |
| `--profile NAME` | The settings of a profile |
| `--model ID` | One model for every role (default `deepseek/deepseek-v4.1-flash-1017`); in a terminal a short name (`deepseek`, `glm`) is looked up in the model list |
| `--fast-model ID` | The model of the short calls of the funnel (`rating`, `unit_check`, `triage`, `verify`) |
| `--agent-model ID` | The model of the agent sessions (`deep_check`, `free_roaming`, `agent`) |
| `--plain` | The plain lines, also in a terminal |
| `--base-url URL` | An OpenAI-compatible endpoint |
| `--max-tokens N` | An upper limit of the tokens of the run (default: the token plan of the cost cap; 20,000,000 without a cap) |
| `--wall-clock SECONDS` | The wall clock of the run |
| `--max-cost-usd USD` | The cost cap of the run in US dollars: it buys the depth, and new calls stop at it (default: $2, the standard run, when each model of the route has prices; `0`: no cap). A cap for a model without prices is a usage error |
| `--depth DEPTH` | `quick`, `standard`, `deep` or `max`: a cost cap of $0.50, $2 (the standard run), $10 or $50, when `--max-cost-usd` is not given. Deep and max carry the label "preview: more checks; effect on findings not yet measured" |
| `--sarif-category NAME` | The code-scanning category of `findings.sarif` (default `sentrytower`) |
| `--sarif-path-prefix DIR` | A repository folder in front of each SARIF path, for the audit of a subfolder |
| `--format FORMATS` | `json`, `sarif`, `markdown`, `html` or `all`, comma-separated (default all); `run.json` is always written |
| `--open`, `--no-open` | Open `report.html` in the browser when the audit ends (default: in a terminal yes, unless `run.open_report = false`; in CI, over SSH and without a screen no) |
| `--fail-on SEVERITY` | Exit 1 when a finding of either tier has this severity or a higher one (a finding without a severity counts as medium); only a complete run gives exit 1 |
| `--state-dir DIR` | The folder of the run state (a folder of this user or of root; no folder on its path in the audited repository may be a symbolic link) |
| `--keep-state` | Keep the run state after a complete run |
| `-q`, `--quiet` / `-v`, `--verbose` | Warnings only / one line for each model call (no prompt or answer text) |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The run is complete, and no finding is at or above `--fail-on` |
| 1 | `--fail-on`: a complete run has a finding at or above the severity (tier 2 counts) |
| 2 | An invalid command line or configuration, also a cost cap for a model without prices, a cost cap that cannot pay for one model call, and a refused output or state folder |
| 3 | The environment is not ready (provider key, Pi CLI, ripgrep, fd), or a folder cannot be created or written |
| 4 | The run failed or is incomplete: the provider refused the key, the account or the route (HTTP 401, 402, 403 or 404), more than 20% of the model calls failed (from 10 calls on) or each call failed, the engine crashed, the agent of the agent route gave no answer, the funnel did not do its work (its inventory failed, it checked no code unit, more than 20% of its unit checks failed, or more than half of its agent sessions gave no answer), or the output of the engine cannot be read |
| 130 | Interrupted (Ctrl-C or SIGTERM) |

Each run that starts writes its outputs, also with exit code 4 or 130.
`run.json` (`result`) gives the status, the stop and the failure in plain
sentences ([output format](output-format.md#the-result)).

### The output folder

The output folder is often in the audited repository (`sentrytower audit .`
writes `./sentrytower-results`), and the repository decides what its folders
hold. So, before any model call:

- the output folder must not be a symbolic link;
- no folder on its path inside the audited repository may be a link (a link
  outside it, such as `/tmp` on macOS, is followed);
- it must belong to the user of the run (with Docker, pass
  `--user "$(id -u):$(id -g)"`);
- a link, a folder or another file that is not a regular file at the name
  of an output file (`findings.json`, `findings.sarif`, `report.md`,
  `report.html`, `run.json`) is refused.

Each refusal is exit code 2 with a plain message. Each output file is
written to a new private staging file, then renamed in one step: a link at
the final name is replaced, never followed. `sentrytower last` reads and
opens only the regular files of a folder with no link on its path. The same
link rule applies to `--state-dir` and `SENTRYTOWER_STATE_DIR`.
