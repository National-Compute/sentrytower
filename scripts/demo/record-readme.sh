#!/usr/bin/env bash
# Record the demo of the README: a real `sentrytower setup` and a real audit of DVWA, then render it.
#
#   SENTRYTOWER_API_KEY=<OpenRouter key> scripts/demo/record-readme.sh
#
# 1. Check that the program is the SentryTower version of this checkout, and
#    that `sentrytower doctor --offline` finds the pinned tools (Pi 1.5.0,
#    ripgrep 15.2.0, fd 10.5.0) without a warning: the recording shows them.
#    Clone DVWA (Damn Vulnerable Web Application, a PHP application that is
#    vulnerable on purpose) at a pinned commit into a new temporary home folder.
# 2. Run `sentrytower setup` in a pseudo-terminal in that home folder. The
#    answers of scripts/demo/readme.json go in as key presses: the default
#    agent, OpenRouter, the key of the environment, one model (the default,
#    DeepSeek V4.1 Flash), the standard depth ($2, the measured run), 4 hours,
#    the default results folder, then "Audit this folder". The program records
#    its screen (SENTRYTOWER_RECORD).
# 3. Render the recording: docs/assets/demo.svg (animated; the audit plays
#    faster). Then run `sentrytower last` in the same home folder and render
#    its screen as docs/assets/demo-results.svg (the results of the audit).
#
# The key reaches the program only through the environment. It is never an
# argument, never printed and never written to a file: the setup uses a key of
# the environment and saves nothing of it. Your own settings, keychain, state
# and results do not change. Cost: one audit with the default model, within
# the cost cap of the standard depth ($2).
#
# DEMO_OUT keeps the recording, the results of the audit and a file
# "status" with the exit code (default: the temporary folder). DEMO_SCRIPT
# and DEMO_ASSETS replace the key presses and the folder of the images. The
# tools come from PATH, or from SENTRYTOWER_PI, SENTRYTOWER_RG and
# SENTRYTOWER_FD.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
REPOSITORY=${DEMO_REPOSITORY:-https://github.com/digininja/DVWA}
COMMIT=${DEMO_COMMIT:-a1978a2fed195acd093010af6395f86a281537ca}
NAME=${DEMO_NAME:-DVWA}
WIDTH=${DEMO_COLUMNS:-100}
HEIGHT=${DEMO_ROWS:-34}
SCRIPT=${DEMO_SCRIPT:-$ROOT/scripts/demo/readme.json}
ASSETS=${DEMO_ASSETS:-$ROOT/docs/assets}

if [ -z "${SENTRYTOWER_API_KEY:-}${OPENROUTER_API_KEY:-}" ]; then
  echo "record-readme: put the OpenRouter key in SENTRYTOWER_API_KEY first" >&2
  exit 2
fi
program="$ROOT/.venv/bin/sentrytower"
if [ ! -x "$program" ]; then
  program=$(command -v sentrytower || true)
fi
if [ -z "$program" ]; then
  echo "record-readme: install SentryTower first (make install)" >&2
  exit 2
fi
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/pyproject.toml" | head -1)
if [ "$("$program" --version)" != "sentrytower $version" ]; then
  echo "record-readme: $program is not SentryTower $version; install this checkout first (make install)" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/sentrytower-demo.XXXXXX")
out=${DEMO_OUT:-$work}
mkdir -p "$out"
rm -f "$out/status"
trap 'echo "$?" > "$out/status"' EXIT
home="$work/home"
mkdir -p "$home/code"
# The pinned tools, with no warning of doctor in the home folder of the recording (no request: --offline).
if ! HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_STATE_HOME="$home/.local/state" XDG_CACHE_HOME="$home/.cache" \
    PATH="$(dirname "$program"):$PATH" "$program" doctor --offline --json \
    | python3 -c 'import json, sys; sys.exit(any(check["status"] in ("warn", "fail") for check in json.load(sys.stdin)["checks"]))'; then
  echo "record-readme: sentrytower doctor --offline reports a missing tool or a version other than the pins; fix it first" >&2
  exit 2
fi
echo "record-readme: cloning $REPOSITORY at ${COMMIT:0:12}"
git clone --quiet "$REPOSITORY" "$home/code/$NAME"
git -C "$home/code/$NAME" checkout --quiet "$COMMIT"
rm -rf "$home/code/$NAME/.git"

recording="$out/readme.jsonl"
echo "record-readme: recording the setup and the audit (about 30 to 50 minutes)"
(
  cd "$home/code/$NAME"
  HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_STATE_HOME="$home/.local/state" XDG_CACHE_HOME="$home/.cache" \
    PATH="$(dirname "$program"):$PATH" \
    python3 "$ROOT/scripts/record_demo.py" "$SCRIPT" "$recording" \
    --columns "$WIDTH" --rows "$HEIGHT" -- sentrytower setup
)
if [ -d "$home/sentrytower-results/$NAME" ]; then
  rm -rf "$out/results" && cp -R "$home/sentrytower-results/$NAME" "$out/results"
fi

python3 "$ROOT/scripts/render_demo.py" "$recording" --svg "$ASSETS/demo.svg" \
  --prompt "~/code/$NAME \$ sentrytower setup" --squeeze "is auditing:issues in|issue in|stopped early|could not finish:24" \
  --max-gap 1.6 --hold 8 --title "sentrytower setup"

# The results: `sentrytower last` shows the outputs of the audit again (no model call, no key).
echo '[{"expect": "Open the report?", "after": 1.0}, {"keys": ["down", "enter"]}]' > "$work/last.json"
(
  cd "$home/code/$NAME"
  env -u SENTRYTOWER_API_KEY -u OPENROUTER_API_KEY \
    HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_STATE_HOME="$home/.local/state" XDG_CACHE_HOME="$home/.cache" \
    PATH="$(dirname "$program"):$PATH" \
    python3 "$ROOT/scripts/record_demo.py" "$work/last.json" "$out/last.jsonl" --columns "$WIDTH" --rows "$HEIGHT" -- sentrytower last
)
python3 "$ROOT/scripts/render_demo.py" "$out/last.jsonl" --still "$ASSETS/demo-results.svg" --still-after "" --title "sentrytower last"
echo "record-readme: done. Recording: $recording"
