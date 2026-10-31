#!/usr/bin/env bash
# Run a SentryTower image against the fake model endpoint of the tests: no key, no model.
#
#   docker/smoke.sh IMAGE [REPO] [OUT]
#
# The fake endpoint (tests/smoke/fake_endpoint.py) runs on this computer, and
# the container reaches it through host.docker.internal. The container runs
# with the settings of the GitHub Action: the repository read only, a
# read-only root file system, the run state in a tmpfs, no capabilities and
# the user of this shell. The smoke passes when the audit exits with 0, its
# run is complete and it wrote each output file. REPO is the repository to
# audit (default: this repository); OUT is the output folder (default: a new
# temporary folder). SMOKE_PORT sets the port of the fake endpoint (default
# 8099), PYTHON the Python of the fake endpoint (default python3).
set -euo pipefail

image="${1:?usage: docker/smoke.sh IMAGE [REPO] [OUT]}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo="$(cd "${2:-${root}}" && pwd)"
out="${3:-$(mktemp -d)}"
port="${SMOKE_PORT:-8099}"
python="${PYTHON:-python3}"
mkdir -p "${out}"
out="$(cd "${out}" && pwd)"
log="$(mktemp)"

"${python}" "${root}/tests/smoke/fake_endpoint.py" --host 0.0.0.0 --port "${port}" 2>"${log}" &
endpoint=$!
stop_endpoint() {
  local status=$?
  kill "${endpoint}" 2>/dev/null || true
  wait "${endpoint}" 2>/dev/null || true
  rm -f "${log}"
  exit "${status}"
}
trap stop_endpoint EXIT
"${python}" - "${port}" <<'PY'
import socket
import sys
import time

for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit("smoke: the fake endpoint does not answer")
PY

code=0
docker run --rm --add-host=host.docker.internal:host-gateway -e SENTRYTOWER_API_KEY=smoke \
  --user "$(id -u):$(id -g)" --read-only \
  --tmpfs "/home/dev:rw,nosuid,nodev,size=4g,uid=$(id -u),gid=$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,size=1g \
  --cap-drop ALL --security-opt no-new-privileges \
  -v "${repo}:/workspace/repo:ro" -v "${out}:/workspace/out" \
  "${image}" audit /workspace/repo --out /workspace/out --base-url "http://host.docker.internal:${port}/v1" --wall-clock 900 \
  || code=$?
echo "smoke: the audit exited with ${code}; the fake endpoint answered $(grep -c '^call ' "${log}" || true) calls"
if [ "${code}" -ne 0 ]; then
  tail -n 5 "${log}" >&2
  exit "${code}"
fi
"${python}" - "${out}" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
missing = [name for name in ("run.json", "findings.json", "findings.sarif", "report.md", "report.html") if not (out / name).is_file()]
if missing:
    sys.exit(f"smoke: these outputs are missing: {', '.join(missing)}")
run = json.loads((out / "run.json").read_text(encoding="utf-8"))
status = (run.get("result") or {}).get("status") or run.get("status")
findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))["summary"]["findings"]
print(f"smoke: run {status} on the {run.get('route')} route, {findings} finding(s), outputs in {out}")
if status != "complete":
    sys.exit(f"smoke: the run is {status}, not complete")
PY
