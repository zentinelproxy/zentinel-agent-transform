#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary> [harness args...]]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request. Extra
# arguments go to the harness (e.g. `--transport grpc`).
#
# With scripts/smoke/rules.yaml loaded:
#   * the v2 handshake works and an ordinary request is forwarded (200) with
#     the header the catch-all rule sets;
#   * a request under /api/ matches the api rule instead: the upstream gets
#     X-Transform-Rule: api, not the catch-all header, and the client's
#     X-Internal-Debug header is removed;
#   * with the agent stopped the ordinary request is refused.

set -euo pipefail

if [ $# -ge 2 ]; then AGENT_BIN=$1 ZENTINEL_BIN=$2; shift 2; fi
AGENT_BIN=${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
ZENTINEL_BIN=${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}
RULES="$(cd "$(dirname "$0")" && pwd)/smoke/rules.yaml"

python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name transform \
    --agent-arg=--config --agent-arg "$RULES" \
    --clean '{"name": "ordinary request", "path": "/smoke", "upstream_headers": {"X-Transform-Smoke": "1"}, "upstream_lacks_headers": ["X-Transform-Rule"]}' \
    --case '{"name": "/api rule applied", "path": "/api/v1/users", "headers": {"X-Internal-Debug": "secret"}, "expect": 200, "upstream_headers": {"X-Transform-Rule": "api"}, "upstream_lacks_headers": ["X-Internal-Debug", "X-Transform-Smoke"]}' \
    --case '{"name": "/public gets the catch-all rule", "path": "/public/index.html", "headers": {"X-Internal-Debug": "kept"}, "expect": 200, "upstream_headers": {"X-Transform-Smoke": "1", "X-Internal-Debug": "kept"}}' \
    "$@"
