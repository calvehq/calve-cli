# Shared helpers for Calve examples. Each example builds a fresh Project in a temporary
# directory, so it never touches your own Workspaces. Set CALVE to a calve binary to test a
# specific build (the integration test does); otherwise `calve` from PATH is used.
set -euo pipefail

CALVE_BIN="${CALVE:-calve}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export XDG_DATA_HOME="$WORK/data" XDG_CONFIG_HOME="$WORK/config"
PROJECT="$WORK/project"

# calve <args...>: JSON output, never starts a background daemon.
calve() { "$CALVE_BIN" --json --no-daemon-start --project "$PROJECT" "$@"; }

# get '<python subscript>': reads JSON on stdin, prints one field, e.g. get '["id"]'.
get() { python3 -c "import json,sys; v=json.load(sys.stdin)$1; print(v if isinstance(v,str) else json.dumps(v))"; }

# expect <description> <actual> <expected>
expect() {
  if [[ "$2" != "$3" ]]; then
    echo "FAILED: $1 (got '$2', expected '$3')" >&2
    exit 1
  fi
  echo "ok - $1"
}

# promote <pack-id>: seal, qualify and promote the pack at its current generation.
promote() {
  local g
  g=$(calve pack show "$1" | get '["generation"]')
  calve pack seal "$1" --generation "$g" >/dev/null
  calve pack qualify "$1" --generation "$g" >/dev/null
  calve pack promote "$1" --generation "$g" | get '["promoted_digest"]'
}

generation() { calve pack show "$1" | get '["generation"]'; }

"$CALVE_BIN" --json --no-daemon-start init "$PROJECT" --name example >/dev/null
