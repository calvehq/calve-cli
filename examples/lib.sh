# Shared helpers for Calve examples. Each example builds a fresh Project in a temporary
# directory, so it never touches your own Workspaces. Set CALVE to a calve binary to test a
# specific build (the integration test does); otherwise `calve` from PATH is used.
#
# Extensions come from a signed catalog: set CALVE_CATALOG_ADD to the arguments of
# `calve extension catalog add` (one per line) for a catalog providing them, e.g. the first-party
# calve-extensions catalog. CALVE_FILES_EXT names the file-domain extension the generic examples
# enable (default org.calve.software); the integration test uses the fixture `org.example.toy`.
set -euo pipefail

CALVE_BIN="${CALVE:-calve}"
WORK="$(mktemp -d)"
# Installed packages are read-only by design; make them writable again to clean up.
trap 'chmod -R u+w "$WORK"; rm -rf "$WORK"' EXIT
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

FILES_EXT="${CALVE_FILES_EXT:-org.calve.software}"

# enable <extension-id>: enables an extension in the Project, acknowledging that its native
# component runs unconfined with your permissions.
enable() { calve extension enable "$1" --acknowledge-native >/dev/null; }

if [[ -n "${CALVE_CATALOG_ADD:-}" ]]; then
  mapfile -t catalog_args <<<"$CALVE_CATALOG_ADD"
  "$CALVE_BIN" --json --no-daemon-start "${catalog_args[@]}" >/dev/null
fi
"$CALVE_BIN" --json --no-daemon-start init "$PROJECT" --name example >/dev/null
