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
# Git Bash on Windows: hand Windows programs C:/... paths, not /tmp/... ones.
if command -v cygpath >/dev/null 2>&1; then WORK="$(cygpath -m "$WORK")"; fi
# Windows often has `python` only (its `python3` may be the Store stub).
if ! python3 -c '' >/dev/null 2>&1; then python3() { python "$@"; }; fi
# Installed packages are read-only by design; make them writable again to clean up. A daemon an
# example started is stopped first.
trap '"$CALVE_BIN" daemon stop >/dev/null 2>&1 || true; chmod -R u+w "$WORK"; rm -rf "$WORK"' EXIT
export XDG_DATA_HOME="$WORK/data" XDG_CONFIG_HOME="$WORK/config"
# Under the test suite (which sets CALVE_TEST_GUARD), the same roots on every platform: macOS and
# Windows do not use the XDG variables, and the guard refuses their real Calve directories.
if [ -n "${CALVE_TEST_GUARD:-}" ]; then
  export CALVE_TEST_DATA_ROOT="$WORK/data/calve" CALVE_TEST_CONFIG_ROOT="$WORK/config/calve"
fi
PROJECT="$WORK/project"

# calve <args...>: JSON output, never starts a background daemon.
calve() { "$CALVE_BIN" --json --no-daemon-start --project "$PROJECT" "$@"; }

# get '<python subscript>': reads JSON on stdin, prints one field, e.g. get '["id"]'.
# --json output is the envelope {"api_version","command","data"}; get reads data.
get() { python3 -c "import json,sys; v=json.load(sys.stdin)['data']$1; print(v if isinstance(v,str) else json.dumps(v))"; }

# q '<python expression over d>': reads JSON on stdin and prints the expression, d = data.
q() { python3 -c "import json,sys; d=json.load(sys.stdin)['data']; v=$1; print(v if isinstance(v,str) else json.dumps(v))"; }

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

# kill_pid <pid>: kills a process Calve reported (a Windows PID under Git Bash, which `kill` alone
# does not take).
kill_pid() { if [ -n "${WINDIR:-}" ]; then taskkill //F //PID "$1" >/dev/null; else kill -9 "$1"; fi; }

# sha256 < file: the SHA-256 of stdin (Linux sha256sum, macOS shasum).
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }

# enable <extension-id>: enables an extension in the Project, acknowledging that its native
# component runs unconfined with your permissions.
enable() { calve extension enable "$1" --acknowledge-native >/dev/null; }

if [[ -n "${CALVE_CATALOG_ADD:-}" ]]; then
  # One argument per line (macOS ships bash 3.2, which has no mapfile).
  catalog_args=()
  while IFS= read -r arg; do catalog_args+=("$arg"); done <<<"$CALVE_CATALOG_ADD"
  "$CALVE_BIN" --json --no-daemon-start "${catalog_args[@]}" >/dev/null
fi
"$CALVE_BIN" --json --no-daemon-start init "$PROJECT" --name example >/dev/null
