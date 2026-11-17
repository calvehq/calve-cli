#!/usr/bin/env bash
# Builds a realistic demo Project through the public CLI and records every read model the
# console requests into console.json. Extensions come from the first-party signed catalog:
# set CALVE_CATALOG_ADD as for examples/lib.sh (e.g. via ~/calve-scripts/xrepo.sh). Re-run
# after read-model changes:
#   cargo build -p calve && CALVE_CATALOG_ADD=... crates/calve-console/tests/fixtures/generate.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
bin="$root/target/debug"
work="$(mktemp -d)"
trap 'chmod -R u+w "$work"; rm -rf "$work"' EXIT
export XDG_DATA_HOME="$work/d" XDG_CONFIG_HOME="$work/c"
p="$work/openaevc"
clv() { "$bin/clv" --no-daemon-start --json --project "$p" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)['data']$1)"; }
gen() { clv pack show "$1" | field '["generation"]'; }

: "${CALVE_CATALOG_ADD:?set CALVE_CATALOG_ADD to the catalog add arguments, one per line}"
mapfile -t catalog_args <<<"$CALVE_CATALOG_ADD"
"$bin/clv" --no-daemon-start --json "${catalog_args[@]}" >/dev/null
"$bin/clv" --no-daemon-start --json init "$p" --name openaevc >/dev/null
clv extension enable org.calve.software --acknowledge-native >/dev/null
clv extension enable org.calve.rust --acknowledge-native >/dev/null

http=$(clv intent create "HTTP conformance" --description "Validate OpenAEVC conformance over a remote HTTP transport." | field '["id"]')
sdk=$(clv intent create "SDK compatibility" | field '["id"]')
t_spec=$(clv task create "$http" "Write transport spec" --assignee shiv | field '["id"]')
t_runtime=$(clv task create "$http" "Runtime HTTP support" --assignee codex --priority high | field '["id"]')
t_daemon=$(clv task create "$http" "Daemon hardening" --assignee codex | field '["id"]')
t_remote=$(clv task create "$http" "Remote conformance runner" | field '["id"]')
t_sdk=$(clv task create "$sdk" "Update SDK bindings" --assignee reviewer | field '["id"]')
clv task depends-on "$t_runtime" "$t_spec" >/dev/null
clv task depends-on "$t_daemon" "$t_runtime" >/dev/null
clv task depends-on "$t_remote" "$t_runtime" >/dev/null
clv task complete "$t_spec" >/dev/null
clv task start "$t_runtime" >/dev/null
clv task block "$t_daemon" --reason "waiting for runtime HTTP support" >/dev/null
clv task start "$t_sdk" >/dev/null

mkdir -p "$p/crates/runner" "$p/schemas"
printf 'pub const DEFAULT_TIMEOUT: u64 = 10;\n\npub fn run() {}\n' > "$p/crates/runner/http.rs"
printf '{"version": 1}\n' > "$p/schemas/protocol.json"

# 1. Promoted schema update, composed into a Baseline.
schemas=$(clv pack create "Update protocol schemas" --intent "$sdk" | field '["id"]')
clv pack capture-tree "$schemas" . --generation 1 >/dev/null
g=$(gen "$schemas"); clv pack seal "$schemas" --generation "$g" >/dev/null
clv pack qualify "$schemas" --generation "$g" >/dev/null
promoted=$(clv pack promote "$schemas" --generation "$g" | field '["promoted_digest"]')
clv task link-pack "$t_sdk" "$schemas" >/dev/null
baseline=$(clv baseline create staging "$promoted" | field '["id"]')
clv baseline alias set staging "$baseline" >/dev/null
clv baseline activate staging >/dev/null

# 2. Runner change awaiting review, with a real diff against accepted content.
printf 'use std::time::Duration;\n\npub const DEFAULT_TIMEOUT: u64 = 30;\n\npub fn run() {\n    retry(3, Duration::from_secs(1));\n}\n' > "$p/crates/runner/http.rs"
printf 'mod http;\n' > "$p/crates/runner/mod.rs"
runner=$(clv pack create "Add remote conformance runner" --intent "$http" --require-review --require-snapshot-verification | field '["id"]')
clv pack capture-tree "$runner" crates --generation 1 >/dev/null
g=$(gen "$runner"); clv pack seal "$runner" --generation "$g" >/dev/null
clv pack verify "$runner" --generation "$g" >/dev/null
clv pack evaluate "$runner" --generation "$g" >/dev/null
clv task link-pack "$t_remote" "$runner" >/dev/null

# 3. Rejected daemon fix.
printf 'fn race() {}\n' > "$p/crates/runner/daemon.rs"
daemon=$(clv pack create "Fix daemon race condition" --intent "$http" --require-review | field '["id"]')
clv pack capture "$daemon" crates/runner/daemon.rs --generation 1 >/dev/null
g=$(gen "$daemon"); clv pack seal "$daemon" --generation "$g" >/dev/null
clv pack reject "$daemon" --generation "$g" --reason "missing compatibility evidence" >/dev/null
clv task link-pack "$t_daemon" "$daemon" >/dev/null

# 4. Open draft and 5. quarantined pack.
draft=$(clv pack create "Refactor verification rules" | field '["id"]')
printf 'rules\n' > "$p/rules.txt"
clv pack capture "$draft" rules.txt --generation 1 >/dev/null
quarantined=$(clv pack create "Experimental transport" | field '["id"]')
clv pack quarantine "$quarantined" --reason "security review pending" >/dev/null

# A failing harness run for the inbox and execution screens.
clv provider add shell --kind local-process --executable sh >/dev/null
cfg=$(clv config edit-path --scope project | field '["path"]')
printf 'format_version = 1\n[harnesses.lint]\nprovider = "shell"\nmode = "check"\ncommand = ["-c", "echo checking; echo \\"lint: 2 problems\\" >&2; exit 2"]\n' > "$cfg"
failing=$(clv pack create "Lint sweep" | field '["id"]')
execution=$(clv execution start "$failing" --harness lint --generation 1 | field '["execution"]')

dump() {
  local out="$here/console.json"
  python3 - "$out" <<'PY'
import json, subprocess, sys, os, time
out = sys.argv[1]
bin_ = os.environ["CALVE_BIN"]
proj = os.environ["CALVE_PROJECT"]
def clv(*args):
    r = subprocess.run([bin_, "--no-daemon-start", "--json", "--project", proj, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"{args}: {r.stderr}")
    return json.loads(r.stdout)["data"]
data = {}
def put(key, *args):
    data[key] = clv(*args)
put("status", "status")
put("overview", "view", "overview")
put("intents", "intent", "list")
put("tasks", "task", "list")
put("graph", "view", "change-graph")
put("packs", "view", "packs")
put("baselines", "baseline", "list")
put("aliases", "baseline", "alias", "list")
put("evidence", "view", "evidence")
put("events", "activity")
put("projects", "project", "list")
put("inbox", "inbox", "list")
put("doctor", "doctor")
put("extensions", "extension", "list")
put("extension-health", "extension", "health")
put("extension-catalog", "extension", "search")
put("extension-catalogs", "extension", "catalog", "list")
for pack in data["packs"]["items"]:
    pid = pack["id"]
    put(f"pack:{pid}", "view", "pack", pid)
    for f in data[f"pack:{pid}"]["files"]:
        put(f"diff:{pid}:{f['path']}", "view", "pack-diff", pid, f["path"])
for b in data["baselines"]:
    put(f"baseline:{b['id']}", "view", "baseline", b["id"])
    put(f"baseline-history:{b['id']}", "activity", "--pack", b["id"])
for t in data["tasks"]:
    put(f"task:{t['id']}", "task", "show", t["id"])
for e in data["extensions"]:
    put(f"extension-info:{e['id']}", "extension", "info", e["id"])
for p in data["projects"]:
    put(f"project-health:{p['project_id']}", "project", "health", p["project_id"])
put(f"execution:{os.environ['CALVE_EXECUTION']}", "view", "execution", os.environ["CALVE_EXECUTION"])
# Paths and machine-specific values are replaced so fixtures are portable.
text = json.dumps({"now": int(time.time()), "data": data}, indent=1, sort_keys=True)
text = text.replace(proj, "/home/dev/openaevc")
text = text.replace(os.path.expanduser("~"), "/home/dev")
open(out, "w").write(text)
print(f"wrote {len(data)} read models to {out}")
PY
}
CALVE_BIN="$bin/clv" CALVE_PROJECT="$p" CALVE_EXECUTION="$execution" dump
