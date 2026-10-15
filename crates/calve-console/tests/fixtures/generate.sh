#!/usr/bin/env bash
# Builds a realistic demo Project through the public CLI and records every read model the
# console requests into console.json. Re-run after read-model changes:
#   cargo build --workspace && crates/calve-console/tests/fixtures/generate.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
bin="$root/target/debug"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export XDG_DATA_HOME="$work/d" XDG_CONFIG_HOME="$work/c"
p="$work/openaevc"
calve() { "$bin/calve" --no-daemon-start --json --project "$p" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
gen() { calve pack show "$1" | field '["generation"]'; }

"$bin/calve" --no-daemon-start --json init "$p" --name openaevc >/dev/null
calve extension enable >/dev/null
calve extension enable org.langs.rust >/dev/null

http=$(calve intent create "HTTP conformance" --description "Validate OpenAEVC conformance over a remote HTTP transport." | field '["id"]')
sdk=$(calve intent create "SDK compatibility" | field '["id"]')
t_spec=$(calve task create "$http" "Write transport spec" --assignee shiv | field '["id"]')
t_runtime=$(calve task create "$http" "Runtime HTTP support" --assignee codex --priority high | field '["id"]')
t_daemon=$(calve task create "$http" "Daemon hardening" --assignee codex | field '["id"]')
t_remote=$(calve task create "$http" "Remote conformance runner" | field '["id"]')
t_sdk=$(calve task create "$sdk" "Update SDK bindings" --assignee reviewer | field '["id"]')
calve task depends-on "$t_runtime" "$t_spec" >/dev/null
calve task depends-on "$t_daemon" "$t_runtime" >/dev/null
calve task depends-on "$t_remote" "$t_runtime" >/dev/null
calve task complete "$t_spec" >/dev/null
calve task start "$t_runtime" >/dev/null
calve task block "$t_daemon" --reason "waiting for runtime HTTP support" >/dev/null
calve task start "$t_sdk" >/dev/null

mkdir -p "$p/crates/runner" "$p/schemas"
printf 'pub const DEFAULT_TIMEOUT: u64 = 10;\n\npub fn run() {}\n' > "$p/crates/runner/http.rs"
printf '{"version": 1}\n' > "$p/schemas/protocol.json"

# 1. Promoted schema update, composed into a Baseline.
schemas=$(calve pack create "Update protocol schemas" --intent "$sdk" | field '["id"]')
calve pack capture-tree "$schemas" . --generation 1 >/dev/null
g=$(gen "$schemas"); calve pack seal "$schemas" --generation "$g" >/dev/null
calve pack qualify "$schemas" --generation "$g" >/dev/null
promoted=$(calve pack promote "$schemas" --generation "$g" | field '["promoted_digest"]')
calve task link-pack "$t_sdk" "$schemas" >/dev/null
baseline=$(calve baseline create staging "$promoted" | field '["id"]')
calve baseline alias set staging "$baseline" >/dev/null
calve baseline activate staging >/dev/null

# 2. Runner change awaiting review, with a real diff against accepted content.
printf 'use std::time::Duration;\n\npub const DEFAULT_TIMEOUT: u64 = 30;\n\npub fn run() {\n    retry(3, Duration::from_secs(1));\n}\n' > "$p/crates/runner/http.rs"
printf 'mod http;\n' > "$p/crates/runner/mod.rs"
runner=$(calve pack create "Add remote conformance runner" --intent "$http" --require-review --require-snapshot-verification | field '["id"]')
calve pack capture-tree "$runner" crates --generation 1 >/dev/null
g=$(gen "$runner"); calve pack seal "$runner" --generation "$g" >/dev/null
calve pack verify "$runner" --generation "$g" >/dev/null
calve pack evaluate "$runner" --generation "$g" >/dev/null
calve task link-pack "$t_remote" "$runner" >/dev/null

# 3. Rejected daemon fix.
printf 'fn race() {}\n' > "$p/crates/runner/daemon.rs"
daemon=$(calve pack create "Fix daemon race condition" --intent "$http" --require-review | field '["id"]')
calve pack capture "$daemon" crates/runner/daemon.rs --generation 1 >/dev/null
g=$(gen "$daemon"); calve pack seal "$daemon" --generation "$g" >/dev/null
calve pack reject "$daemon" --generation "$g" --reason "missing compatibility evidence" >/dev/null
calve task link-pack "$t_daemon" "$daemon" >/dev/null

# 4. Open draft and 5. quarantined pack.
draft=$(calve pack create "Refactor verification rules" | field '["id"]')
printf 'rules\n' > "$p/rules.txt"
calve pack capture "$draft" rules.txt --generation 1 >/dev/null
quarantined=$(calve pack create "Experimental transport" | field '["id"]')
calve pack quarantine "$quarantined" --reason "security review pending" >/dev/null

# A failing harness run for the inbox and execution screens.
calve provider add shell --kind local-process --executable sh >/dev/null
cfg=$(calve config edit-path --scope project | field '["path"]')
printf 'format_version = 1\n[harnesses.lint]\nprovider = "shell"\nmode = "check"\ncommand = ["-c", "echo checking; echo \\"lint: 2 problems\\" >&2; exit 2"]\n' > "$cfg"
failing=$(calve pack create "Lint sweep" | field '["id"]')
execution=$(calve execution start "$failing" --harness lint --generation 1 | field '["execution"]')

dump() {
  local out="$here/console.json"
  python3 - "$out" <<'PY'
import json, subprocess, sys, os, time
out = sys.argv[1]
bin_ = os.environ["CALVE_BIN"]
proj = os.environ["CALVE_PROJECT"]
def calve(*args):
    r = subprocess.run([bin_, "--no-daemon-start", "--json", "--project", proj, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"{args}: {r.stderr}")
    return json.loads(r.stdout)
data = {}
def put(key, *args):
    data[key] = calve(*args)
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
for pack in data["packs"]:
    pid = pack["id"]
    put(f"pack:{pid}", "view", "pack", pid)
    for f in data[f"pack:{pid}"]["files"]:
        put(f"diff:{pid}:{f['path']}", "view", "pack-diff", pid, f["path"])
for b in data["baselines"]:
    put(f"baseline:{b['id']}", "view", "baseline", b["id"])
    put(f"baseline-history:{b['id']}", "activity", "--pack", b["id"])
for t in data["tasks"]:
    put(f"task:{t['id']}", "task", "show", t["id"])
for p in data["projects"]:
    put(f"project-health:{p['project_id']}", "project", "health", p["project_id"])
put(f"execution:{os.environ['CALVE_EXECUTION']}", "view", "execution", os.environ["CALVE_EXECUTION"])
# Paths and machine-specific values are replaced so fixtures are portable.
text = json.dumps({"now": int(time.time()), "data": data}, indent=1, sort_keys=True)
text = text.replace(proj, "/home/dev/openaevc")
open(out, "w").write(text)
print(f"wrote {len(data)} read models to {out}")
PY
}
CALVE_BIN="$bin/calve" CALVE_PROJECT="$p" CALVE_EXECUTION="$execution" dump
