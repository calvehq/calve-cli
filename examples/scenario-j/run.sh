#!/usr/bin/env bash
# §57 Scenario J — Copied Project: identity conflict detected, writes in the ambiguous copy blocked,
# adopt-copy creates a new identity, accepted state transfers, active executions are not live.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
echo "accepted" > "$PROJECT/a.txt"
p=$(calve pack create "Accepted" | get '["id"]')
calve pack capture "$p" a.txt --generation 1 >/dev/null
digest=$(promote "$p")
b=$(calve baseline create "b" "$digest" | get '["id"]')
pid=$(calve status | get '["project"]["project_id"]')
nid=$(calve status | get '["project"]["namespace_id"]')
# An execution left active: its daemon is killed mid-run, so OpenAEVC still holds it RUNNING.
"$CALVE_BIN" --json --no-daemon-start provider add shell --kind local-process --executable sh >/dev/null
cfg=$(calve config edit-path --scope project | get '["path"]')
printf 'format_version = 1\n[harnesses.slow]\nprovider = "shell"\nmode = "check"\ncommand = ["-c", "sleep 30"]\n' > "$cfg"
active=$(calve pack create "Active" | get '["id"]')
daemon=$("$CALVE_BIN" --json daemon start | q "d['pid']")
calve execution start "$active" --harness slow --generation 1 >/dev/null 2>&1 &
runner=$!
for _ in $(seq 1 150); do
  state=$(calve execution list --pack "$active" | q "[e['state'] for e in d]")
  [[ "$state" == *RUNNING* ]] && break
  sleep 0.2
done
expect "an execution is active in the original" "$(echo "$state" | grep -c RUNNING)" "1"
kill -9 "$daemon"
wait "$runner" 2>/dev/null || true
# 1. Copy the Project directory.
COPY="$WORK/copy"
cp -r "$PROJECT" "$COPY"
c() { "$CALVE_BIN" --json --no-daemon-start --project "$COPY" "$@"; }
# 2–3. Registering both paths: the identity conflict is detected.
reg=$("$CALVE_BIN" --json --no-daemon-start project register "$COPY" 2>&1 || true)
echo "$reg" | grep -qi 'conflict\|already\|copy' || { echo "FAILED: 3 conflict not reported: $reg" >&2; exit 1; }
echo "ok - 3 identity conflict detected"
# 4. Writes in the ambiguous copy are blocked.
w=$(c pack create "ambiguous" 2>&1 || true)
echo "$w" | grep -qi 'conflict\|identity\|adopt' || { echo "FAILED: 4 write not blocked: $w" >&2; exit 1; }
echo "ok - 4 writes in the copy blocked"
# 5–6. adopt-copy creates a new ProjectId and Namespace.
adopted=$("$CALVE_BIN" --json --no-daemon-start project adopt-copy "$COPY" --name adopted)
expect "6 new ProjectId" "$(test "$(c status | get '["project"]["project_id"]')" != "$pid" && echo yes)" "yes"
expect "6 new Namespace" "$(test "$(c status | get '["project"]["namespace_id"]')" != "$nid" && echo yes)" "yes"
# 7. Reachable immutable accepted state transferred.
expect "7 store verifies" "$(c maintenance verify-store | get '["ok"]')" "true"
# Imported objects are inert history by protocol design: they verify, but join no new Baseline.
expect "7 accepted objects transferred" "$(echo "$adopted" | q "d['transferred_objects'] > 1")" "true"
# 8. Active executions are not cloned as live.
expect "8 no live execution in the copy" "$(c execution list | q "[e['state'] for e in d if e['state'] in ('RUNNING','STARTING','ADMITTED','PENDING')]")" "[]"
# The original is untouched and writable.
expect "original keeps its identity" "$(calve status | get '["project"]["project_id"]')" "$pid"
calve intent create "still writable" >/dev/null
