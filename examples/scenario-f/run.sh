#!/usr/bin/env bash
# §57 Scenario F — Parallel agent work: two Intents, a cross-Intent dependency, two local fake
# agents on independent Tasks, the console showing the dependency, completion making E eligible,
# separate provenance. One run; the console engine reads a real daemon.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
# 1–2. Intent A with Tasks A/B/C, Intent D with Tasks D/E.
a=$(calve intent create "Intent A" | get '["id"]')
d=$(calve intent create "Intent D" | get '["id"]')
ta=$(calve task create "$a" "Task A" | get '["id"]')
tb=$(calve task create "$a" "Task B" | get '["id"]')
calve task create "$a" "Task C" >/dev/null
td=$(calve task create "$d" "Task D" | get '["id"]')
te=$(calve task create "$d" "Task E" | get '["id"]')
# 3. E depends on B.
calve task depends-on "$te" "$tb" >/dev/null
# 4. Two local fake-agent executions on independent Tasks, running at the same time.
"$CALVE_BIN" --json --no-daemon-start provider add fake-agent --kind local-process --executable sh >/dev/null
cfg=$(calve config edit-path --scope project | get '["path"]')
cat > "$cfg" <<'TOML'
format_version = 1
[harnesses.write-a]
provider = "fake-agent"
mode = "change"
paths = ["a"]
command = ["-c", "mkdir -p a && echo \"from $CALVE_TASK\" > a/out.txt"]
[harnesses.write-d]
provider = "fake-agent"
mode = "change"
paths = ["d"]
command = ["-c", "mkdir -p d && echo \"from $CALVE_TASK\" > d/out.txt"]
TOML
pa=$(calve pack create "A work" --intent "$a" | get '["id"]')
pd=$(calve pack create "D work" --intent "$d" | get '["id"]')
"$CALVE_BIN" --json daemon start >/dev/null
# Started together; writes to one Project are serialized, so the one that finds the Project
# locked gets the retryable PROJECT_LOCKED and retries, as the error says.
start() {
  for _ in $(seq 1 100); do
    if calve execution start "$1" --harness "$2" --generation 1 --task "$3" > "$4" 2> "$4.err"; then return 0; fi
    grep -q PROJECT_LOCKED "$4.err" || { cat "$4.err" >&2; return 1; }
    sleep 0.2
  done
  return 1
}
start "$pa" write-a "$ta" "$WORK/ea.json" & first=$!
start "$pd" write-d "$td" "$WORK/ed.json" & second=$!
wait "$first"; wait "$second"
ea=$(get '["execution"]' < "$WORK/ea.json")
ed=$(get '["execution"]' < "$WORK/ed.json")
# 5. Dependency-aware UI: the console, over the daemon, shows E waiting on B.
# 6–7 happen inside it: B completes through the CLI, and E becomes eligible on refresh.
export CALVE_E2E_PROJECT="$PROJECT" CALVE_BIN CALVE_E2E_BLOCKED="$te" CALVE_E2E_BLOCKER="$tb"
(cd "$(dirname "$0")/../.." && cargo test -q --locked -p calve-console --test reconnect_e2e scenario_f_dependency_ui -- --ignored)
expect "7 E eligible" "$(calve task show "$te" | get '["blocked_by"]')" "[]"
# 8. Separate provenance.
expect "8 distinct executions" "$([[ "$ea" != "$ed" ]] && echo distinct)" "distinct"
expect "8 A's task links A's execution" "$(calve task show "$ta" | get '["linked_executions"][0]')" "$ea"
expect "8 D's task links D's execution" "$(calve task show "$td" | get '["linked_executions"][0]')" "$ed"
expect "8 A's content" "$(cat "$PROJECT/a/out.txt")" "from $ta"
expect "8 D's content" "$(cat "$PROJECT/d/out.txt")" "from $td"
"$CALVE_BIN" --json daemon stop >/dev/null
