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
# 4. Two local fake-agent executions on independent Tasks, running at the same time. Each worker
# finishes only after it has seen the other one running, so a run that held the Project for
# itself would time out and fail.
marks=$(mktemp -d "${TMPDIR:-/tmp}/calve-f.XXXXXX")
"$CALVE_BIN" --json --no-daemon-start provider add fake-agent --kind local-process --executable sh --env TMPDIR >/dev/null
cfg=$(calve config edit-path --scope project | get '["path"]')
worker() {
  printf 'mkdir -p %s; echo \\"from $CALVE_TASK\\" > %s/out.txt; touch %s/%s; n=0; until test -e %s/%s; do n=$((n+1)); test $n -lt 300 || exit 1; sleep 0.1; done' \
    "$1" "$1" "$marks" "$1" "$marks" "$2"
}
cat > "$cfg" <<TOML
format_version = 1
[harnesses.write-a]
provider = "fake-agent"
mode = "change"
paths = ["a"]
command = ["-c", "$(worker a d)"]
[harnesses.write-d]
provider = "fake-agent"
mode = "change"
paths = ["d"]
command = ["-c", "$(worker d a)"]
TOML
calve config approve >/dev/null
pa=$(calve pack create "A work" --intent "$a" | get '["id"]')
pd=$(calve pack create "D work" --intent "$d" | get '["id"]')
"$CALVE_BIN" --json daemon start >/dev/null
calve execution start "$pa" --harness write-a --generation 1 --task "$ta" > "$WORK/ea.json" & first=$!
calve execution start "$pd" --harness write-d --generation 1 --task "$td" > "$WORK/ed.json" & second=$!
wait "$first"; wait "$second"
expect "4 A ran alongside D" "$(get '["state"]' < "$WORK/ea.json")" "SUCCEEDED"
expect "4 D ran alongside A" "$(get '["state"]' < "$WORK/ed.json")" "SUCCEEDED"
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
