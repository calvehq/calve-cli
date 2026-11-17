#!/usr/bin/env bash
# Two Intents evolving concurrently with a cross-intent dependency and two local agent runs
# with separate provenance.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
a=$(clv intent create "Intent A" | get '["id"]')
d=$(clv intent create "Intent D" | get '["id"]')
ta=$(clv task create "$a" "Task A" | get '["id"]')
tb=$(clv task create "$a" "Task B" | get '["id"]')
tc=$(clv task create "$a" "Task C" | get '["id"]')
td=$(clv task create "$d" "Task D" | get '["id"]')
te=$(clv task create "$d" "Task E" | get '["id"]')
clv task depends-on "$te" "$tb" >/dev/null

clv provider add fake-agent --kind local-process --executable sh >/dev/null
cfg=$(clv config edit-path --scope project | get '["path"]')
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
clv config approve >/dev/null
pa=$(clv pack create "A work" --intent "$a" | get '["id"]')
pd=$(clv pack create "D work" --intent "$d" | get '["id"]')
ea=$(clv execution start "$pa" --harness write-a --generation 1 --task "$ta" | get '["execution"]')
ed=$(clv execution start "$pd" --harness write-d --generation 1 --task "$td" | get '["execution"]')
expect "separate provenance" "$([[ "$ea" != "$ed" ]] && echo distinct)" "distinct"
expect "task A linked to its execution" "$(clv task show "$ta" | get '["linked_executions"][0]')" "$ea"

graph=$(clv view change-graph | get '["edges"]')
expect "dependency visible in read model" "$(grep -c "$tb" <<<"$graph" | tr -d ' ')" "1"
expect "E waits on B" "$(clv task show "$te" | get '["blocked_by"][0]')" "$tb"
clv task complete "$tb" >/dev/null
expect "E becomes eligible" "$(clv task show "$te" | get '["blocked_by"]')" "[]"
clv task complete "$te" >/dev/null
expect "C untouched" "$(clv task show "$tc" | get '["state"]')" "OPEN"
