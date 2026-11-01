#!/usr/bin/env bash
# Two Intents evolving concurrently with a cross-intent dependency and two local agent runs
# with separate provenance.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
a=$(calve intent create "Intent A" | get '["id"]')
d=$(calve intent create "Intent D" | get '["id"]')
ta=$(calve task create "$a" "Task A" | get '["id"]')
tb=$(calve task create "$a" "Task B" | get '["id"]')
tc=$(calve task create "$a" "Task C" | get '["id"]')
td=$(calve task create "$d" "Task D" | get '["id"]')
te=$(calve task create "$d" "Task E" | get '["id"]')
calve task depends-on "$te" "$tb" >/dev/null

calve provider add fake-agent --kind local-process --executable sh >/dev/null
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
calve config approve >/dev/null
pa=$(calve pack create "A work" --intent "$a" | get '["id"]')
pd=$(calve pack create "D work" --intent "$d" | get '["id"]')
ea=$(calve execution start "$pa" --harness write-a --generation 1 --task "$ta" | get '["execution"]')
ed=$(calve execution start "$pd" --harness write-d --generation 1 --task "$td" | get '["execution"]')
expect "separate provenance" "$([[ "$ea" != "$ed" ]] && echo distinct)" "distinct"
expect "task A linked to its execution" "$(calve task show "$ta" | get '["linked_executions"][0]')" "$ea"

graph=$(calve view change-graph | get '["edges"]')
expect "dependency visible in read model" "$(grep -c "$tb" <<<"$graph" | tr -d ' ')" "1"
expect "E waits on B" "$(calve task show "$te" | get '["blocked_by"][0]')" "$tb"
calve task complete "$tb" >/dev/null
expect "E becomes eligible" "$(calve task show "$te" | get '["blocked_by"]')" "[]"
calve task complete "$te" >/dev/null
expect "C untouched" "$(calve task show "$tc" | get '["state"]')" "OPEN"
