#!/usr/bin/env bash
# §57 Scenario M — Unsafe Baseline materialization: uncaptured local edits stop the materialization;
# Calve explains the divergence and the choices; nothing is discarded silently. One run.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
echo "one" > "$PROJECT/a.txt"
p=$(calve pack create "One" | get '["id"]')
calve pack capture "$p" a.txt --generation 1 >/dev/null
d1=$(promote "$p")
b1=$(calve baseline create "b1" "$d1" | get '["id"]')
echo "two" > "$PROJECT/a.txt"
r=$(calve pack create "Two" | get '["id"]')
calve pack capture "$r" a.txt --generation 1 >/dev/null
d2=$(promote "$r")
b2=$(calve baseline create "b2" "$d2" | get '["id"]')
calve baseline materialize "$b2" --apply >/dev/null
# 1. The active local resource has uncaptured edits.
echo "precious local edit" > "$PROJECT/a.txt"
# 2–3. The target Baseline would overwrite it: materialization stops.
result=$(calve baseline materialize "$b1" --apply)
expect "3 blocked on the file" "$(echo "$result" | get '["blocked"][0]')" "a.txt"
expect "3 nothing applied" "$(echo "$result" | q "d.get('applied', False)")" "false"
# 4. The explanation offers capture and reconcile choices.
choices=$(echo "$result" | get '["note"]')
echo "$choices" | grep -q capture || { echo "FAILED: 4 capture choice ($choices)" >&2; exit 1; }
echo "$choices" | grep -q -- --discard || { echo "FAILED: 4 discard choice ($choices)" >&2; exit 1; }
echo "ok - 4 explains the capture and discard choices"
# 5. No data is discarded silently.
expect "5 local edit intact" "$(cat "$PROJECT/a.txt")" "precious local edit"
# The explicit choice still works, naming the file.
calve baseline materialize "$b1" --apply --discard a.txt >/dev/null
expect "explicit discard applies" "$(cat "$PROJECT/a.txt")" "one"
