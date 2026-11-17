#!/usr/bin/env bash
# Independent compositions over the same promoted packs; Baselines are commitments, not
# branches, and they reuse immutable objects instead of copying them.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
declare -a P
for i in 0 1 2 3 4 5; do
  echo "content $i" > "$PROJECT/file$i.txt"
  id=$(clv pack create "P$i" | get '["id"]')
  clv pack capture "$id" "file$i.txt" --generation 1 >/dev/null
  P[$i]=$(promote "$id")
done
objects_before=$(clv maintenance verify-store | get '["objects"]')
b0=$(clv baseline create B0 "${P[0]}" "${P[1]}" "${P[3]}" | get '["id"]')
b1=$(clv baseline create B1 "${P[0]}" "${P[1]}" "${P[2]}" | get '["id"]')
b2=$(clv baseline create B2 "${P[0]}" "${P[2]}" "${P[5]}" | get '["id"]')
objects_after=$(clv maintenance verify-store | get '["objects"]')
# Each Baseline adds its own object plus a command receipt; no pack objects are copied.
expect "Baselines reuse promoted packs" "$((objects_after - objects_before))" "6"

shared=$(clv baseline compare "$b0" "$b1" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]["shared_members"]))')
expect "B0 and B1 share P0 and P1" "$shared" "2"
for b in "$b0" "$b1" "$b2"; do
  expect "baseline $b validates" "$(clv baseline validate "$b" | get '["valid"]')" "true"
done
clv baseline alias set staging "$b1" >/dev/null
clv baseline activate staging >/dev/null
expect "active pointer only" "$(clv status | get '["active_baseline"]["id"]')" "$b1"
