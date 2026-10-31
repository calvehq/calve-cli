#!/usr/bin/env bash
# §57 Scenario D — independent Baselines over promoted P0–P5: immutability, shared identity,
# compare, alias movement, and minimal reconciliation materializing B0 then B1. One run.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
declare -a P
for i in 0 1 2 3 4 5; do
  echo "content $i" > "$PROJECT/file$i.txt"
  id=$(calve pack create "P$i" | get '["id"]')
  calve pack capture "$id" "file$i.txt" --generation 1 >/dev/null
  P[$i]=$(promote "$id")
done
objects_before=$(calve maintenance verify-store | get '["objects"]')
b0=$(calve baseline create B0 "${P[0]}" "${P[1]}" "${P[3]}" | get '["id"]')
b1=$(calve baseline create B1 "${P[0]}" "${P[1]}" "${P[2]}" | get '["id"]')
b2=$(calve baseline create B2 "${P[0]}" "${P[2]}" "${P[5]}" | get '["id"]')
snapshot() { for b in "$b0" "$b1" "$b2"; do calve baseline show "$b" | q "d"; done; }
frozen=$(snapshot)

# Shared packs have one immutable identity: each Baseline adds only its own object and receipt.
expect "shared packs are not copied" "$(( $(calve maintenance verify-store | get '["objects"]') - objects_before ))" "6"
expect "B0 and B2 hold the same P0 object" \
  "$(calve baseline show "$b0" | q "'${P[0]}' in json.dumps(d)")$(calve baseline show "$b2" | q "'${P[0]}' in json.dumps(d)")" "truetrue"

# Compare is correct, by members and by resources.
cmp=$(calve baseline compare "$b0" "$b1")
expect "shared P0 P1" "$(echo "$cmp" | q "sorted(d['shared_members'])")" "$(python3 -c "import json; print(json.dumps(sorted(['${P[0]}','${P[1]}'])))")"
expect "only in B0: P3" "$(echo "$cmp" | q "d['only_left_members']")" "[\"${P[3]}\"]"
expect "only in B1: P2" "$(echo "$cmp" | q "d['only_right_members']")" "[\"${P[2]}\"]"
expect "resources differ by file2/file3" \
  "$(echo "$cmp" | q "[[x['path'] for x in d['resources']['only_left']], [x['path'] for x in d['resources']['only_right']], d['resources']['same']]")" \
  '[["file3.txt"], ["file2.txt"], 2]'

# Alias movement does not mutate Baselines.
calve baseline alias set staging "$b0" >/dev/null
calve baseline alias set staging "$b1" >/dev/null
calve baseline activate staging >/dev/null
expect "active pointer only" "$(calve status | get '["active_baseline"]["id"]')" "$b1"
expect "Baselines unchanged by aliases" "$(snapshot)" "$frozen"

# Materialize B0, then B1: only file2 (create) and file3 (delete) are touched.
calve baseline materialize "$b0" --apply >/dev/null
ino() { stat -c %i "$PROJECT/$1"; }
i0=$(ino file0.txt); i1=$(ino file1.txt)
step=$(calve baseline materialize "$b1" --apply)
expect "B1 plan touches only file2 and file3" \
  "$(echo "$step" | q "sorted((s['path'], s['action']) for s in d['plan'] if s['action'] != 'unchanged')")" \
  '[["file2.txt", "create"], ["file3.txt", "delete"]]'
expect "shared files untouched (same inodes)" "$(ino file0.txt) $(ino file1.txt)" "$i0 $i1"
expect "B1 materialized" "$(ls "$PROJECT" | tr '\n' ' ')" "file0.txt file1.txt file2.txt "
for b in "$b0" "$b1" "$b2"; do
  expect "baseline $b validates" "$(calve baseline validate "$b" | get '["valid"]')" "true"
done
expect "Baselines immutable throughout" "$(snapshot)" "$frozen"
