#!/usr/bin/env bash
# §57 Scenario E — revision: R1 amends promoted P1 without editing it; B0 (without R1) stays as it
# was; B1 includes the revision relation; compare and materialize each. One run.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
# 1. Promote P1.
echo "v1" > "$PROJECT/config.txt"
p1=$(calve pack create "P1" | get '["id"]')
calve pack capture "$p1" config.txt --generation 1 >/dev/null
p1_digest=$(promote "$p1")
# 2. B0 includes P1.
b0=$(calve baseline create "B0" "$p1_digest" | get '["id"]')
b0_record=$(calve baseline show "$b0" | q "d")
# 3. RevisionPack R1 amends P1, promoted.
echo "v2" > "$PROJECT/config.txt"
r1=$(calve revision create "R1 amend config" --of "$p1_digest" --relation amends | get '["id"]')
calve revision capture "$r1" config.txt --generation 1 >/dev/null
r1_digest=$(promote "$r1")
expect "3 P1 is unchanged" "$(calve pack show "$p1" | get '["state"]')" "PROMOTED"
# 4. B1 includes the revision relation.
b1=$(calve baseline create "B1" "$p1_digest" "$r1_digest" | get '["id"]')
expect "4 B1 validates" "$(calve baseline validate "$b1" | get '["valid"]')" "true"
# 5. B0 is unchanged.
expect "5 B0 unchanged" "$(calve baseline show "$b0" | q "d")" "$b0_record"
expect "5 B0 validates" "$(calve baseline validate "$b0" | get '["valid"]')" "true"
# 6. Compare B0/B1: R1 only in B1, with its amends relation; config.txt differs.
cmp=$(calve baseline compare "$b0" "$b1")
expect "6 R1 only in B1" "$(echo "$cmp" | q "d['only_right_members']")" "[\"$r1_digest\"]"
expect "6 revision relation in B1" \
  "$(echo "$cmp" | q "any('amends' in json.dumps(r).lower() for r in d['revisions']['right'])")" "true"
expect "6 config.txt differs" "$(echo "$cmp" | q "[x['path'] for x in d['resources']['different']]")" '["config.txt"]'
# 7. Materialize each: distinct accepted state.
calve baseline materialize "$b0" --apply --discard config.txt >/dev/null
expect "7 B0 accepted state" "$(cat "$PROJECT/config.txt")" "v1"
calve baseline materialize "$b1" --apply >/dev/null
expect "7 B1 accepted state" "$(cat "$PROJECT/config.txt")" "v2"
calve baseline materialize "$b0" --apply >/dev/null
expect "7 back to B0" "$(cat "$PROJECT/config.txt")" "v1"
