#!/usr/bin/env bash
# Accepted history is immutable: a RevisionPack amends P1 without editing it, and Baselines
# choose whether to include the revision.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
echo "v1" > "$PROJECT/config.txt"
p1=$(calve pack create "P1" | get '["id"]')
calve pack capture "$p1" config.txt --generation 1 >/dev/null
p1_digest=$(promote "$p1")

echo "v2" > "$PROJECT/config.txt"
r1=$(calve revision create "R1 amend config" --of "$p1_digest" --relation amends | get '["id"]')
calve revision capture "$r1" config.txt --generation 1 >/dev/null
r1_digest=$(promote "$r1")
expect "P1 is unchanged" "$(calve pack show "$p1" | get '["state"]')" "PROMOTED"

without=$(calve baseline create "without revision" "$p1_digest" | get '["id"]')
with=$(calve baseline create "with revision" "$p1_digest" "$r1_digest" | get '["id"]')
expect "baseline without R1 validates" "$(calve baseline validate "$without" | get '["valid"]')" "true"
expect "baseline with R1 validates" "$(calve baseline validate "$with" | get '["valid"]')" "true"
echo "local" > "$PROJECT/config.txt"
calve baseline materialize "$without" --apply --discard config.txt >/dev/null
expect "materialize without revision" "$(cat "$PROJECT/config.txt")" "v1"
calve baseline materialize "$with" --apply >/dev/null
expect "materialize with revision" "$(cat "$PROJECT/config.txt")" "v2"
