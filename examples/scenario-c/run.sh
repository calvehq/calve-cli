#!/usr/bin/env bash
# §57 Scenario C — Pre-promotion reopen, with the approved v0.1.0 deviation for generations that
# carry effects: the reopen is refused before anything changes, and the work continues in an
# explicit replacement pack. The original scenario text stays in docs/audit/sources; see
# acceptance.md. The literal lifecycle runs on one pack at the end, where the protocol allows it.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
echo "first" > "$PROJECT/a.txt"
# 1. Create, seal, verify and approve generation 1.
p=$(calve pack create "Reopened" --require-review | get '["id"]')
calve pack capture "$p" a.txt --generation 1 >/dev/null
g1=$(generation "$p")
c1=$(calve pack seal "$p" --generation "$g1" | get '["candidate_digest"]')
calve pack verify "$p" --generation "$g1" >/dev/null
calve pack approve "$p" --generation "$g1" --reason "looks right" >/dev/null
evidence=$(calve evidence list "$p" | q "d['items'][0]['digest']")
# 2. Reopen: refused for this generation, and nothing changed.
refused=$(calve pack reopen "$p" --generation "$g1" 2>&1 || true)
echo "$refused" | grep -q "REOPEN_UNSAFE" || { echo "FAILED: 2 reopen refusal: $refused" >&2; exit 1; }
expect "2 the pack is unchanged" "$(calve pack show "$p" | q "[d['state'], d['generation']]")" "[\"SEALED\", $g1]"
expect "2 no replacement started by itself" "$(calve supersede list | q "len(d)")" "0"
# 5. Modify the candidate, in an explicit replacement holding none of the old effects.
echo "second" > "$PROJECT/a.txt"
r=$(calve supersede start "$p" --keep 0 --yes | q "d.get('replacement') or d.get('new_pack') or d['pack']")
expect "5 the original is abandoned, kept in history" "$(calve pack show "$p" | get '["state"]')" "ABANDONED"
calve pack capture "$r" a.txt --generation "$(generation "$r")" >/dev/null
g3=$(generation "$r")
# 6. Rerun qualification and review on the changed candidate.
c2=$(calve pack seal "$r" --generation "$g3" | get '["candidate_digest"]')
calve pack verify "$r" --generation "$g3" >/dev/null
calve pack approve "$r" --generation "$g3" --reason "new candidate reviewed" >/dev/null
calve pack qualify "$r" --generation "$g3" >/dev/null
# 7. Promote the changed candidate (a new pack, not generation 2 of the first: see the limit).
calve pack promote "$r" --generation "$g3" >/dev/null
expect "7 promoted" "$(calve pack show "$r" | get '["state"]')" "PROMOTED"
expect "7 a different candidate" "$(test "$c1" != "$c2" && echo yes)" "yes"
# 8. Generation 1's evidence and history remain inspectable.
expect "8 old evidence readable" "$(calve evidence show "$evidence" | q "d['envelope']['body']['generation'] if 'envelope' in d else d['generation']")" "$g1"
expect "8 old review kept" "$(calve pack review "$p" | q "sum(1 for r in d if r['generation'] == $g1)")" "1"
expect "8 sealed candidate 1 in history" "$(calve view pack "$p" | q "any(v['generation'] == $g1 for v in d['verifications'])")" "true"

# The literal lifecycle on one pack, where the protocol allows it: generation 1 carries no effects,
# so nothing stale survives the reopen, and the same pack promotes at a later generation.
e=$(calve pack create "Reopened empty" --require-review | get '["id"]')
g1=$(generation "$e")
calve pack seal "$e" --generation "$g1" >/dev/null
calve pack approve "$e" --generation "$g1" --reason "empty" >/dev/null
calve pack reopen "$e" --generation "$g1" >/dev/null
expect "literal 4 review stale" "$(calve pack review "$e" | q "d[0]['stale']")" "true"
echo "third" > "$PROJECT/b.txt"
calve pack capture "$e" b.txt --generation "$(generation "$e")" >/dev/null
g2=$(generation "$e")
calve pack seal "$e" --generation "$g2" >/dev/null
calve pack approve "$e" --generation "$g2" --reason "reviewed again" >/dev/null
calve pack qualify "$e" --generation "$g2" >/dev/null
calve pack promote "$e" --generation "$g2" >/dev/null
expect "literal 7 promoted at the later generation, same pack" "$(calve pack show "$e" | get '["state"]')" "PROMOTED"
