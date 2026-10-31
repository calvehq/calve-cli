#!/usr/bin/env bash
# §57 Scenario C — Pre-promotion reopen: generation 1 is sealed, verified and approved; reopen
# makes generation 2; old verification and review show stale; generation 1's evidence and history
# stay inspectable. DEVIATION: OpenAEVC v0.1.0 cannot promote a pack's effects after a reopen, so
# steps 5-7 run on a superseding pack and the limit itself is asserted (see acceptance.md).
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
# 2. Reopen.
calve pack reopen "$p" --generation "$g1" >/dev/null
# 3. Generation 2.
g2=$(generation "$p")
expect "3 a new generation" "$(python3 -c "print($g2 > $g1)")" "True"
expect "3 open again" "$(calve pack show "$p" | get '["state"]')" "OPEN"
# 4. Prior verification and review display stale.
expect "4 review stale" "$(calve pack review "$p" | q "d[0]['stale']")" "true"
expect "4 verification not current" "$(calve view pack "$p" | q "[v['current'] for v in d['verifications']]")" "[false]"
expect "4 evidence stale" "$(calve evidence list "$p" | q "d['items'][0]['stale']")" "true"
# OpenAEVC v0.1.0 limit, asserted: a reopen keeps the pack's effects, and promotion requires every
# effect to come from the current generation, so a pack with effects cannot be promoted after a
# reopen. Resealing and requalifying generation 2 unchanged shows the refusal.
calve pack seal "$p" --generation "$g2" >/dev/null
calve pack approve "$p" --generation "$g2" --reason "same content" >/dev/null
calve pack qualify "$p" --generation "$g2" >/dev/null
same=$(calve pack promote "$p" --generation "$g2" 2>&1 || true)
echo "$same" | grep -q "without complete provenance" || { echo "FAILED: protocol limit changed: $same" >&2; exit 1; }
echo "ok - limit: OpenAEVC v0.1.0 refuses to promote reopened effects (steps 5-7 need a new pack)"
calve pack reopen "$p" --generation "$g2" >/dev/null
g2=$(generation "$p")
# 5. Modify the candidate: Calve's path is a superseding pack, from none of the old effects.
echo "second" > "$PROJECT/a.txt"
refused=$(calve pack capture "$p" a.txt --generation "$g2" 2>&1 || true)
echo "$refused" | grep -q "new pack" || { echo "FAILED: 5 capture refusal: $refused" >&2; exit 1; }
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
