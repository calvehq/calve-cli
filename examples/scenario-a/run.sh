#!/usr/bin/env bash
# §57 Scenario A — fresh installation and generic Project: every step, in order, in one run.
# Needs the first-party catalog (org.calve.general).
source "$(dirname "$0")/../lib.sh"

# 1. Install: the clv binary under test runs (calved is `clv daemon serve`, step 14).
expect "1 clv runs" "$("$CALVE_BIN" --json version | q "'calve' in d")" "true"
# 2. `clv init` in an empty directory (lib.sh initialized $PROJECT, which did not exist).
pid=$(clv status | get '["project"]["project_id"]')
nid=$(clv status | get '["project"]["namespace_id"]')
# 3. The Project is registered in the default Workspace.
expect "3 default Workspace registration" \
  "$("$CALVE_BIN" --json workspace show default | q "any(p['project_id']=='$pid' for p in d['projects'])")" "true"
# 4. Install and enable general-project from the signed catalog.
enable org.calve.general
expect "4 general-project enabled" "$(clv extension list | q "any(e['id']=='org.calve.general' and e['active'] for e in d)")" "true"
# 5. Intent and Tasks.
intent=$(clv intent create "Launch plan" --description "Agree the launch checklist" | get '["id"]')
task1=$(clv task create "$intent" "Draft the checklist" --assignee alex | get '["id"]')
task2=$(clv task create "$intent" "Record the owner" --assignee sam | get '["id"]')
# 6. ChangePack (review required by OpenAEVC policy).
pack=$(clv pack create "Launch checklist" --intent "$intent" --require-review | get '["id"]')
clv task link-pack "$task1" "$pack" >/dev/null
clv task link-pack "$task2" "$pack" >/dev/null
# 7. Generic resources as effects.
clv resource set "$pack" --generation 1 \
  --set 'note:launch/summary={"text":"Ship to the pilot group first."}' \
  --set 'checklist:launch/steps={"items":[{"text":"Docs reviewed","done":true},{"text":"Pilot invited","done":false}]}' \
  --set 'record:launch/owner={"fields":{"name":"alex","approvals":2}}' >/dev/null
expect "7 three effects" "$(clv pack show "$pack" | q "len(d['candidate_effects'])")" "3"
# 8. Seal.
g=$(generation "$pack")
clv pack seal "$pack" --generation "$g" >/dev/null
expect "8 sealed" "$(clv pack show "$pack" | get '["state"]')" "SEALED"
# 9. Verify/evaluate: OpenAEVC evaluates the pack's policies; without a review it is not
#    promotable.
expect "9 evaluated: review blocks promotion" \
  "$(clv pack promote "$pack" --generation "$g" --preflight | q "d['ready']")" "false"
# 10. Review/approve, then qualification is ALLOW.
clv pack approve "$pack" --generation "$g" --reason "matches the plan" >/dev/null
clv pack qualify "$pack" --generation "$g" >/dev/null
expect "10 qualification after review" \
  "$(clv pack promote "$pack" --generation "$g" --preflight | q "d['qualification']['outcome']")" "ALLOW"
# 11. Promote.
promoted=$(clv pack promote "$pack" --generation "$g" | get '["promoted_digest"]')
clv task complete "$task1" >/dev/null
clv task complete "$task2" >/dev/null
# 12. Baseline.
baseline=$(clv baseline create "pilot" "$promoted" | get '["id"]')
clv baseline activate "$baseline" >/dev/null
# 13. Receipts and activity.
receipt=$(clv receipt list --limit 1 | q "d['items'][0]['digest']")
expect "13 receipt verifies" "$(clv receipt verify "$receipt" | q "d['valid']")" "true"
expect "13 activity shows the promotion" \
  "$(clv activity --pack "$pack" | q "any('promot' in json.dumps(e) for e in d)")" "true"
before=$(clv status | q "[d['project'], d['active_baseline']]")
note=$(clv resource show note:launch/summary | get '["value"]["text"]')
# 14. Restart the daemon (a real calved process) and work through it.
"$CALVE_BIN" --json daemon start >/dev/null
expect "14 daemon running" "$("$CALVE_BIN" --json daemon status | q "d['running']")" "true"
clv status >/dev/null
"$CALVE_BIN" --json daemon stop >/dev/null
expect "14 daemon stopped" "$("$CALVE_BIN" --json daemon status | q "d['running']")" "false"
"$CALVE_BIN" --json daemon start >/dev/null
expect "14 daemon restarted" "$("$CALVE_BIN" --json daemon status | q "d['running']")" "true"
# 15. State is unchanged after the restart, read through the daemon.
expect "15 identity and active Baseline" "$(clv status | q "[d['project'], d['active_baseline']]")" "$before"
expect "15 accepted note" "$(clv resource show note:launch/summary | get '["value"]["text"]')" "$note"
expect "15 pack promoted" "$(clv pack show "$pack" | get '["state"]')" "PROMOTED"
expect "15 tasks complete" "$(clv task show "$task2" | get '["state"]')" "COMPLETE"
expect "15 Namespace unchanged" "$(clv status | get '["project"]["namespace_id"]')" "$nid"
expect "15 Baseline validates" "$(clv baseline validate "$baseline" | get '["valid"]')" "true"
expect "15 store verifies" "$(clv maintenance verify-store | get '["ok"]')" "true"
"$CALVE_BIN" --json daemon stop >/dev/null
