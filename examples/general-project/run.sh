#!/usr/bin/env bash
# Non-software change workflow: structured notes and checklists, reviewed and accepted into a
# Baseline. Proves Calve is not a source-code-only product.
source "$(dirname "$0")/../lib.sh"

enable org.calve.general
intent=$(clv intent create "Launch plan" --description "Agree the launch checklist" | get '["id"]')
task=$(clv task create "$intent" "Draft the checklist" --assignee alex | get '["id"]')

pack=$(clv pack create "Launch checklist" --intent "$intent" --require-review | get '["id"]')
clv resource set "$pack" --generation 1 \
  --set 'note:launch/summary={"text":"Ship to the pilot group first."}' \
  --set 'checklist:launch/steps={"items":[{"text":"Docs reviewed","done":true},{"text":"Pilot invited","done":false}]}' \
  --set 'record:launch/owner={"fields":{"name":"alex","approvals":2}}' >/dev/null
clv task link-pack "$task" "$pack" >/dev/null

g=$(generation "$pack")
clv pack seal "$pack" --generation "$g" >/dev/null
# Review is a candidate-bound decision; OpenAEVC policy gates promotion on it.
clv pack approve "$pack" --generation "$g" --reason "matches the plan" >/dev/null
clv pack qualify "$pack" --generation "$g" >/dev/null
promoted=$(clv pack promote "$pack" --generation "$g" | get '["promoted_digest"]')
clv task complete "$task" >/dev/null

baseline=$(clv baseline create "pilot" "$promoted" | get '["id"]')
clv baseline activate "$baseline" >/dev/null
expect "accepted note" "$(clv resource show note:launch/summary | get '["value"]["text"]')" "Ship to the pilot group first."
expect "checklist state" "$(clv resource show checklist:launch/steps | get '["value"]["items"][1]["done"]')" "false"
expect "task completed" "$(clv task show "$task" | get '["state"]')" "COMPLETE"
