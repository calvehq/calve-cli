#!/usr/bin/env bash
# Non-software change workflow: structured notes and checklists, reviewed and accepted into a
# Baseline. Proves Calve is not a source-code-only product.
source "$(dirname "$0")/../lib.sh"

enable org.calve.general
intent=$(calve intent create "Launch plan" --description "Agree the launch checklist" | get '["id"]')
task=$(calve task create "$intent" "Draft the checklist" --assignee alex | get '["id"]')

pack=$(calve pack create "Launch checklist" --intent "$intent" --require-review | get '["id"]')
calve resource set "$pack" --generation 1 \
  --set 'note:launch/summary={"text":"Ship to the pilot group first."}' \
  --set 'checklist:launch/steps={"items":[{"text":"Docs reviewed","done":true},{"text":"Pilot invited","done":false}]}' \
  --set 'record:launch/owner={"fields":{"name":"alex","approvals":2}}' >/dev/null
calve task link-pack "$task" "$pack" >/dev/null

g=$(generation "$pack")
calve pack seal "$pack" --generation "$g" >/dev/null
# Review is a candidate-bound decision; OpenAEVC policy gates promotion on it.
calve pack approve "$pack" --generation "$g" --reason "matches the plan" >/dev/null
calve pack qualify "$pack" --generation "$g" >/dev/null
promoted=$(calve pack promote "$pack" --generation "$g" | get '["promoted_digest"]')
calve task complete "$task" >/dev/null

baseline=$(calve baseline create "pilot" "$promoted" | get '["id"]')
calve baseline activate "$baseline" >/dev/null
expect "accepted note" "$(calve resource show note:launch/summary | get '["value"]["text"]')" "Ship to the pilot group first."
expect "checklist state" "$(calve resource show checklist:launch/steps | get '["value"]["items"][1]["done"]')" "false"
expect "task completed" "$(calve task show "$task" | get '["state"]')" "COMPLETE"
