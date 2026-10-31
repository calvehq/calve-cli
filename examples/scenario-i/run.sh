#!/usr/bin/env bash
# §57 Scenario I — Project relocation: stop the daemon, move the root, relocate the registration;
# identity, Namespace and all protocol/product state survive. One run.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
# 1. Initialized and registered (lib.sh), with some accepted state.
echo "kept" > "$PROJECT/a.txt"
p=$(calve pack create "P" | get '["id"]')
calve pack capture "$p" a.txt --generation 1 >/dev/null
digest=$(promote "$p")
baseline=$(calve baseline create "B" "$digest" | get '["id"]')
open=$(calve pack create "still open" | get '["id"]')
pid=$(calve status | get '["project"]["project_id"]')
nid=$(calve status | get '["project"]["namespace_id"]')
receipts=$(calve receipt list --limit 100 | q "len(d['items'])")
# 2. The daemon serves the Project, then stops.
"$CALVE_BIN" --json daemon start >/dev/null
calve status >/dev/null
"$CALVE_BIN" --json daemon stop >/dev/null
expect "2 daemon stopped" "$("$CALVE_BIN" --json daemon status | q "d['running']")" "false"
# 3. Move the root.
mv "$PROJECT" "$WORK/moved"
PROJECT="$WORK/moved"
expect "3 health asks for relocation" "$("$CALVE_BIN" --json project health "$pid" | get '["status"]')" "missing_path"
# 4. Relocate the registration.
"$CALVE_BIN" --json project relocate "$pid" "$PROJECT" >/dev/null
expect "4 healthy at the new path" "$("$CALVE_BIN" --json project health "$pid" | get '["status"]')" "healthy"
# 5. Identity and Namespace unchanged.
expect "5 ProjectId" "$(calve status | get '["project"]["project_id"]')" "$pid"
expect "5 NamespaceId" "$(calve status | get '["project"]["namespace_id"]')" "$nid"
# 6. Protocol and product state valid.
expect "6 store verifies" "$(calve maintenance verify-store | get '["ok"]')" "true"
expect "6 product checks" "$(calve maintenance check | get '["ok"]')" "true"
expect "6 promoted pack" "$(calve pack show "$p" | get '["state"]')" "PROMOTED"
expect "6 open pack still writable" "$(calve pack show "$open" | get '["state"]')" "OPEN"
expect "6 Baseline validates" "$(calve baseline validate "$baseline" | get '["valid"]')" "true"
expect "6 receipts intact" "$(calve receipt list --limit 100 | q "len(d['items']) >= $receipts")" "true"
calve intent create "after the move" >/dev/null
