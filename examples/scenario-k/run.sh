#!/usr/bin/env bash
# §57 Scenario K — Crash during execution: a real daemon is killed mid-execution; after restart
# OpenAEVC reconciles it, Calve reports it accurately and no success is fabricated. One run.
source "$(dirname "$0")/../lib.sh"
export CALVE_EXECUTION_LEASE_MS=5000

enable "$FILES_EXT"
"$CALVE_BIN" --json --no-daemon-start provider add shell --kind local-process --executable sh >/dev/null
cfg=$(calve config edit-path --scope project | get '["path"]')
printf 'format_version = 1\n[harnesses.slow]\nprovider = "shell"\nmode = "check"\ncommand = ["-c", "sleep 20"]\n' > "$cfg"
calve config approve >/dev/null
pack=$(calve pack create "Slow" | get '["id"]')
# 1. Start an execution under the daemon.
pid=$("$CALVE_BIN" --json daemon start | q "d['pid']")
calve execution start "$pack" --harness slow --generation 1 >/dev/null 2>&1 &
client=$!
for _ in $(seq 1 150); do
  e=$(calve execution list --pack "$pack" | q "[x['id'] for x in d if x['state'] == 'RUNNING']")
  [[ "$e" != "[]" ]] && break
  sleep 0.2
done
execution=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])[0])" "$e")
# 2. Kill the daemon ungracefully.
kill_pid "$pid"
wait "$client" 2>/dev/null || true
# 3. Restart.
"$CALVE_BIN" --json daemon start >/dev/null
# 4. OpenAEVC reconciliation runs once the lease lapses.
sleep 7
# 5. Calve presents the interrupted state accurately.
expect "5 reported LOST" "$(calve execution show "$execution" | get '["state"]')" "LOST"
expect "5 inbox names it" "$(calve inbox list | q "any(i['summary'] == 'Execution LOST' for i in d)")" "true"
# 6. No duplicate successful execution is fabricated.
expect "6 one execution, none succeeded" "$(calve execution list --pack "$pack" | q "[e['state'] for e in d]")" '["LOST"]'
"$CALVE_BIN" --json daemon stop >/dev/null
