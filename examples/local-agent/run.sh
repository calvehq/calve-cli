#!/usr/bin/env bash
# A deterministic stdio agent: it reads the context frame Calve sends and proposes a file.
# No credentials or third-party services are involved.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
agent="$WORK/agent.sh"
cat > "$agent" <<'AGENT'
#!/bin/sh
read -r context
echo '{"type":"log","text":"planning"}'
# "Y2hhbmdlbG9nCg==" is base64 for "changelog\n".
echo '{"type":"propose","path":"CHANGELOG.md","content_base64":"Y2hhbmdlbG9nCg=="}'
echo '{"type":"done","status":"succeeded"}'
AGENT
chmod +x "$agent"
# The agent is the provider's program. Windows cannot execute a script directly, so there sh
# runs it; elsewhere it runs itself (a confined worker may execute and read its own program).
if [ -n "${WINDIR:-}" ]; then
  clv provider add fake --kind stdio-agent --executable sh --arg "$agent" >/dev/null
else
  clv provider add fake --kind stdio-agent --executable "$agent" >/dev/null
fi
expect "provider healthy" "$(clv provider test fake | get '["healthy"]')" "true"
cfg=$(clv config edit-path --scope project | get '["path"]')
printf 'format_version = 1\n[harnesses.changelog]\nprovider = "fake"\nmode = "change"\n' > "$cfg"
clv config approve >/dev/null
pack=$(clv pack create "Agent changelog" | get '["id"]')
run=$(clv execution start "$pack" --harness changelog --generation 1)
expect "agent run succeeded" "$(get '["state"]' <<<"$run")" "SUCCEEDED"
expect "agent proposal became an effect" "$(get '["effects"][0]["path"]' <<<"$run")" "CHANGELOG.md"
execution=$(get '["execution"]' <<<"$run")
expect "agent log recorded" "$(clv view execution "$execution" | get '["output"][0]["text"]')" "planning"
promote "$pack" >/dev/null
expect "promoted" "$(clv pack show "$pack" | get '["state"]')" "PROMOTED"
