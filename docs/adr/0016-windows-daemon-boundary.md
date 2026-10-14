# ADR 0016: Windows daemon trust boundary and pipe authorization

Status: Accepted (native tests PENDING).

## Context
The daemon talks to clients over a named pipe on Windows.

## Decision
- Same-OS-user processes are trusted (user decision; like ssh-agent/gpg-agent). Defended: other local users, remote clients, pipe squatting by other users.
- Pipe `\\.\pipe\calve-<hex(sha256(user SID ‖ data_root))>`, explicit DACL (user SID only), `FILE_FLAG_FIRST_PIPE_INSTANCE`, `reject_remote_clients`; per-connection impersonation SID check; client-side server PID/SID and executable-path integrity checks — all in `calve-win-sec`.

## Consequences
These checks enforce the other-user boundary; they are not same-user authentication.

## Tests / evidence
M5 native: other-user client refused, squatter refused, remote refused, same-user unrelated process **accepted** (boundary assertion), stale daemon path refused.

## Residuals
Same-user malware can connect or impersonate (documented, asserted).
