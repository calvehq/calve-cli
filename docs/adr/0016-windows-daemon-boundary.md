# ADR 0016: Windows daemon trust boundary and pipe authorization

Status: Accepted; implemented in M5 (same-user and stale-path tests native; other-user, squatter and remote PENDING).

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

## M5 implementation (2026-10-26)
- `calve_win_sec::{pipe_name, pipe_server, verify_pipe_client, pipe_connect, verify_pipe_server}`. Server: owner + DACL `O:<sid>D:P(A;;GRGW;;;<sid>)`, `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance, `PIPE_REJECT_REMOTE_CLIENTS`; each connection is impersonated and the thread-token SID compared with the daemon's. Client: `SECURITY_IDENTIFICATION` QoS, server PID → token SID equal to ours, image path equal to the `calved.exe` beside the client, PID re-checked after the image check.
- `calve-ipc` serves one generic connection handler over the Unix socket or the pipe. `Frame::Shutdown` → `ShutdownAck{pid}` replaces `kill -TERM` for `calve daemon stop` on every platform (R2); the shutdown request passes the same peer checks as any request.
- Native evidence (Windows 11, x86_64-pc-windows-gnu, `daemon_windows.rs`): same-user client served; a second daemon cannot take the pipe ("already running"); a daemon copy at another path is refused (`DAEMON_INCOMPATIBLE: refusing the daemon pipe: the daemon runs …\stale\calved.exe instead of …\calved.exe`); `daemon stop` over the pipe returns the daemon pid and the process exits 0.
- **PENDING (no second account / remote host on this machine):** other-user client refused, other-user squatter refused, remote client refused. MSVC build not run.
