# Windows boundary

**Same-user processes are trusted**, as on Unix, and like ssh-agent or gpg-agent. Calve defends against other local users and remote clients. It does not defend against malware running as you.

| Threat | Mechanism | Tested |
|---|---|---|
| Other user connects to the daemon | Pipe DACL for the user's SID; impersonation SID check per connection | **Pending**: no second account was available |
| Other user squats the pipe name | Name derived from the SID and data root; first-instance flag; client checks the server's SID | **Pending** |
| Remote client | `PIPE_REJECT_REMOTE_CLIENTS` | **Pending** |
| Stale or foreign daemon binary | Client compares the server's image path with the `calved.exe` beside it | Native test |
| Second daemon | First-instance flag, "already running" | Native test |
| Other users reading state | Owner-only DACLs | Native test |

Native results come from Windows 11 x86_64 with cross-compiled `x86_64-pc-windows-gnu` binaries. The MSVC target, which is the one the release workflow builds, has not been run.

**Not available on Windows:** Landlock and mount namespaces, so workers have no filesystem confinement there and can reach `.calve/`, the daemon pipe and anything else the user can. Keys are still outside the Project directory, and Project configuration still needs approval; and `cpu_seconds` limits, which are refused. Job Objects apply memory and process limits. A process started out of the job by another service escapes it.

**Materialization:** see [materialization guarantees](materialization-guarantees.md).

**Install rename:** a Windows telemetry service can briefly hold a newly written executable open, which refuses the install rename. Calve retries for up to 5 seconds, and a holder that lasts longer fails and is named in the error. This is a mitigation: a slower holder, or another service, can still fail an install, and retrying the install is then safe.

Decision record: [ADR 0016](../adr/0016-windows-daemon-boundary.md).
