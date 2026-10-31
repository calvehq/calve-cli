# IPC

The CLI and console talk to `calved` over a local, private channel. Nothing listens on a network.

| Platform | Transport | Access control |
|---|---|---|
| Unix | Socket `daemon.sock` in the data directory | Directory `0700`, socket `0600`, peer UID checked |
| Windows | Named pipe `\\.\pipe\calve-<hash>` | Explicit user-only DACL, first-instance flag, remote clients rejected, impersonation SID check, client checks of the server's SID and image path |

**Version.** The handshake carries `api_version`, currently **1**. A client and daemon that differ refuse each other (`UNSUPPORTED_API_VERSION`). The daemon also reports its product version and OpenAEVC revision.

**Frames.** Length-prefixed JSON, at most 8 MiB. Payloads are the `Request` and `Response` types in `calve-api`, with `payload_version` 1.

**Idempotence.** Each request has a UUID. The daemon remembers the last 1,024 responses. A replayed id with the same body returns the original response, and one still in progress returns a retryable error.

**Shutdown** is a frame, not a signal, and it passes the same peer checks as a request.

Same-user processes are trusted on this channel, as with ssh-agent. See the [threat model](../security/threat-model.md).

The wire is an internal interface between matching binaries. For scripting, use the [JSON API](json-api.md).
