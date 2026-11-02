# Trust tiers

Calve runs code from several sources. A tier says how far that code is confined, which decides what you are trusting when you enable it.

| Tier | What runs | Confinement | What you trust |
|---|---|---|---|
| **T0** | `calve`, `calved`, OpenAEVC | none; your permissions | The release you verified |
| **T1** | `cic.wasm` modules | Wasm with no imports, memory and fuel caps, supervised child with a hard kill, every response validated. On Linux also Landlock deny-all: where confinement is required, a module does not run without it. `calve doctor` reports `cic_landlock` and whether the policy is fail-closed or best-effort. macOS and Windows have the wasm boundary only | Very little: it can give wrong answers but cannot reach the host |
| **T2** | Native extension artifacts | **None.** OpenAEVC spawns them with your permissions. Package verification, re-hash on spawn, cleared environment, grants on host-mediated calls | The publisher, entirely |
| **T3** | Workers and checks | Process group or Job Object, resource limits. On Linux: user and mount namespaces hide `.calve/`, Calve's data and config directories and the daemon socket, then Landlock; refused if unavailable, unless the provider sets `confinement = "best-effort"`. Windows and macOS have neither, and such workers run unconfined. Descendants that leave the group escape it | The program you configured or approved |

T2 needs an explicit acknowledgment, `--acknowledge-native`, recorded per Project and artifact. `apps/calve/tests/extensions.rs::t2_native_code_is_not_confined_residual` proves the lack of confinement: its write outside the install directory succeeds.

Host capability grants limit what a T2 artifact may do **through the host**. They are not a sandbox: the artifact can still do anything your user can do by calling the OS itself.

**Keys** are outside the Project directory on every platform. **Project configuration** that chooses what runs is ignored until the host approves its exact bytes, so a worker cannot grant itself a harness or check command by writing it.

Check plans cross tiers: a T1 module proposes a command that runs as T3. So a plan runs only after you approve a digest covering the plan, the package and the resolved executable. Approval does not limit what the program then does.

Decision record: [ADR 0005](../adr/0005-trust-tiers.md).
