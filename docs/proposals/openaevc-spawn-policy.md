# Proposal: a versioned spawn-policy hook for OpenAEVC extensions

Status: proposal for a future OpenAEVC release (not part of OpenAEVC v0.1.0, which Calve uses
unmodified). Owner: Calve. Related: ADR 0005 (trust tiers), ADR 0017 (process containment).

## Problem
OpenAEVC v0.1.0 spawns a registered extension's program directly (F4): it clears the
environment except `PATH`, re-hashes the artifact on every spawn and talks to it over stdio.
The embedding application cannot add OS confinement around that spawn. Calve therefore classifies
native extensions as **T2: elevated trust, not confined**, and requires an explicit, recorded
acknowledgment to install or enable them. The residual is asserted by a test
(`t2_native_code_is_not_confined_residual`): a T2 extension can write outside its directory.

## Proposal
Add an optional, versioned launcher hook to the runtime's extension host:

```text
ExtensionLauncher v1
  fn launch(&self, req: LaunchRequest) -> Result<Child, LaunchError>
  LaunchRequest { program: AbsPath, artifact_digest: Digest, extension_id, version,
                  env: Vec<(String, String)>, stdio: Piped, policy: SpawnPolicy }
  SpawnPolicy  { read_only: Vec<AbsPath>, writable: Vec<AbsPath>, network: bool,
                 max_processes: Option<u32>, version: 1 }
```

- The runtime keeps verifying the artifact digest **immediately before** calling the launcher and
  passes the digest, so a launcher cannot run a different file by accident.
- The embedding application implements the launcher (Linux: Landlock + seccomp in a helper such
  as `calve __exec-confined`; Windows: AppContainer or a restricted token inside a Job Object;
  macOS: sandbox profile), and reports which policy fields it enforced.
- The hook is versioned (`SpawnPolicy.version`); an unknown version fails closed.
- Without a launcher, behaviour is exactly v0.1.0's.

## What Calve would do with it
- Offer a T2-confined tier: native extensions run with read access to their install directory
  and the Project, write access to a scratch directory, no network unless granted.
- Keep the T2 acknowledgment for extensions that declare needs beyond the policy.

## Compatibility
Additive to the extension host API; no wire or protocol change for extensions. Extensions that
need broader access declare it in their manifest so users see it before enabling.
