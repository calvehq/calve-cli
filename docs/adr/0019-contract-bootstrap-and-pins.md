# ADR 0019: Contract crate bootstrap and coordinated pins

Status: Accepted.

## Context
calve-extensions depends on `calve-integration-contract`, which lives in calve-cli and is not yet public.

## Decision
- calve-cli uses the contract crate by workspace path; calve-extensions declares `git = "https://github.com/calvehq/calve-cli.git", rev = "<40-hex>"`. Reproducibility comes from the commit hash.
- Local development before the commit is public rewrites the **transport only** (`scripts/dev-env.sh`: `url.file://…insteadOf`), never the lockfile.
- Coordinated advance (`scripts/bump-contract.sh`): commit in calve-cli → update rev + run conformance/e2e in calve-extensions → commit → append `{calve-cli sha, contract version, calve-extensions sha, e2e result}` to `docs/contract-pins.md`; xtask checks the lock rev equals the latest entry.

## Consequences
Release dependencies must be publicly reachable (tag `contract-v<semver>` or crates.io, each with authorization). Public cross-repo CI is PENDING until push authorization (G4/G5).

## Tests / evidence
M2 step 10 (pin workflow exercised once end to end).

## Residuals
None.
