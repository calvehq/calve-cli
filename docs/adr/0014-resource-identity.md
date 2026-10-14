# ADR 0014: Resource identity and containment (cap-std)

Status: Accepted (M0: FG5 PASS Linux; Windows run).

## Context
Workspace I/O must never escape the Project root through symlinks and must detect files replaced while being hashed.

## Decision
- All workspace I/O through `cap-std` `Dir` handles from the Project root, component-wise nofollow traversal (`cap-fs-ext`).
- Locators: UTF-8, `/`, relative, no `.`/`..`/empty/NUL, not under `.calve/`, ≤ 4 096 B, ≤ 64 components; byte identity (no Unicode normalization); per-directory case-sensitivity probe; symlinks captured as targets and never followed.
- Stable-handle hashing: fstat → hash via handle → fstat → re-stat path, compare file ids; change → rehash (≤ 3) → `unstable_file`.

## Consequences
FG5 showed plain cap-std follows in-root symlinks; the component walk is what refuses them.

## Tests / evidence
FG5; M2 table-driven locator tests.

## Residuals
**User-approved limitation:** Windows symlink creation needs privilege or developer mode (otherwise `Conflicted(unsupported_symlink)`).
