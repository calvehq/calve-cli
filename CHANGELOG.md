# Changelog

All notable changes to Calve are documented here.

## Unreleased

### Added

- **Acceptance scenarios** A–P run as tests, and `xtask acceptance` reports them with an environment
  fingerprint, keeping deviations apart from passes.
- **`CAPABILITY_DENIED`**: a host call OpenAEVC denies now reports the extension, the capability and
  the grant command.
- Concept, architecture, guide, reference and security documentation.

### Fixed

- A pack refresh no longer holds a transaction across awaits, which made concurrent writes fail.
- **`execution cancel` works on a running execution.** It needed the Project writer lock, which the
  run holds until it ends, so it always failed with `PROJECT_LOCKED`.
- The `execution start` and `execution wait` JSON schemas no longer require fields that a cancelled
  execution does not have. `execution cancel`, `task link-execution`, `extension catalog reset` and
  `extension switch-publisher` now support `--json`.
- A running execution is no longer disturbed by reads: `maintenance gc --dry-run` leaves its runtime
  open, `maintenance check` reports the store as `in_use`, and `inbox list`, `inbox show` and
  `--preflight` no longer need the writer lock.
- Listing captures and sagas no longer truncates a journal record being written.
- A supersede whose replay attempt dies after applying effects now compensates and keeps the
  original pack. It could finish Done on a replacement that could never be promoted.
- A cancelled worker's output is kept in `.calve/logs/`, and `execution start` reports the
  cancellation instead of failing.
- Relative paths reach a daemon as absolute paths: `doctor --bundle`, `project register`,
  `project relocate`, `project adopt-copy` and catalog `--root`.
- `pack check` scratch copies are private to the user.
- A daemon of another Calve version is refused with `DAEMON_INCOMPATIBLE`.
- A store held by another process reports the retryable `PROJECT_LOCKED`, not `STALE_VIEW`.
- `activity --pack` no longer scans the event index. Views after an unrelated change no longer list
  receipts.
- `execution start` refuses any pack with effects. An execution would start a new generation and
  make those effects unpromotable.

### Changed

- **Bundled extensions removed.** Calve ships only `calve` and `calved`. Extensions come from signed
  catalogs (`calve extension catalog add …`, `calve extension install …`); the first-party ones live
  in calve-extensions.
- **Catalogs are TUF repositories.** `extension catalog-trust`/`catalog-untrust`/`catalogs` are
  replaced by `extension catalog add|list|refresh|reset|remove`; the root is pinned by SHA-256 and
  verified with delegations, rollback and freeze protection (sigstore-tuf behind Calve's
  `TrustClient`). `extension enable` takes an extension id (no local artifact paths).
- **Native extensions need an explicit acknowledgment.** `--acknowledge-native` on install and per
  Project on enable/update records that the extension runs with the user's permissions and is not
  confined.
- **The Calve Integration Contract (CIC) is introduced.** Ignore decisions, capture decisions,
  diffs, language detection and check plans come from the enabled packages' CIC modules, run in a
  supervised wasm sandbox (`calve __cic-sandbox`). A rename is captured as a delete plus an add with
  a derived relation recorded as an observation (no rename effects are emitted; recorded ones are
  still read).
- **Capture refuses over-limit files** with `FILE_TOO_LARGE` (inline content limit 1 MiB until
  chunked content).
- `ignore list` shows Calve's hard rule and the lines of the package's ignore file; the package's
  built-in defaults are reported by `ignore check`.
- The built-in capture harness is listed as `capture`.
- **Native builds are selected by exact target triple and digest.** A catalog's `package.json`
  lists each native build under its Rust target triple with its sha256, stored at
  `<id>/<version>/<triple>/<file>`; Calve installs only its own triple and requires the catalog,
  index and handshake digests to agree. After registration, the manifest OpenAEVC recorded must
  equal the installed one (`EXTENSION_IDENTITY_MISMATCH` otherwise).
- **Stable error codes and exit statuses** (ADR 0020): every error has a code from a fixed
  table that sets the exit status (2 usage, 3 conflict, 4 not found, 5 permission or confirmation,
  6 incompatible, 7 recovery, 8 unavailable, 9 rejected, 130 cancelled); OpenAEVC errors map onto
  Calve codes and stay available in `detail.openaevc`. `PROJECT_BUSY` is now `PROJECT_LOCKED`.
- **`--json` is a versioned envelope, only for commands that declare it**:
  `{"api_version":"1","command","data"}` on stdout, errors as an envelope on stderr; per-command
  schemas in `docs/reference/json/v1/`. Human output is tables and aligned records.
- **Destructive commands need `--yes`** (asked interactively on a terminal); `workspace delete`
  of a Workspace that still lists Projects also needs `--force`.
- **Worker secrets are redacted** from every output, log, error and bundle (raw and encoded
  forms, per stream); the worker context is recorded in OpenAEVC (names only), and OpenAEVC
  idempotency keys derive from the Calve request id.
- **Check-plan approvals cover the executable.** The approval digest now also covers the package
  and the executable `PATH` resolves the program to (path and sha256), checked again before each
  run; replacing the executable or changing `PATH` asks for approval again (`CHECK_PLAN_CHANGED`
  if it changes mid-run).

- **`capture-tree` asks before recording deletions** of accepted files: `--accept-deletions`
  (`CONFIRMATION_REQUIRED` otherwise), `--preview` shows the plan. One batch holds up to 10 000
  files and 512 MiB (`LIMIT_EXCEEDED`); files over the inline 1 MiB are chunked up to 256 MiB
  when the file domain declares it (`FILE_TOO_LARGE` above).
- **Materialization is journaled** (`calve materialize list|resume|resolve|rollback`): a
  concurrent change stops it as a conflict with both versions kept, never reversed
  automatically. On filesystems without atomic exchange/no-replace (macOS and Windows until M5)
  replacing or deleting files is refused unless `--allow-unsafe-fs`. Discarded local edits are
  kept as the step's verified backup instead of `.calve/cache/discarded/`.
- **`status` is a typed read model**: pack counts by state with their items, the active Baseline
  as `{id, aliases}`, task totals and attention, verification and review blockers, recovery
  items, extension and provider problems.
- **`maintenance gc` reports a plan** per class (owner, count, estimated bytes, reason) and also
  collects Calve's own expired state; conflict artifacts only with `--conflicts`.
- **Seal and promote preflight** (`--preflight`), expected candidate (`--candidate`) and an
  idempotent promotion result with its record and receipt; capture sessions and the supersede
  saga resume after a crash (`calve capture`, `calve supersede`).
- **Baselines are OpenAEVC objects** with labels in their metadata: `baseline create --edge`,
  `baseline derive`, and `compare` with revisions and resource differences.
- **Pack commands at a moved generation fail with `STALE_VIEW`** (they were `PRODUCT_ERROR`).

### Security

- **Check plans need approval.** A checks package's own plan (from its CIC module) runs with your
  permissions, so `pack check` refuses with `CHECK_PLAN_UNAPPROVED` and prints each plan with its
  digest until you approve it with `--approve-plan <digest>`; the approval covers that exact plan
  of that extension artifact. Configured `[integrations."<id>".checks]` commands need none. A plan
  may only name a program on an absolute `PATH` entry, and candidate files are copied for checks
  without following symlinks.
- **Product database backups carry a SHA-256** checked before any restore; Calve's transient
  entries in the tree (`.calve-init-*`, `.calve-mat-*`, `.calve-trash-*`, `.calve-tmp-*`,
  `.calve-adopt-source-*`) are never scanned or captured.
- **One locator validator.** The contract crate now owns the ADR 0014 locator rules
  (`calve_integration_contract::locator::validate`), shared by the host and extensions.
