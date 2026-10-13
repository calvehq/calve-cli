# Software resources

Calve's first-party software extension records exact file snapshots in OpenAEVC ChangePacks. Build the CLI and extension with `cargo build --bins`, initialize a Project, then explicitly enable the local extension:

```text
calve extension enable            # the bundled software extension
calve extension enable ./path/to/calve_ext_software   # or a specific artifact
calve extension list
```

`extension enable` installs the artifact into the shared, content-addressed package cache (see [extensions](extensions.md)), checks its manifest and extension-contract range, and registers it with OpenAEVC. Projects reference the cached artifact by digest, so the same bytes serve every Project.

Create a pack and capture a Project-relative file:

```text
calve pack create "Update message" --require-snapshot-verification
calve resource list
calve pack capture-tree <pack-id> src --generation 1
calve resource show src/message.txt
calve resource diff <pack-id> src/message.txt
```

`pack capture-tree` scans an existing directory (default `.`), applies ignore rules, preflights eligible files, and submits their snapshots in **one** OpenAEVC execution. It accepts at most 64 files and 16 MiB total, with the same 1 MiB limit per file. It returns captured paths and the updated generation. Use `pack capture <pack-id> src/message.txt --generation 1` for a single-file pack. Each pack accepts one effect-bearing capture batch: adding another work unit would advance the generation and invalidate earlier effect provenance at promotion. A repeat with identical files returns unchanged results; changed or additional files need a new pack. File content is stored in effect payloads; these commands do not alter the working tree.

Only regular files of at most 1 MiB can be captured. Paths must be relative, UTF-8, outside `.calve`, and contain no symlink components. `resource list` applies [resource ignore rules](ignore.md), does not traverse symlinks, and is bounded to 10,000 entries and 32 directory levels. Ignored files outside `.calve` may still be captured by explicit path. `resource diff` compares current bytes with the pack's latest snapshot for that path and reports `unchanged`, `modified`, `deleted`, or `not_captured`; text line changes are included for small UTF-8 files.

After capture, seal and verify with the current generation:

```text
calve pack seal <pack-id> --generation <current-generation>
calve pack verify <pack-id> --generation <current-generation>
calve pack verify <pack-id> --generation <current-generation> --path src/message.txt --digest <expected-sha256>
calve pack evaluate <pack-id> --generation <current-generation> --warn-after-bytes 262144 --warn-after-files 16
calve pack qualify <pack-id> --generation <current-generation>
calve pack promote <pack-id> --generation <current-generation>
```

The verifier checks all stored software snapshots for structural and content integrity. With `--path` and `--digest`, it also checks the latest snapshot of that path against the expected digest. It records PASS, FAIL, or INCONCLUSIVE in OpenAEVC. When the pack was created with `--require-snapshot-verification`, OpenAEVC policy requires the latest candidate-bound verification result to be PASS before qualification. Without that option, verification is recorded but does not gate promotion.

The change-size evaluator counts captured software files and their total bytes through the extension contract. It records an OpenAEVC evaluation with `ALLOW` when the count is within both thresholds, `WARN` when either is exceeded, and `UNKNOWN` when no software snapshots exist. Defaults are 16 files and 256 KiB; `--warn-after-files` and `--warn-after-bytes` override them. This is an advisory size signal, not a universal risk score or a promotion policy.

Materialization writes accepted snapshots back to the working tree safely; see [materialization](materialization.md). Snapshot effects record whole-file content, so deletions and renames are not yet expressible as effects: a file removed locally is simply not captured.
