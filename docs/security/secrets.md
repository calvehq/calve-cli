# Secrets

Code: `calve-app::redact`, `providers` (launch and streams), `app::fault`.

## Prevention

- Secrets are references in provider profiles (`env:NAME`, `keyring:NAME`), resolved at launch and passed to the worker **only in its environment**; never in argv, config files, the `WorkerContext` record (names only), errors or metric labels.
- Resolved values live in `Zeroizing` buffers, dropped when the launch ends.
- Secrets are never given to CIC modules, checks or extensions. A check also never inherits a variable that a provider uses as an `env:` secret. T2 extensions read secrets only through OpenAEVC grants (`SecretRead`).
- A secret under 4 bytes over-matches: `provider test` warns; redaction still applies.

## Redactor

Per secret, the pattern set is: raw; base64 standard and URL-safe at byte offsets 0, 1 and 2 (only the characters fully determined by the secret); percent-encoding with upper- and lower-case hex; JSON escaping; hex lower and upper. Patterns are matched with Aho-Corasick (leftmost-longest) and replaced by `[REDACTED]`.

Each stream has its own state: stdout and stderr are never merged. A stream holds back `longest pattern − 1` bytes until they can no longer start a match, and flushes at EOF; lines are split only after redaction, so 1-byte writes are caught.

While a launch lives, its secrets are also registered process-wide (`redact::register`), so sinks that never see the stream (errors, faults, details) redact them too.

## Sink inventory

| # | Sink | Mechanism | Test |
|---|---|---|---|
| 1 | worker stdout | per-stream redactor in `providers::pump` | `secrets::secrets_never_reach_any_sink` (raw, 1-byte, JSON, percent) |
| 2 | worker stderr | own per-stream redactor | same (base64 offsets 1/2, hex upper) |
| 3 | execution log | built from the redacted lines | same (`execution logs`) |
| 4 | `org.calve.harness.log` observations | appended from the redacted lines | same (store scan) |
| 5 | `execution logs` CLI | reads the observations | same (JSON and human output) |
| 6 | console viewer and toasts | reads the same observations and faults | same source as 4 and 7 |
| 7 | `Fault.message` / `detail` (CLI, IPC) | `app::fault` redacts against the registered secrets | `redact::tests::faults_are_redacted` |
| 8 | tracing / request log (`observe::record`) | records ids, codes and durations only | `secrets` store scan |
| 9 | diagnostics bundle | key-name redaction plus redacted sources | same (`doctor --bundle` scan) |
| 10 | metrics | names and counts only | `secrets` store scan |
| 11 | extension stderr as surfaced | extensions never receive Calve's secrets; errors pass through `fault` | 7 |
| 12 | CIC errors | CIC never receives secrets; errors pass through `fault` | 7 |
| 13 | check output → evidence | `run_command` redacts against the registered secrets; checks get no provider secrets | `checks` e2e |
| 14 | capture, materialization and recovery journals | record paths, digests and codes; error text passes through `fault` | `secrets` store scan |
| 15 | inbox and activity | derived from redacted records | same (`inbox list`, `activity`) |
| 16 | product DB backups (`.calve/backups/`) | the same product data as the database (which never stores secret values); owner-only, SHA-256 sidecar | `secrets` store scan; `continuity` |
| 17 | operational journals: capture, supersede, materialization, install | records ids, digests, paths, codes and exact signed envelopes; error text passes through `fault` | `secrets::captured_content_stays_in_content_sinks_only` |
| 18 | new diagnostic surfaces: `materialize list`, `inbox summary`, `status` blockers and recovery, `recover inspect`/`plan`, `maintenance gc --dry-run` (paths and counts), typed error details | ids, paths, digests, counts | same |
| 19 | diagnostics bundle (status, recovery) | redacted; never journals, spools, backups or conflict artifacts | same (bundle scan) |

### Captured content is not a diagnostic sink

File content the user captures or materializes is the product's data and is kept **verbatim**, never redacted (redaction would corrupt it): capture spools and chunk staging (`.calve/run/capture/`), the exact signed envelopes in capture journals, OpenAEVC effects and blobs, materialization backups (`.calve/run/materialize/<op>/*.backup`) and conflict artifacts (`.calve/conflicts/<op>/<step>/{displaced,ours,current}`). These are owner-only (`.calve` is 0700; backups and artifacts 0600 in 0700 directories) and are never copied into logs, the request log, errors, listings, the GC plan, recovery output or diagnostic bundles. A secret a user puts in a captured file is therefore in the content sinks by the user's choice, and in no diagnostic one (asserted by the test of row 17).

The end-to-end test scans every file under the data, config and Project directories and the bundle, plus every CLI output and error, for every encoded form of the secret.

Two more sinks hold a stdio agent's decoded text: the `text` of log frames and the `reason` of a failed run, which reaches OpenAEVC's failure record and the request log. Both are redacted after JSON decoding.

## Residual exposure (user-approved; tests assert it)

- A secret split across stdout and stderr is not detected (`redact::tests::a_split_across_streams_is_not_redacted_residual`, and the `split` line of the end-to-end test).
- Arbitrary transformations (reversal, compression, encryption, other encodings) are not detected.
- Base64 edge characters that depend on neighbouring bytes may remain.
- Channels outside Calve's sinks are not covered: files the worker writes (captured as content), the network, other processes.
- A worker that emits the base64 of a secret inside an agent `propose` frame gets the frame redacted, so the proposal fails rather than leaking.

The real boundary is not giving secrets to untrusted workers.
