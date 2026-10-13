# Activity

`calve activity` shows one recent timeline from Calve product events and OpenAEVC audit events. `--json` returns an array of items. The Console Activity section uses the same read model. The configured `ui.page_size` limits the total number of displayed items to 1–1000.

Each item includes `source` (`calve` or `openaevc`), `source_event_id`, `source_sequence`, `project_id`, `namespace_id`, `timestamp`, `kind`, and related `subjects`. OpenAEVC items also carry their authoritative `actor` and `body`; Calve product events currently have no recorded actor and include their `detail` text. Calve does not copy protocol audit events into its product database.

Items are ordered by timestamp, then by sequence within one source, with a deterministic source/ID tie-breaker. The two journals have independent sequences, so the merged display does not claim a shared cryptographic order. Older product events recorded only whole seconds; migration preserves that precision. New product events use nanosecond timestamps.

`calve activity` accepts `--source calve|openaevc`, `--actor ID`, `--object-kind KIND`, `--pack ID`, `--task ID`, `--execution ID`, `--since UTC`, `--until UTC`, `--severity LEVEL`, and `--type EVENT_KIND`. Filters combine with AND. `--type` matches the full event kind; `--object-kind` matches the part before the first dot (for example `task` in `task.completed`). Pack, Task, and Execution IDs match exact subject or detail references, or exact string values in a protocol event body. Severity matches a protocol event body's `severity` field when present. Calve product events currently record neither actor nor severity, so those filters exclude them. Time bounds are inclusive and use RFC 3339 UTC timestamps such as `2026-09-29T12:00:00Z`.

The default view reads recent OpenAEVC events through its public event query. It uses the public journal checkpoint to find a bounded window, then pages to the current end of the journal. Filtered queries scan the source journals so an older matching item is not hidden by newer unrelated events. The configured page size limits the final merged result.
