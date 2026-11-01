# Inbox

`calve inbox list` refreshes a Project's attention projection and shows active items; `--all` also shows resolved history. Items come from failed or lost OpenAEVC executions; quarantined packs; stale Calve reviews; completed Tasks that conflict with linked OpenAEVC state; failed verifications, evaluation warnings and denied qualification of live packs at their current generation (a later passing result resolves them); unhealthy extensions; interrupted capture sessions, supersessions and materializations (`recovery_required`), conflicted materializations (`materialization_divergence`); and Project identity conflicts. OpenAEVC v0.1.0 has no capability-request object, so that §29.1 source has nothing to show. Each item has a deterministic `source_key`, so repeated refreshes never duplicate it.

| Command | Effect |
|---|---|
| `inbox show <key>` | One item, including resolved ones |
| `inbox read <key>` | Mark read |
| `inbox ack <key>...` | Acknowledge one or more items (`acknowledge` still works) |
| `inbox unack <key>...` | Remove acknowledgements so items need attention again |
| `inbox snooze <key> --until <time>` | Hide until an RFC 3339 time, Unix seconds, or a duration such as `30m`, `2h`, `1d` |
| `inbox unsnooze <key>` | Show again |
| `inbox clear-resolved` | Forget resolved items |

`needs_attention` is false while an item is acknowledged or snoozed. These commands change only Calve's attention state: they never cancel an execution, release a quarantine, or approve a review, and `clear-resolved` never touches protocol audit history. Resolution is detected on the next list or action; if a resolved source becomes active again, its read, acknowledgement and snooze state resets.

The Overview screen in the console orders attention as failures, blocked work, review, stale state, running work, then warnings. The Inbox is per Project. `calve inbox summary` gives, for every Project of the selected Workspace, its attention and danger counts as of that Project's last refresh, read from each product database without opening its runtime; Namespaces are never merged.
