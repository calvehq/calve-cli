# OpenAEVC receipts

Every accepted OpenAEVC command produces a signed, immutable receipt object. Calve reads these through the public object query API:

```text
calve receipt list --limit 100
calve receipt show <receipt-digest>
```

`receipt list` returns a page of `items` and a `next` digest cursor. Pass `--after <next-digest>` to read the following page. The limit must be between 1 and 100 and may be capped further by the OpenAEVC runtime. Each item includes the receipt digest and its command, caller, request ID, result, journal sequence range, runtime instance, and completion time. `receipt show` returns the full immutable object envelope, including its signatures. These commands do not copy receipt state into Calve's product database.
