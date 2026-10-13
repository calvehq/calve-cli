# Candidate evidence

Seal a pack, then register a file against its exact candidate:

```text
calve evidence add <pack-id> --generation <sealed-generation> --kind org.example.report --file report.txt --media-type text/plain
calve evidence show <returned-digest>
calve evidence list <pack-id> --current
```

Relative file paths resolve from the Project root. The file may be outside the Project when given as an absolute path. Calve rejects files under `.calve`, payloads over 1 MiB, and reserved `org.calve.review.*` kinds. OpenAEVC stores the payload as an immutable Blob and binds the evidence record to the pack's sealed candidate digest and generation. A stale generation, unsealed pack, or protocol-invalid evidence request is rejected. `show` returns the OpenAEVC evidence record; it does not write the payload back to disk.

`evidence list` reads OpenAEVC's immutable object index. It returns `items` with a `stale` flag and a `next` cursor. `--current` hides evidence from older candidates. Use `--after <next-digest>` to page forward and `--limit 1..100` to set the global evidence-index page size; a page can contain fewer items for the selected pack because objects from other packs are filtered after reading it.

This is a generic evidence input. Review decisions use a separate candidate-bound evidence path described in [review policy](review-policy.md). Evaluator selection and source links remain planned work.
