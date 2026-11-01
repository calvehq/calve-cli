# File resources

File capture, views and materialization work through the enabled package that declares a `files` domain (for source trees, the software extension from calve-extensions). Calve scans the working tree without following symlinks and asks the package's CIC module which entries are ignored (`classify`); captures build two manifests (accepted content and working tree) and let the package decide one canonical operation per path (`capture`: add, modify, delete, unchanged or refuse). Calve then builds the effects itself with the host-generic file payload and submits them in one OpenAEVC execution.

```text
calve pack create "Update message" --require-snapshot-verification
calve resource list
calve pack capture-tree <pack-id> src --generation 1
calve pack capture <pack-id> src/message.txt --generation 1
calve resource show src/message.txt
calve resource diff <pack-id> src/message.txt
```

- A rename is captured as a delete plus an add. When the package declares relation kinds, it derives them (e.g. a rename) in a separate `relate` session; Calve records each verified relation verbatim as an observation linked to the effects and never interprets it. A required relation that fails stops the capture before anything is submitted.
- Files up to 1 MiB are stored inline, and larger ones as verified chunked blobs up to the limit in [error codes](error-codes.md) (`FILE_TOO_LARGE` above it). Paths are UTF-8, relative, outside `.calve`, without symlink components or Windows-reserved forms.
- Each pack accepts one effect-bearing capture batch; repeating it with identical files returns unchanged results.
- `resource diff` compares the captured content with the working copy; line hunks come from the package's `diff` operation.

Verification and evaluation use the verifier and evaluator the package declares (`pack verify --path p --digest d`, `pack evaluate --warn-after-files n --warn-after-bytes b`). Materialization writes accepted content back safely; see [materialization](materialization.md).
