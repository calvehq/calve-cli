# OpenAEVC compatibility

Calve 0.1.0 currently tracks the `main` branch of `https://github.com/calvehq/openaevc` (locked in `Cargo.lock`, last at `288b804fc2b7d178de9dd2de20d13e615aed02c8`) until a release tag is published. The crate versions are `0.1.0`. The supported protocol and extension-contract ranges are those declared by this revision's `openaevc-protocol` crate (currently protocol `0.1.0`). Calve queries the runtime before project mutations and stops if either range has no overlap. `calve version` shows the build pin; `calve doctor` shows the negotiated runtime versions. Calve uses the SDK's signed request envelopes and runtime admission path without accessing OpenAEVC tables.

This pin is a development compatibility target, not a release claim. The repository cannot be built from a clean machine until that Git revision is publicly accessible or the crates are published. A local checkout may be used through Cargo's Git URL rewrite for development while preserving the committed dependency source and revision:

```sh
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=url.file:///absolute/path/to/open-aevc.insteadOf \
GIT_CONFIG_VALUE_0=ssh://git@github.com/calvehq/openaevc.git \
cargo --config net.git-fetch-with-cli=true build --locked
```

The local checkout must contain the commit recorded in `Cargo.lock`. The repository is fetched over SSH, so CI needs a deploy key with read access. This override affects only that invocation; it is not a committed path dependency.
