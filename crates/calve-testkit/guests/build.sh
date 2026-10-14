#!/bin/sh
# Rebuilds the CIC reference guest fixtures from source and records their digests. The outputs
# are committed; `cargo test -p calve-testkit` checks SHA256SUMS against the files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../fixtures/cic"
mkdir -p "$out"
cargo build --quiet --locked --release --target wasm32-unknown-unknown --manifest-path "$here/Cargo.toml"
cp "$here/target/wasm32-unknown-unknown/release/cic_ref_rust.wasm" "$out/ref-rust.wasm"
cp "$here/target/wasm32-unknown-unknown/release/cic_ref_min.wasm" "$out/ref-min.wasm"
grep -o 'r#"{.*}"#' "$here/ref-rust/src/lib.rs" | head -1 | sed 's/^r#"//; s/"#$//' > "$out/toy-metadata.json"
(cd "$out" && sha256sum ref-rust.wasm ref-min.wasm toy-metadata.json > SHA256SUMS)
cat "$out/SHA256SUMS"
