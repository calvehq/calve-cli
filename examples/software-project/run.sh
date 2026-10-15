#!/usr/bin/env bash
# Software project without Git: capture files, run a language check whose evidence a policy
# requires, promote, then safely materialize accepted state back into the working tree.
source "$(dirname "$0")/../lib.sh"

enable org.calve.software
enable org.calve.rust
cfg=$(calve config edit-path --scope project | get '["path"]')
# The check command is configurable; this one keeps the example fast and toolchain-free.
cat > "$cfg" <<'TOML'
format_version = 1
[integrations."org.calve.rust".checks]
build = ["sh", "-c", "grep -q 'pub fn greet' src/lib.rs"]
TOML
mkdir -p "$PROJECT/src"
printf '[package]\nname = "hello"\nversion = "0.1.0"\n' > "$PROJECT/Cargo.toml"
printf 'pub fn greet() -> &%sstr { "hi" }\n' "'static" > "$PROJECT/src/lib.rs"
expect "no git repository needed" "$(test -d "$PROJECT/.git" && echo yes || echo no)" "no"

pack=$(calve pack create "Greeting" --require-check rust | get '["id"]')
calve pack capture-tree "$pack" . --generation 1 >/dev/null
g=$(generation "$pack")
calve pack seal "$pack" --generation "$g" >/dev/null
status=$(calve pack check "$pack" --generation "$g" | get '["languages"][0]["verification"]["status"]')
expect "rust checks verified by OpenAEVC" "$status" "PASS"
calve pack qualify "$pack" --generation "$g" >/dev/null
promoted=$(calve pack promote "$pack" --generation "$g" | get '["promoted_digest"]')
baseline=$(calve baseline create "v1" "$promoted" | get '["id"]')

# Losing a captured file is recoverable; editing one without capturing blocks materialize.
rm "$PROJECT/src/lib.rs"
calve baseline materialize "$baseline" --apply >/dev/null
expect "file restored from accepted state" "$(grep -c greet "$PROJECT/src/lib.rs")" "1"
echo "local edit" >> "$PROJECT/Cargo.toml"
blocked=$(calve baseline materialize "$baseline" --apply | get '["blocked"][0]')
expect "uncaptured edit protected" "$blocked" "Cargo.toml"
