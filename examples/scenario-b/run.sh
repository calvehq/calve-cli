#!/usr/bin/env bash
# §57 Scenario B — Software project without Git: scan, external edit, uncaptured status, capture,
# diff, tests through a harness, seal/verify/review/promote, Baseline, materialize into a clean
# copied directory. One run against the first-party software and language extensions.
source "$(dirname "$0")/../lib.sh"

# 1. A directory of source files with no Git metadata.
mkdir -p "$PROJECT/src"
printf '[package]\nname = "hello"\nversion = "0.1.0"\n' > "$PROJECT/Cargo.toml"
printf 'pub fn greet() -> u32 { 1 }\n' > "$PROJECT/src/lib.rs"
expect "1 no Git metadata" "$(test -e "$PROJECT/.git" && echo yes || echo no)" "no"
# 2. software-project plus a language extension.
enable org.calve.software
enable org.calve.rust
# 3. Scan resources: accepted state is empty, so every file is uncaptured.
first=$(clv pack create "Import" --require-review | get '["id"]')
clv pack capture-tree --accept-deletions "$first" . --generation 1 >/dev/null
g=$(generation "$first")
clv pack seal "$first" --generation "$g" >/dev/null
clv pack approve "$first" --generation "$g" --reason "initial import" >/dev/null
clv pack qualify "$first" --generation "$g" >/dev/null
base=$(clv pack promote "$first" --generation "$g" | get '["promoted_digest"]')
b0=$(clv baseline create "b0" "$base" | get '["id"]')
clv baseline activate "$b0" >/dev/null
expect "3 scan: nothing uncaptured after the import" "$(clv status | get '["uncaptured_changes"]')" "0"
# 4. Modify files externally.
printf 'pub fn greet() -> u32 { 2 }\n' > "$PROJECT/src/lib.rs"
# 5. status shows the uncaptured change.
expect "5 status shows the uncaptured change" "$(clv status | get '["uncaptured_changes"]')" "1"
# 6. Create and capture a ChangePack.
pack=$(clv pack create "Bump greeting" --require-review --require-check rust | get '["id"]')
clv pack capture "$pack" src/lib.rs --generation 1 >/dev/null
# 7. View the diff.
diff=$(clv view pack-diff "$pack" src/lib.rs | q "' '.join(l['text'] for l in d['lines'] if l['kind'] in ('add','delete'))")
expect "7 diff" "$diff" "pub fn greet() -> u32 { 1 } pub fn greet() -> u32 { 2 }"
# 8. Run tests through a provider and harness.
"$CALVE_BIN" --json --no-daemon-start provider add shell --kind local-process --executable sh >/dev/null
cfg=$(clv config edit-path --scope project | get '["path"]')
cat > "$cfg" <<'TOML'
format_version = 1
[integrations."org.calve.rust".checks]
build = ["sh", "-c", "grep -q 'greet' src/lib.rs"]
[harnesses.tests]
provider = "shell"
mode = "check"
command = ["-c", "grep -q '{ 2 }' src/lib.rs"]
TOML
clv config approve >/dev/null
# An execution starts a new generation, so a harness cannot run on a pack that holds captures
# (Calve refuses, or those effects could never be promoted); it runs in its own pack over the
# same working tree, and the candidate's own checks run through `pack check` below.
refused=$(clv execution start "$pack" --harness tests --generation "$(generation "$pack")" 2>&1 || true)
echo "$refused" | grep -q "pack already has effects" || { echo "FAILED: 8 refusal: $refused" >&2; exit 1; }
tests=$(clv pack create "Test run" | get '["id"]')
run=$(clv execution start "$tests" --harness tests --generation 1)
expect "8 tests ran through the harness" "$(echo "$run" | get '["state"]')" "SUCCEEDED"
# 9. Seal, verify, review, promote.
g=$(generation "$pack")
clv pack seal "$pack" --generation "$g" >/dev/null
expect "9 verify" "$(clv pack verify "$pack" --generation "$g" | get '["status"]')" "PASS"
expect "9 language checks" "$(clv pack check "$pack" --generation "$g" | get '["languages"][0]["verification"]["status"]')" "PASS"
clv pack approve "$pack" --generation "$g" --reason "reviewed" >/dev/null
clv pack qualify "$pack" --generation "$g" >/dev/null
promoted=$(clv pack promote "$pack" --generation "$g" | get '["promoted_digest"]')
# 10. Create and activate a Baseline.
b1=$(clv baseline create "b1" "$base" "$promoted" --edge "$promoted:$base:orders-after" | get '["id"]')
clv baseline activate "$b1" >/dev/null
expect "10 active Baseline" "$(clv status | get '["active_baseline"]["id"]')" "$b1"
# 11. Materialize into a clean copied working directory: the Project copied, the registration
# moved to the copy (a second live copy would be an identity conflict, Scenario J), and every
# working file removed.
pid=$(clv status | get '["project"]["project_id"]')
cp -r "$PROJECT" "$WORK/copy"
mv "$PROJECT" "$WORK/original"
"$CALVE_BIN" --json --no-daemon-start project relocate "$pid" "$WORK/copy" >/dev/null
PROJECT="$WORK/copy"
rm -rf "$PROJECT/src" "$PROJECT/Cargo.toml"
clv baseline materialize "$b1" --apply >/dev/null
# 12. File state matches the expected composition, byte for byte.
expect "12 src/lib.rs" "$(sha256 < "$PROJECT/src/lib.rs")" "$(sha256 < "$WORK/original/src/lib.rs")"
expect "12 Cargo.toml" "$(sha256 < "$PROJECT/Cargo.toml")" "$(sha256 < "$WORK/original/Cargo.toml")"
expect "12 the composed content" "$(cat "$PROJECT/src/lib.rs")" "pub fn greet() -> u32 { 2 }"
