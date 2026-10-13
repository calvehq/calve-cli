# First-party domains

Each domain is its own OpenAEVC extension binary; they depend only on the `calve-domain` crate and OpenAEVC contract crates, never on Calve internals.

## software-project (`org.calve.software`)

File snapshots, verification, change-size evaluation and materialization. See [software resources](software-resources.md) and [materialization](materialization.md).

## general-project (`org.calve.general`)

Non-file resources for projects that are not source code:

| Kind | Set with | Value |
|---|---|---|
| `note:<name>` | `{"text":"..."}` | text up to 64 KiB |
| `checklist:<name>` | `{"items":[{"text":"...","done":false}]}` | up to 500 items |
| `record:<name>` | `{"fields":{"key":"value","count":2}}` | strings, integers, booleans |
| `artifact:<name>` | `{"uri":"...","digest":"...","media_type":"..."}` | external reference |

```sh
calve extension enable org.calve.general
calve resource set <pack> --generation <n> --set 'note:plan={"text":"Ship to pilot first"}' --remove artifact:old-spec
calve resource show note:plan
calve resource list --domain general
```

`resource set` records all changes in one execution. Current values come from promoted packs; when a Baseline is active, only its members count.

## Language extensions

`org.calve.rust`, `go`, `python`, `javascript-typescript`, `java`, `c-cpp`, `shell` and `hcl` each provide a verifier, `org.calve.<language>.checks`, plus detection, ignore defaults and default check commands:

| Language | Detected by | Default checks |
|---|---|---|
| Rust | `Cargo.toml` | `cargo check --all-targets`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` |
| Go | `go.mod`, `go.work` | `go test ./...`, `go vet ./...`, `gofmt -l .` |
| Python | `pyproject.toml`, `setup.py`, `requirements.txt` | `python3 -m pytest -q` |
| JavaScript/TypeScript | `package.json` | `npm test --silent` |
| Java | `pom.xml`, `build.gradle(.kts)` | `mvn -q test`, or `gradle test -q` without a pom |
| C/C++ | `Makefile`, `CMakeLists.txt`, `meson.build` | `make`, or CMake configure + build |
| Shell | `.sh`/`.bash` files | `shellcheck <files>` |
| HCL | `.tf`/`.hcl` files | `terraform fmt -check -recursive` |

Override commands per Project (or Workspace/global) in configuration:

```toml
[integrations."org.calve.python".checks]
test = ["uv", "run", "pytest", "-q"]
types = ["uv", "run", "mypy", "src"]
```

`calve pack check <pack> --generation <n> [--language rust] [--check test]` copies the working tree (respecting ignore rules) into a scratch directory, overlays the sealed candidate's snapshots, runs each check with a cleared environment, and registers each result as `org.calve.check-result/v1` evidence bound to the candidate. If the language extension is enabled, OpenAEVC then runs its verifier over exactly that evidence: all checks passing is `PASS`, any failure is `FAIL`, and a missing tool is `INCONCLUSIVE` with a `tool_unavailable` finding, never a pass. The result records `drift`: captured paths whose working copy differs from the candidate.

`pack create --require-check <language>` attaches an OpenAEVC policy requiring that verifier to pass before qualification.
