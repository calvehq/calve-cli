# Configuration

Calve reads versioned TOML in this order: built-in defaults, global user config, selected Workspace config, Project config, then an explicit `--config <file>` override. Global files live under `$XDG_CONFIG_HOME/calve` on Linux (or `$HOME/.config/calve` when unset). Workspace files are `workspaces/<workspace-id>.toml` under that directory. Project config is `.calve/config.toml`.

Each persisted file starts with `format_version = 1`. The current supported keys are:

```toml
format_version = 1

[ui]
color = "auto"       # auto, always, never
page_size = 100      # 1..1000; bounds activity results

[secrets]
api_token = "env:CALVE_API_TOKEN"  # or keyring:<name>; never a literal secret

[integrations."org.example.tool"]
enabled = true
```

Unknown Calve core keys are preserved and reported as warnings. Integration keys must be namespaced. Config files store secret references only; Calve does not resolve or copy the secret into TOML. Invalid known values and unsupported file versions stop loading.

Use `calve config list`, `get <key>`, `set <key> <value> --scope <global|workspace|project>`, `unset <key> --scope ...`, `validate`, and `edit-path --scope ...`. `set` and `unset` support `ui.color`, `ui.page_size`, `secrets.<name>`, `console.theme` (`dark`, `light`, `high-contrast`, `mono`), `console.mouse` and `console.unicode`. Provider profiles are edited with `calve provider add|edit` and stored as `[providers.<id>]` tables; harnesses are declared directly as `[harnesses.<id>]` tables (see [providers and harnesses](providers-and-harnesses.md)); language check overrides live under `[integrations."org.calve.<language>".checks]` (see [domains](domains.md)). They write a temporary file in the same directory and rename it over the old file after syncing. `--config <file>` adds a read-only final override for the current CLI invocation.
