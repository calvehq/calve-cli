# Domains

Calve's host is domain-neutral (INV-022). Software files, general project records and language checks are provided by packages from the [calve-extensions](https://github.com/calvehq/calve-extensions) catalog; each declares its kinds in signed `calve-integration.json` and implements its semantics in its CIC module and native OpenAEVC extension. See [extensions](extensions.md) for installing and enabling them.

| Declaration | Calve commands it drives |
|---|---|
| `files` (one enabled package) | `resource list/show/diff/scan/history`, `pack capture`, `pack capture-tree`, `pack verify`, `pack evaluate`, `pack create --require-snapshot-verification`, materialization, `ignore *` |
| `resources` | `resource set <pack> --set kind:name=JSON --remove kind:name`, `resource show kind:name`, `resource list --domain general` |
| `checks` | `pack check [--language l] [--check c]`, `pack create --require-check <language>` |

Check commands can be overridden per Project, Workspace or globally, keyed by the package id:

```toml
[integrations."<extension id>".checks]
test = ["uv", "run", "pytest", "-q"]
```

`pack check` copies the working tree (as the file package classifies it), overlays the sealed candidate's files, asks each checks package which languages it detects (`detect`) and which commands to run (`check_plan`), runs them with a cleared environment, and registers each result as `org.calve.check-result/v1` evidence bound to the candidate; the package's verifier then judges that evidence. A missing tool is never a pass.

A check plan is chosen by the package but runs with your permissions, so Calve runs a package's own plan only after you approve it: the first `pack check` prints each plan (its digest, the exact command, whether candidate files are appended, the environment names and the full canonical plan) and stops with `CHECK_PLAN_UNAPPROVED`; approve a plan you reviewed with `--approve-plan <digest>` (repeatable). The approval covers exactly that plan of that extension artifact: a changed plan or an upgrade asks again. Commands you configure under `[integrations."<id>".checks]` replace the plan and need no approval. Independently of approval, a plan may only name a program found on an absolute `PATH` entry (never a path, so candidate files are never executed), the candidate tree is copied without following symlinks, and environment names that look like credentials or loader hooks are refused.
