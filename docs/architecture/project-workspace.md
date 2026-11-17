# Projects and Workspaces

Two independent stores describe a Project:

- **The Project itself**, in `.calve/`: its identity, keys, product database and OpenAEVC store. It travels with the directory and is complete without the registry.
- **The machine registry**, `workspace.sqlite3`: ProjectId → canonical path and NamespaceId, plus Workspace membership. It is local and can be rebuilt with `project register`.

**Discovery.** Calve walks up from the current directory to the first `.calve/project.toml`, stopping at the filesystem root or a `CALVE_DISCOVERY_CEILING` boundary. If none is found, it uses the selected Workspace's default Project.

**Identity checks.** On open, Calve compares the directory's identity with the registry and the store binding. A second live path with the same ProjectId is a copy, and writes are blocked with an identity conflict. `project health` names the condition and the command that resolves it.

**Adopt-copy** gives a copy a new ProjectId and Namespace. Accepted objects transfer through OpenAEVC's object exchange, so the copy's history is verified on import. Imported objects are inert history: they verify and appear in no Baseline list. The operation is journaled, so a crash resolves one way or the other through `recover apply`.

Schema versions of the registry and the product database are independent. A newer unsupported schema stops startup and is not modified.

Layout: [Project format](../reference/project-format.md). Decision record: [ADR 0010](../adr/0010-cross-store-identity.md).
