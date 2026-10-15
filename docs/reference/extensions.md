# Extensions and catalogs

OpenAEVC defines the extension contract, handshake and runtime authorization. Calve decides which packages to trust, install and enable. Every extension comes from a **signed TUF catalog**; nothing is bundled with Calve (decision records: ADR 0005–0007, ADR 0021; trust model: [catalog trust](catalog-trust.md)).

## Three independent gates

| Gate | Checks | Where |
|---|---|---|
| Trust | TUF verification (root pinned by SHA-256, delegations, rollback/freeze protection) plus Calve's catalog policy (ed25519 keys whose ids are the key's hash, unique key material, consistent snapshots, sha256 targets), revocations, the publisher's id policy and cross-catalog pin | `extension install` |
| Compatibility | OpenAEVC protocol/contract range, platform, `calve-integration.json` schema, CIC ABI/wire/capabilities, `describe` equal to the signed metadata | `extension install` |
| Permission | host-capability grants and the **T2 acknowledgment**: a native extension runs with your user permissions and is not confined | `extension install` / `enable` (per Project and artifact) |

## Catalogs

```sh
calve extension catalog add <name> <https-url-or-dir> --root root.json --root-digest <sha256>
calve extension catalog list            # fresh | stale | expired | recovery_required
calve extension catalog refresh [name]
calve extension catalog reset <name> --root new-root.json --root-digest <sha256> --yes --i-understand-rollback-risk
calve extension catalog remove <name>
calve extension search [query]
```

The root and its digest come from the publisher out of band. A catalog is a TUF repository with consistent snapshots; Calve's conventions are ordinary signed targets: `index.json` (ids, for search), `revocations.json` and `id-policy.json` (top-level role only), and per extension `<id>/package.json` listing versions, the package kind and the files at `<id>/<version>/<file>`.

## Packages

```sh
calve extension install <id> [--version v] [--catalog c] --acknowledge-native
calve extension list --installed
calve extension switch-publisher <id> --catalog <c> --yes --acknowledge-native
calve extension uninstall <id> [--version v]      # refused while a Project uses it
```

Two kinds: **cic-capable** (native artifact + `cic.wasm` + required `calve-integration.json`) and **openaevc-only** (native artifact, optional `calve-ui.json`). A package is installed into `<data>/packages/<id>/<artifact-sha256>/`, read-only, named by its verified digest; every install is journaled and an interrupted one converges on `calve recover apply`. The first install of an id pins its publisher (catalog and delegation chain); another catalog offering the same id is refused until `switch-publisher`.

## Per Project

```sh
calve extension enable <id> [--grant cap]... --acknowledge-native
calve extension list | info <id> | health | permissions <id>
calve extension grant <id> <cap>... | revoke <id> <cap>...
calve extension update <id> [--grant cap]... --acknowledge-native
calve extension disable <id>
```

Enabling grants nothing by default; grants and the T2 acknowledgment are recorded per extension id and artifact digest. An update that requests a new host capability installs the new package but keeps the Project on the old one, reporting `permission_widening`, until each new capability is granted. Re-registering a new version is refused (`EXTENSION_IN_USE`) while a non-terminal execution in the Project references the extension, because OpenAEVC resolves extensions per submission.

## What packages declare

A cic-capable package's signed metadata declares its domain to Calve, so Calve's host contains no domain knowledge: `files` (the file resource kind, put/delete effects, verifier, evaluator, ignore-file names), `resources` (non-file kinds for `resource set`), `checks` (the verifier for check results) and `relations` (derived relation kinds). Detection, check plans, ignore decisions, diffs, capture decisions and relations come from the package's CIC module, run in Calve's supervised sandbox ([integration contract](integration-contract.md)).
