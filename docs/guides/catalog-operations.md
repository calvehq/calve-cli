# Catalog operations

A catalog is a TUF repository. This guide is for users of one; publishers should read the [publishing guide](https://github.com/calvehq/calve-extensions/blob/main/docs/publishing.md).

## Add

```sh
calve extension catalog add <name> <https-url-or-dir> --root root.json --root-digest <sha256>
```

The digest anchors everything, so get it from the publisher out of band. It is pinned for the life of the catalog.

## Keep fresh

```sh
calve extension catalog list          # fresh | stale | expired | recovery_required
calve extension catalog refresh [name]
```

Installs and updates need a Fresh catalog. A package's revocation data goes stale after `revocation_max_age`, seven days by default.

## Install and update

```sh
calve extension search [query]
calve extension install <id> --acknowledge-native
calve extension update <id> --acknowledge-native     # in a Project
```

The first install of an id pins its publisher. Moving to another publisher is a deliberate step:

```sh
calve extension switch-publisher <id> --catalog <name> --yes --acknowledge-native
```

## When trust state breaks

Calve never falls back to older state. Damaged or inconsistent state is `recovery_required`, and a refresh is the first thing to try.

If the publisher has rotated its root beyond what a refresh can follow, or the state cannot be restored, reset with a root you obtained out of band:

```sh
calve extension catalog reset <name> --root new-root.json --root-digest <sha256> --yes --i-understand-rollback-risk
```

The reset is audited. It discards rollback protection, so a mirror could then serve you older metadata that is still validly signed. Treat it as a security decision.

## Remove

```sh
calve extension catalog remove <name>
```

Trust model: [catalog trust](../reference/catalog-trust.md).
