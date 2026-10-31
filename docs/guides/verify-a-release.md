# Verify a release

Check a release before you run it. The first two checks are required. The third is independent of Calve's release key.

## 1. Checksums

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

## 2. Release-key attestations

Every file is the subject of an in-toto statement signed by Calve's ed25519 release key. From a source checkout at the release's tag:

```sh
cargo run --locked -p xtask -- verify-release --dist <download-dir> --pubkey <hex> --smoke
```

This checks every file against `SHA256SUMS`, every attestation against the key, and that no file is left unattested. `--smoke` then unpacks this host's archive into an empty directory and runs it with fresh data and config directories.

The public key is published with the release notes. Any DSSE and in-toto verifier can do the same check.

## 3. Keyless signature and provenance

`SHA256SUMS` is also signed in the release workflow, with no stored key. Verify that it came from that workflow and tag:

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/calvehq/calve-cli/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
gh attestation verify <archive> --repo calvehq/calve-cli
```

## Rebuild it yourself

Archives are built with fixed timestamps and remapped paths. With the same toolchain, target and `SOURCE_DATE_EPOCH`, `xtask dist` should produce the same bytes:

```sh
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" cargo run --locked -p xtask -- dist --target <target>
```

What this proves, and the policy behind it: [ADR 0021](../adr/0021-release-trust-policy.md).
