# Authority

OpenAEVC owns principals, capability grants, revocations, and authorization decisions. Calve reads those records and submits signed grant and revoke operations through OpenAEVC.

Use `calve authority principals` to find principal IDs and `calve authority grants` to inspect the current grants. `calve authority show <principal-or-grant-id>` retrieves a current record. A revoked grant remains in the list with `revoked: true` for auditability.

`calve authority explain <action>` asks OpenAEVC whether the current principal can perform an action. Add `--principal <id>` to inspect another principal. To check a specific resource, supply `--resource-kind`, `--resource-locator`, and `--extension` together. The `decision` field is OpenAEVC's result; `related_grants`, `matching_grants`, `revocations`, and `grant_limits` provide context. A grant shown in `related_grants` does not imply permission for the requested action or resource.

Grant creation is previewed by default:

```sh
calve authority grant <principal-id> --action object.read --expires-at 2027-01-01T00:00:00Z
```

The preview shows the proposed grant, the issuer's current `grant.issue` decision, and `broad_scope`. It does not submit a grant. Review the actions, resource selector, validity window, and delegation depth, then repeat the command with `--apply` to issue it. Omit `--resource-kind` for all resource kinds, or use `--resource-kind <kind> [--locator-prefix <prefix>]` to narrow it. An action of `*` or an unrestricted resource selector sets `broad_scope: true`. OpenAEVC performs the final authorization and validates delegated grants.

Revoke with `calve authority revoke <grant-id> [--reason <text>]`. The resulting grant record shows `revoked: true`. A revocation does not remove its audit history.

Local reviewer or agent identities can be created with `calve authority identity-add <name>`, listed with `calve authority identities`, and removed with `calve authority identity-remove <name>`. Use the global `--as <name>` option to act with a local identity's key. Identity creation issues a scoped OpenAEVC grant; removal revokes the identity's active grants. The key is stored in the Project's private `.calve/identities` directory.
