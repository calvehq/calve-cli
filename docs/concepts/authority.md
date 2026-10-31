# Authority

Authority is who may do what in a Project. OpenAEVC owns it: principals, capability grants, revocations and every authorization decision. Calve reads those records and submits signed grant and revoke operations. It does not add a permission system of its own.

Every command is signed by a principal. `--as <name>` acts with a local identity, which is how a separate reviewer or agent is set up on one machine. Identity keys live in the Project's private state.

`authority explain <action>` asks OpenAEVC whether a principal may do something, and shows the grants involved. Issuing a grant is a preview until you add `--apply`. A revoked grant stays visible, for audit.

**Host capabilities are a separate thing.** They say what an extension may ask the host to do, such as `process.execute`. You grant them per Project with `extension grant`. OpenAEVC enforces them at the call: a denied call stops the extension and fails closed, and Calve reports `CAPABILITY_DENIED` with the command that would grant it.

More: [authority](../reference/authority.md), [extensions](../reference/extensions.md).
