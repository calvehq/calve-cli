# ADR 0002: Calve product state is separate

Status: Accepted for the initial implementation.

Project-local `.calve/product.sqlite3` stores Calve IDs, labels, intent/task organization, review records, preferences, and product events. Machine-local `workspace.sqlite3` stores Workspace membership and canonical Project registrations. OpenAEVC persists ChangePacks, executions, evidence, promotion, immutable objects, and Baselines in its own runtime store.

Calve indexes protocol object IDs only for product navigation and reads current protocol objects through the SDK. Product databases use numbered migrations; a newer unsupported schema stops startup. A copied Project with an existing registered identity is readable but cannot be changed through the CLI until its identity is resolved.
