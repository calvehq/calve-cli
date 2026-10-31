# Project

A Project is a directory with a `.calve/` folder. It has one immutable ProjectId bound to one OpenAEVC Namespace, the authority and history boundary behind it.

The directory can hold anything: a source tree, documents, or only records. What Calve understands about its contents comes from the extensions enabled in the Project, never from Calve itself.

`calve init` creates the identity, signing keys, product database and OpenAEVC store, then registers the Project on this machine. Commands find the Project by walking up from the current directory, so `--project <path-or-id>` is only needed from elsewhere.

**Identity survives moves, not copies.** A moved Project is the same Project, and `project relocate` updates the registration. A copy is not: it shares an identity with the original, so Calve blocks writes until `project adopt-copy` makes it a new Project. See [relocation and copies](../guides/relocation-and-copies.md).

The display name is mutable product metadata. Closing a Calve session, or deleting a registration, never changes what is on disk.

More: [Project format](../reference/project-format.md), [workspaces](../reference/workspaces.md).
