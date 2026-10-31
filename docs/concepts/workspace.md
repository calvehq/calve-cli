# Workspace

A Workspace is a local grouping of Projects on one machine. It holds an ordered list of ProjectIds and an optional default Project, and nothing else: no change state and no copy of any Project.

A Project can belong to several Workspaces. Removing one from a Workspace, or deleting a Workspace, only edits the registry; Project data stays on disk. Calve creates a `default` Workspace on first use.

Workspaces also scope configuration: a Workspace's config applies between the global and Project layers. See [configuration](../reference/config.md).

Workspaces are not shared. Nothing about them leaves the machine, and they are not a team or permission boundary. Authority lives in each Project's OpenAEVC Namespace.

More: [workspaces reference](../reference/workspaces.md).
