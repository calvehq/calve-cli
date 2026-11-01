# Relocation and copies

## Moved a Project

Move the directory, then tell Calve. The old path must no longer exist.

```sh
mv ~/work/hello ~/projects/hello
calve project relocate <project-id> ~/projects/hello
```

Identity is unchanged, and so is all history.

## Copied a Project

A copy has the same identity as the original, and the identity's authority stays bound to the original directory. The copy can be read, and every write is refused until you make it a Project of its own. This holds whether or not either one is registered:

```sh
calve project adopt-copy /path/to/copy --name "Hello copy"
```

The copy gets a new ProjectId and Namespace. Accepted objects are transferred through OpenAEVC's object exchange and verified. They are inert history: they verify, and they appear in no Baseline list of the new Project.

An execution that was active in the copied state is not continued in the new Project. If the process is interrupted, `calve recover apply --yes` finishes or restores it.

## Another machine

Keys never travel with the directory. A copy on another machine holds no authority there, so nothing writes to it. To carry a Project's identity across, export its authority and import it. Anyone holding that file can act as the Project.

```sh
calve project authority-export <project> authority.json --yes      # on this machine
calve project authority-import /path/to/copy authority.json        # on the other
```

**What this does not do:** nothing coordinates between machines. If you import an authority and keep using the original, there are two writers with one identity, and Calve on each machine cannot know about the other.

## Something looks wrong

```sh
calve project health <project-id-or-path>
```

The result is one of `healthy`, `missing_path`, `relocation_needed`, `duplicate_copy`, `identity_conflict`, `name_out_of_sync`, `unregistered` or `invalid_project`, with an explanation of the condition.

Pass the path you are looking at, so Calve can tell it apart from the registered path. An unregistered Project is fixed with `calve project register <path>`.
