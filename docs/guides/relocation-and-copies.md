# Relocation and copies

## Moved a Project

Move the directory, then tell Calve. The old path must no longer exist.

```sh
mv ~/work/hello ~/projects/hello
calve project relocate <project-id> ~/projects/hello
```

Identity is unchanged, and so is all history.

## Copied a Project

A copy has the same identity as the original, so Calve blocks writes to it (`project health` reports `duplicate_copy`). Make it a Project of its own:

```sh
calve project adopt-copy /path/to/copy --name "Hello copy"
```

The copy gets a new ProjectId and Namespace. Accepted objects are transferred through OpenAEVC's object exchange and verified. They are inert history: they verify, and they appear in no Baseline list of the new Project.

An execution that was active in the copied state is not continued in the new Project. If the process is interrupted, `calve recover apply --yes` finishes or restores it.

## Something looks wrong

```sh
calve project health <project-id-or-path>
```

The result is one of `healthy`, `missing_path`, `relocation_needed`, `duplicate_copy`, `identity_conflict`, `name_out_of_sync`, `unregistered` or `invalid_project`, with an explanation of the condition.

Pass the path you are looking at, so Calve can tell it apart from the registered path. An unregistered Project is fixed with `calve project register <path>`.
