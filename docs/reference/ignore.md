# Ignore rules

Which paths a scan skips is decided by the enabled file package (its `classify` operation), so the rule language and built-in defaults are the package's (the software extension's `.calveignore` grammar is in the [calve-extensions docs](https://github.com/calvehq/calve-extensions/blob/main/docs/ignore.md)). Calve itself always excludes `.calve/` and never follows symlinks.

The package declares its ignore-file names; Calve reads those files (at the root and in ancestor directories of each scanned entry) and passes their text to `classify`, one directory batch at a time, so ignored directories are never traversed or hashed.

- `calve ignore check <path>`: the package's decision and the rule it reports (a trailing `/` checks a directory).
- `calve ignore list`: Calve's hard rule, then each line of the root ignore file; built-in defaults are applied by the package.
- `calve ignore add <pattern>` / `remove <pattern>`: edit the root ignore file; the package validates the new rules before the file is replaced.
