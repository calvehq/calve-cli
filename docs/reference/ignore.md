# Resource ignore rules

Put `.calveignore` at the Project root to control first-party software resource discovery. Rules are evaluated in file order; the last matching rule wins. The file must be UTF-8, at most 64 KiB, and contain at most 512 rules. Calve does not read `.gitignore` or depend on Git.

```text
# Comments begin with #
*.log
!keep.log
build/
/private.txt
src/**/generated?.rs
\#literal-name
```

`*` matches any number of characters within one path segment, `?` matches one character within a segment, and `**` crosses directory separators. `**/` also matches zero directory levels. An unprefixed pattern can match at any directory level; `/` at the start anchors it to the Project root. A trailing `/` limits a rule to directories and everything below them. `!` at the start negates an earlier ignore rule. Use `\` to treat the following special character literally, including `#`, `!`, `*`, and `?`. Blank lines and lines starting with `#` are ignored. Paths are normalized to `/` separators for matching.

Calve always excludes `.calve/`. The software integration also defaults to excluding `.git/`, `target/`, `node_modules/`, and `.venv/`; `.calveignore` rules can override these defaults. An ignored directory is not traversed during a scan, so a negation for a child also needs a rule that makes its parent directory visible. Explicit `pack capture <path>` is allowed for ignored files outside `.calve`.

Use `calve ignore check <relative-path>` to see whether a path is ignored and which source, line, and pattern decided it. A trailing `/` checks a directory path even if it does not exist yet.

`calve ignore list` shows every effective rule with its source: hard safety (`.calve/`), software defaults (`.git/`, `target/`, `node_modules/`, `.venv/`), language defaults for languages detected at the Project root (for example `__pycache__/` for Python or `.terraform/` for HCL), and `.calveignore` lines. `calve ignore add <pattern>` and `calve ignore remove <pattern>` edit `.calveignore`; the new content is validated before it replaces the file.
