# Console

`calve console` is a terminal client of the same API as the CLI. `calve-console` depends only on `calve-api` and `calve-client`, so it cannot reach the product store or OpenAEVC; `check-architecture` enforces that.

The console is split into a state engine and a thin terminal loop:

- **State** (`Route`, screens, selection) takes events and produces commands. It has no terminal, so tests drive it directly, including against a real `calved`.
- **Rendering** is a pure function of state, memoized per table and windowed to the visible rows.
- **Input** maps keys to typed actions.

**No private powers.** Every change is a typed command through the same client, authority and audit path as the CLI. A confirmation dialog is the `--yes`. Promotion confirms using the backend's own preflight, and the T2 acknowledgment is given only by Enter in a dialog that quotes the backend's text. There is deliberately no `confirm_destructive` setting.

**Bounded by construction.** Lists are loaded in keyset pages, execution output keeps the last 2,000 lines and says so, and a refresh keeps your selection by identity through inserts, deletes and reordering.

**Disconnected is a state.** If the daemon goes away, the console shows it, keeps what it had marked stale, and reconnects without losing your place (Scenario O).

All terminal output passes through a sanitizer, because pack titles and worker output are untrusted text.

More: [console reference](../reference/console.md).
