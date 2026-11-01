# Console

`calve console` opens the terminal control surface. It draws at once while it connects to `calved` (starting it unless `--no-daemon-start`), reads purpose-built read models through the Calve API, and never touches the product store or OpenAEVC directly. Everything it changes goes through the same typed commands, authorization, confirmations and audit as the CLI.

**Layout.** At 120 columns or wider: Navigation, Workspace and Inspector panes (Ctrl+B hides Navigation). From 90 to 119: Workspace and Inspector (Ctrl+B hides the Inspector), navigation as an overlay (`g`). Below 90: one pane at a time; Enter moves inward and Esc outward. Tabs that do not fit scroll (‹ ›).

**Health.** The top bar shows `○ connecting`, `● healthy` (over the daemon, or `healthy · in-process`), `! degraded` (recovery, extension or provider problems reported by status), `! daemon disconnected` or `× offline`. Without a live backend the last data stays readable, marked `STALE · last update Ns ago`, and actions are disabled. With no Project open, the Projects screen welcomes you and Enter opens a registered Project.

**Screens.** Overview (needs attention, active work, recent activity; Enter opens each item's own context, e.g. a failed check's Verify tab), Work, Change Graph, ChangePacks, Baselines, Evidence, Events, Projects, Inbox (each recovery item offers its remedy), Doctor (PASS only for what it checked), Extensions (with trusted catalogs and their fresh/stale/expired state). A ChangePack opens a workstation with Summary, Diff, Verify, Risk, Evidence, Review, Receipts, Events and Raw tabs and an inspector with Summary/Relations/Eligibility/Raw tabs (`[` `]`); a Baseline has Graph, Packs, Relations, History, Explain and Raw; an Execution has Summary, Output, Observations, Effects, Events and Raw.

**Large Projects.** ChangePacks and Evidence load keyset pages ahead of the selection and say how much is loaded of the total; a `/` filter loads every page so it is never answered from part of a list. Lists, diffs and logs format only the visible window; execution output shows its newest lines and names `calve execution logs` for the rest.

**Keys.**

| Key | Meaning |
|---|---|
| `j`/`k`, arrows, `gg`/`G` | Move, first, last |
| `h`/`l` | Move between panes, or between graph nodes |
| Enter / Esc | Open / back (Esc also clears filters, closes overlays and the drawer) |
| Tab, `1`–`9` | Next tab, jump to tab (on a graph, Tab steps through nodes) |
| `/` | Filter: words (fuzzy), `field:value`, globs (`type:verification.*`), times (`updated:<1h`, `created:>2d`, `after:1h`, `before:2026-10-01`); a field the list lacks is named. On diffs, logs and raw views `/` searches and `n`/`N` move between matches |
| Ctrl+P | Palette: Projects, packs, Baselines, intents, tasks, executions, evidence, events; the found object's own actions; Tab switches All/Objects/Actions/Commands |
| `:` | Command mode with CLI grammar, plus `:pack <id>`, `:verify <pack>`, `:task blocked`, `:project <name>`, `:events actor=codex` |
| `a` | Actions for the selection; unavailable ones show why. Keys no binding claims run the listed action directly (`v` verify, `c` check, `r` review, `p` promote, …) |
| `x` | Explain: satisfied and missing conditions from OpenAEVC policy and results |
| `r` | Review on a reviewable pack, rerun on Verify, otherwise refresh (F5 always refreshes) |
| `e` | ChangePack evidence; on a graph, the next relationship (Enter explains it) |
| `f` | Events live mode / execution output follow; on a graph, neighborhood depth 1, 2, all |
| `w`, `t` | Wrap, output timestamps |
| Space | Mark rows; bulk actions state the count |
| `y` | Copy the reference (ID, digest, file path, output, raw document) |
| Ctrl+L | Activity drawer: console actions and daemon events |
| Alt+←/→, Backspace | History |
| `?` / `q` | Help for this screen / close the innermost layer, then quit (warns while commands run) |

Mouse: click to select, double-click to open, click an inspector action to run it, right-click a row for its actions, scroll wheel.

Destructive actions (promote, abandon, reopen, quarantine, rollback, resolve, uninstall, `--apply`, …; a rejection is confirmed by submitting its form) always confirm, stating the target, the consequence, eligibility, the affected Baseline and, for promotion, the backend's own preflight. A native (T2) extension refused for lack of acknowledgment asks for it in a dialog; only Enter re-issues with `--acknowledge-native`. A command rejected for stale state is explained and never retried silently. All backend text is sanitized before display; pasted text never submits a command.

**Preferences.** `calve config set console.theme dark|light|high-contrast|mono`, `console.mouse`, `console.unicode`, `console.show_footer` (`true|false`), `console.wrap_logs`, `console.time relative|absolute|both`, `console.diff_context 0–50`. There is no `confirm_destructive`: confirmations are the `--yes` of destructive commands. `NO_COLOR`, `--no-color` or `ui.color = never` select the monochrome theme; ASCII mode replaces every non-ASCII glyph, including borders.
