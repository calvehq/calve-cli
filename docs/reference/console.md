# Console

`calve console` opens the terminal control surface. It connects to `calved` (starting it unless `--no-daemon-start`), reads purpose-built read models through the Calve API, and never touches the product store or OpenAEVC directly.

**Layout.** At 120 columns or wider: Navigation, Workspace and Inspector panes. From 90 to 119: Workspace and Inspector, with navigation as an overlay (`g`). Below 90: one pane at a time, where Enter moves inward and Esc outward. The top bar shows the Project, Workspace, route and backend health (`healthy` over the daemon, `local` in-process, `offline` with cached data marked STALE and actions disabled).

**Screens.** Overview (needs attention, active work, recent activity), Work, Change Graph, ChangePacks, Baselines, Evidence, Events, Projects, Inbox, Doctor, Extensions. A ChangePack opens a workstation with Summary, Diff, Verify, Risk, Evidence, Review, Receipts, Events and Raw tabs; a Baseline has Graph, Packs, Relations, History, Explain and Raw; an Execution has Summary, Output, Observations, Effects, Events and Raw.

**Keys.**

| Key | Meaning |
|---|---|
| `j`/`k`, arrows | Move |
| `h`/`l` | Move between panes, or between graph nodes |
| Enter / Esc | Open / back (Esc also clears filters and closes overlays) |
| Tab, `1`–`9` | Next tab, jump to tab |
| `/` | Filter; `field:value` tokens such as `state:sealed`, `actor:codex` |
| Ctrl+P | Palette: objects, actions, destinations, commands |
| `:` | Command mode using CLI grammar, e.g. `:pack <id>`, `:events actor=codex`, `:intent create "Goal"` |
| `a` | Actions for the selection; unavailable ones show why |
| `x` | Explain: satisfied and missing conditions from OpenAEVC policy and results |
| `r` | Refresh (on the Review tab: begin review) |
| `z` | Fullscreen |
| `]c` / `[c`, `w`, `J`/`K` | Diff: next/previous hunk, wrap, scroll |
| `v` | Graph/list toggle |
| `y` | Copy the selected ID (OSC 52) |
| Ctrl+L | Activity drawer |
| Alt+←/→, Backspace | History |
| `?` / `q` | Help / quit |

Destructive actions (promote, abandon, reject, reopen, quarantine, uninstall, `--apply`, …) always confirm and show the exact command. A command rejected for stale state is explained and never retried silently. All backend text is sanitized before display.

**Preferences.** `calve config set console.theme dark|light|high-contrast|mono`, `console.mouse true|false`, `console.unicode true|false`. `NO_COLOR`, `--no-color` or `ui.color = never` select the monochrome theme; ASCII mode replaces every non-ASCII glyph, including borders.
