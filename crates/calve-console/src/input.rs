//! Input mapping and state updates (console-ux §9, §66). Keys become state changes or typed
//! requests; nothing here talks to the backend directly.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use serde_json::Value;

use crate::graph::{self, Direction};
use crate::model::{
    App, Focus, Hit, Overlay, PaletteItem, Request, ReviewForm, Route, Target, Width,
    detail_request, nav_routes, parse_action, route_requests,
};
use crate::screens::{self, Body, Screen, Table, visible_rows};
use crate::theme::Tone;

/// Resolves the selected row of a table by identity, falling back to the nearest neighbour.
pub fn selection(app: &App, table: &Table) -> Option<usize> {
    let rows = visible_rows(app, table);
    if rows.is_empty() {
        return None;
    }
    let state = app.collections.get(&table.key);
    let by_id = state
        .and_then(|c| c.selected_id.as_ref())
        .and_then(|id| rows.iter().position(|row| &row.id == id));
    Some(by_id.unwrap_or_else(|| state.map_or(0, |c| c.selected_index).min(rows.len() - 1)))
}

/// Keeps stored selection aligned with current rows and loads inspector detail (§4.4, §16).
pub fn sync(app: &mut App) {
    let screen = screens::build(app);
    match &screen.body {
        Body::Table(table) => {
            if app.route == Route::Events
                && app.events_live
                && let Some(first) = visible_rows(app, table).first()
            {
                let id = first.id.clone();
                let state = app.collection(&table.key);
                state.selected_id = Some(id);
                state.selected_index = 0;
            }
            // Paged collections load ahead of the selection, and completely while a filter
            // runs, so a filter is never answered from a partial list.
            if crate::model::PAGED.iter().any(|(k, _, _)| *k == table.key) {
                let filtering = app
                    .collections
                    .get(&table.key)
                    .is_some_and(|c| !c.filter.is_empty());
                let rows = visible_rows(app, table).len();
                if filtering || selection(app, table).unwrap_or(0) + 50 >= rows {
                    app.more(&table.key);
                }
            }
            if let Some(index) = selection(app, table) {
                let id = visible_rows(app, table)[index].id.clone();
                let state = app.collection(&table.key);
                state.selected_id = Some(id.clone());
                state.selected_index = index;
                if let Some((key, action)) = detail_request(&app.route, &id)
                    && app.value(&key).is_none()
                {
                    app.request(&key, action);
                }
            }
        }
        Body::Graph(graph) => {
            let key = graph.key.clone();
            let valid = app
                .collections
                .get(&key)
                .and_then(|c| c.selected_id.as_ref())
                .is_some_and(|id| graph.nodes.iter().any(|n| &n.id == id));
            if !valid && let Some(first) = graph.nodes.first() {
                app.collection(&key).selected_id = Some(first.id.clone());
            }
        }
        Body::Diff(_) => {
            if let Route::ChangePack(id) = app.route.clone()
                && let Some(pack) = app.value(&format!("pack:{id}")).cloned()
            {
                let files = pack["files"].as_array().cloned().unwrap_or_default();
                let index = app
                    .collections
                    .get(&format!("diff-files:{id}"))
                    .map_or(0, |c| c.selected_index);
                if let Some(file) = files.get(index.min(files.len().saturating_sub(1))) {
                    let path = file["path"].as_str().unwrap_or("").to_owned();
                    let key = format!("diff:{id}:{path}");
                    if app.value(&key).is_none() {
                        app.request(
                            &key,
                            parse_action(&strings(&["view", "pack-diff", &id, &path]))
                                .expect("valid view"),
                        );
                    }
                }
            }
        }
        _ => {}
    }
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

/// Commands that change or discard authoritative state get a confirmation (§21, §60).
fn destructive(args: &[String]) -> bool {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let risky = [
        "promote",
        "abandon",
        "reject",
        "quarantine",
        "reopen",
        "revoke",
        "uninstall",
        "delete",
        "unregister",
        "disable",
        "cancel",
        "activate",
        "clear-resolved",
        "remove",
        "gc",
        "identity-remove",
    ];
    words.iter().take(3).any(|w| risky.contains(w))
        || words.contains(&"--apply")
        || words.first() == Some(&"recover") && words.get(1) == Some(&"apply")
}

/// Queues a typed command; results come back through [`on_response`].
pub fn issue(app: &mut App, label: &str, args: &[String], show_result: bool) {
    issue_with(app, label, args, show_result, false);
}

/// `confirmed`: the user accepted the confirmation dialog, which is the `--yes` of a
/// destructive command.
fn issue_with(app: &mut App, label: &str, args: &[String], show_result: bool, confirmed: bool) {
    if !app.can_act() {
        app.notify(Tone::Warning, "Offline: actions are disabled");
        return;
    }
    match parse_action(args) {
        Ok(mut action) => {
            if confirmed {
                action.acknowledge();
            }
            app.commands += 1;
            let key = format!("cmd:{}:{}:{label}", app.commands, u8::from(show_result));
            app.outbox.push(Request { key, action });
            app.notify(Tone::Running, format!("{label}…"));
        }
        Err(error) => app.notify(Tone::Danger, format!("{label}: {error}")),
    }
}

/// Serves results for both read models and commands.
pub fn on_response(app: &mut App, key: &str, result: Result<Value, String>) {
    let Some(rest) = key.strip_prefix("cmd:") else {
        app.respond(key, result);
        sync(app);
        return;
    };
    let mut parts = rest.splitn(3, ':');
    let (_, show, label) = (
        parts.next(),
        parts.next() == Some("1"),
        parts.next().unwrap_or("command"),
    );
    match result {
        Ok(value) => {
            app.notify(Tone::Success, label.to_owned());
            if show {
                app.overlays.push(Overlay::Result {
                    title: label.to_owned(),
                    value,
                });
            }
            // Derived caches for other objects may now be stale; drop them so they reload.
            let keep: Vec<String> = route_requests(&app.route)
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            app.data.retain(|k, _| {
                keep.contains(k)
                    || !(k.starts_with("pack:")
                        || k.starts_with("baseline:")
                        || k.starts_with("diff:")
                        || k.starts_with("project-health:"))
            });
            app.refresh();
            sync(app);
        }
        Err(error) => {
            // Stale state is explained, never retried silently (§61).
            if error.contains("generation") || error.contains("CONFLICT") {
                app.overlays.push(Overlay::Explain {
                    title: "State changed before your action completed".into(),
                    lines: vec![
                        (Tone::Warning, format!("{label} was not applied.")),
                        (Tone::Neutral, String::new()),
                        (Tone::Neutral, crate::text::line(&error)),
                        (Tone::Neutral, String::new()),
                        (
                            Tone::Neutral,
                            "r refresh, then review the current state before retrying.".into(),
                        ),
                    ],
                });
            } else {
                app.notify(
                    Tone::Danger,
                    format!("{label}: {}", crate::text::line(&error)),
                );
            }
        }
    }
}

fn run_target(app: &mut App, target: Target) {
    match target {
        Target::Open(route) => app.navigate(route),
        Target::Run {
            args,
            confirm,
            label,
        } => {
            if confirm {
                app.overlays.push(Overlay::Confirm {
                    title: format!("{label}?"),
                    lines: vec![
                        "This changes authoritative state and cannot be silently undone.".into(),
                        String::new(),
                        format!("calve {}", args.join(" ")),
                    ],
                    args,
                    label,
                });
            } else {
                issue(app, &label, &args, false);
            }
        }
        Target::Prompt {
            args,
            suffix,
            field,
            confirm,
            label,
        } => app.overlays.push(Overlay::Prompt {
            title: label.clone(),
            field,
            input: String::new(),
            args,
            suffix,
            confirm,
            label,
        }),
        Target::Review { pack, generation } => app.overlays.push(Overlay::Review(ReviewForm {
            pack,
            generation,
            decision: 0,
            comment: String::new(),
            field: 0,
            error: None,
        })),
        Target::Unavailable(reason) => app.notify(Tone::Warning, format!("Unavailable: {reason}")),
        Target::Command(text) => app.overlays.push(Overlay::Command {
            input: text,
            history: None,
            error: None,
            term: None,
        }),
        Target::OpenProject { root, route } => {
            app.switch_project(root);
            app.navigate(route);
        }
        Target::Select { key, id } => {
            app.collection(&key).selected_id = Some(id);
            app.graph_edge = None;
        }
    }
    sync(app);
}

/// Fuzzy score: exact id/label 0, prefix 1, substring 2, subsequence 3+gaps (§10.2).
pub fn score(query: &str, fields: &[&str]) -> Option<usize> {
    if query.is_empty() {
        return Some(10);
    }
    let query = query.to_lowercase();
    let mut best: Option<usize> = None;
    for field in fields {
        let field = field.to_lowercase();
        let score = if field == query {
            Some(0)
        } else if field.starts_with(&query) {
            Some(1)
        } else if field.contains(&query) {
            Some(2)
        } else {
            let mut chars = field.chars();
            let mut gaps = 0;
            query
                .chars()
                .all(|q| {
                    for (skipped, c) in chars.by_ref().enumerate() {
                        if c == q {
                            gaps += skipped;
                            return true;
                        }
                    }
                    false
                })
                .then_some(3 + gaps)
        };
        if let Some(score) = score {
            best = Some(best.map_or(score, |b| b.min(score)));
        }
    }
    best
}

pub fn filter_items(items: &[PaletteItem], query: &str) -> Vec<PaletteItem> {
    let mut scored: Vec<(usize, usize, PaletteItem)> = items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            score(query, &[&item.label, &item.detail]).map(|s| (s, i, item.clone()))
        })
        .collect();
    scored.sort_by_key(|(s, i, _)| (*s, *i));
    scored.into_iter().map(|(_, _, item)| item).collect()
}

/// Objects, actions, destinations and commands; groups ordered by their best match.
pub fn palette_items(app: &App, screen: &Screen, query: &str) -> Vec<PaletteItem> {
    let mut all: Vec<(usize, PaletteItem)> = Vec::new();
    let mut push = |fields: &[&str], item: PaletteItem| {
        if let Some(s) = score(query, fields) {
            all.push((s, item));
        }
    };
    let str_of = |v: &Value, k: &str| v[k].as_str().unwrap_or("").to_owned();
    for pack in app.pages("packs").items {
        let id = str_of(&pack, "id");
        push(
            &[&id, &str_of(&pack, "title")],
            PaletteItem {
                group: "Objects",
                label: format!(
                    "{} · ChangePack",
                    crate::text::short_id(&id, 16, app.symbols.ellipsis())
                ),
                detail: str_of(&pack, "title"),
                target: Target::Open(Route::ChangePack(id.clone())),
            },
        );
    }
    for baseline in app
        .value("baselines")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let id = str_of(&baseline, "id");
        push(
            &[&id, &str_of(&baseline, "label")],
            PaletteItem {
                group: "Objects",
                label: format!(
                    "{} · Baseline",
                    crate::text::short_id(&id, 16, app.symbols.ellipsis())
                ),
                detail: str_of(&baseline, "label"),
                target: Target::Open(Route::Baseline(id.clone())),
            },
        );
    }
    for task in app
        .value("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let id = str_of(&task, "id");
        push(
            &[&id, &str_of(&task, "title")],
            PaletteItem {
                group: "Objects",
                label: format!(
                    "{} · Task",
                    crate::text::short_id(&id, 16, app.symbols.ellipsis())
                ),
                detail: str_of(&task, "title"),
                target: Target::Open(Route::Task(id.clone())),
            },
        );
    }
    for action in &screen.actions {
        push(&[&action.label, &action.detail], action.clone());
    }
    for route in nav_routes() {
        let title = route.title();
        push(
            &[&title],
            PaletteItem {
                group: "Go to",
                label: title.clone(),
                detail: String::new(),
                target: Target::Open(route),
            },
        );
    }
    for (label, command) in [
        ("New intent", "intent create "),
        ("New ChangePack", "pack create "),
        ("Status", "status"),
        ("Doctor", "doctor"),
        ("Maintenance check", "maintenance check"),
    ] {
        push(
            &[label, command],
            PaletteItem {
                group: "Commands",
                label: format!(":{command}"),
                detail: label.to_owned(),
                target: Target::Command(command.to_owned()),
            },
        );
    }
    let group_rank = |group: &str, all: &[(usize, PaletteItem)]| {
        all.iter()
            .filter(|(_, i)| i.group == group)
            .map(|(s, _)| *s)
            .min()
            .unwrap_or(usize::MAX)
    };
    let order = ["Objects", "Actions", "Unavailable", "Go to", "Commands"];
    let mut groups: Vec<&str> = order.to_vec();
    if !query.is_empty() {
        groups.sort_by_key(|g| (group_rank(g, &all), order.iter().position(|o| o == g)));
    }
    let mut out = Vec::new();
    for group in groups {
        let mut items: Vec<&(usize, PaletteItem)> =
            all.iter().filter(|(_, i)| i.group == group).collect();
        items.sort_by_key(|(s, _)| *s);
        out.extend(
            items
                .into_iter()
                .take(if query.is_empty() { 6 } else { 20 })
                .map(|(_, i)| i.clone()),
        );
    }
    out
}

pub fn nav_matches(query: &str) -> Vec<Route> {
    let mut routes: Vec<(usize, usize, Route)> = nav_routes()
        .into_iter()
        .enumerate()
        .filter_map(|(i, r)| score(query, &[&r.title()]).map(|s| (s, i, r)))
        .collect();
    routes.sort_by_key(|(s, i, _)| (*s, *i));
    routes.into_iter().map(|(_, _, r)| r).collect()
}

fn command_tree() -> clap::Command {
    use clap::CommandFactory;
    #[derive(clap::Parser)]
    #[command(name = "calve", no_binary_name = true)]
    struct Line {
        #[command(subcommand)]
        action: calve_api::Action,
    }
    Line::command()
}

/// Completion candidates for the word being typed in command mode.
pub fn command_suggestions(input: &str) -> Vec<String> {
    let words: Vec<&str> = input.split_whitespace().collect();
    let completing = input.is_empty() || input.ends_with(' ');
    let (context, prefix) = if completing {
        (words.as_slice(), "")
    } else {
        (
            &words[..words.len().saturating_sub(1)],
            *words.last().unwrap_or(&""),
        )
    };
    let mut command = command_tree();
    for word in context {
        match command.find_subcommand(word) {
            Some(sub) => command = sub.clone(),
            None => return vec![],
        }
    }
    command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name().to_owned())
        .filter(|name| name.starts_with(prefix))
        .take(8)
        .collect()
}

/// Splits command-mode input into words with simple double/single quoting.
fn split_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for ch in input.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => {
                quote = Some(ch);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started || !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => {
                current.push(c);
                started = true;
            }
        }
    }
    if started || !current.is_empty() {
        words.push(current);
    }
    words
}

/// `:pack <id>`, `:baseline <id>`, `:task <id>`, `:events actor=x` navigate; anything else
/// is parsed with the CLI grammar and run as a typed request (§10.3).
fn run_command_line(app: &mut App, input: &str) -> Result<(), String> {
    let words = split_words(input);
    if words.is_empty() {
        return Ok(());
    }
    app.command_history.push(input.to_owned());
    let first = words[0].as_str();
    if words.len() == 2 && parse_action(&words).is_err() {
        let id = words[1].clone();
        let route = match first {
            "pack" | "changepack" => Some(Route::ChangePack(id)),
            "baseline" => Some(Route::Baseline(id)),
            "task" => Some(Route::Task(id)),
            "execution" => Some(Route::Execution(id)),
            _ => None,
        };
        if let Some(route) = route {
            app.navigate(route);
            return Ok(());
        }
    }
    if first == "events" && words.len() > 1 && words[1..].iter().all(|w| w.contains('=')) {
        app.navigate(Route::Events);
        app.collection("events").filter = words[1..]
            .iter()
            .map(|w| w.replacen('=', ":", 1))
            .collect::<Vec<_>>()
            .join(" ");
        return Ok(());
    }
    if let Some(route) = nav_routes()
        .into_iter()
        .find(|r| r.title().to_lowercase().replace(' ', "-") == first && words.len() == 1)
    {
        app.navigate(route);
        return Ok(());
    }
    parse_action(&words)?;
    let label = format!(":{}", words.join(" "));
    if destructive(&words) {
        app.overlays.push(Overlay::Confirm {
            title: "Run command?".into(),
            lines: vec![
                "This command changes authoritative state.".into(),
                String::new(),
                format!("calve {}", words.join(" ")),
            ],
            args: words,
            label,
        });
    } else {
        issue(app, &label, &words, true);
    }
    Ok(())
}

fn edit_text(text: &mut String, key: &KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => text.clear(),
        KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let trimmed = text.trim_end().len();
            let cut = text[..trimmed].rfind(' ').map_or(0, |i| i + 1);
            text.truncate(cut);
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) && !c.is_control() => {
            text.push(c)
        }
        KeyCode::Backspace => {
            text.pop();
        }
        _ => return false,
    }
    true
}

/// Follow-up work once the overlay stack is settled.
enum Then {
    Nothing,
    Run(Target),
    Issue {
        label: String,
        args: Vec<String>,
        show: bool,
        confirmed: bool,
    },
    CommandLine(String),
    Navigate(Route),
    Copy(String),
}

fn handle_overlay(app: &mut App, key: KeyEvent) {
    let screen = screens::build(app);
    let Some(mut overlay) = app.overlays.pop() else {
        return;
    };
    let esc = key.code == KeyCode::Esc;
    let enter = key.code == KeyCode::Enter;
    let up = key.code == KeyCode::Up
        || key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::CONTROL);
    let down = key.code == KeyCode::Down
        || key.code == KeyCode::Char('j') && key.modifiers.contains(KeyModifiers::CONTROL);
    let mut keep = true;
    let mut then = Then::Nothing;
    match &mut overlay {
        Overlay::Palette { query, selected } => {
            let items = palette_items(app, &screen, query);
            if esc {
                keep = false;
            } else if up {
                *selected = selected.saturating_sub(1);
            } else if down {
                *selected = (*selected + 1).min(items.len().saturating_sub(1));
            } else if enter {
                keep = false;
                if let Some(item) = items.get(*selected) {
                    then = Then::Run(item.target.clone());
                }
            } else if edit_text(query, &key) {
                *selected = 0;
            }
        }
        Overlay::Command {
            input,
            history,
            error,
            term,
        } => {
            if key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL) {
                // Reverse search: the typed text is the term; repeat to go further back.
                let needle = term.get_or_insert_with(|| input.clone()).clone();
                let start = history.unwrap_or(app.command_history.len());
                if let Some(index) = (0..start)
                    .rev()
                    .find(|&i| app.command_history[i].contains(&needle))
                {
                    *history = Some(index);
                    *input = app.command_history[index].clone();
                    *error = None;
                } else {
                    *error = Some(format!("no earlier command contains “{needle}”"));
                }
            } else if esc {
                keep = false;
            } else if enter {
                keep = false;
                then = Then::CommandLine(input.clone());
            } else if key.code == KeyCode::Tab {
                if let Some(first) = command_suggestions(input).first() {
                    let mut words: Vec<&str> = input.split_whitespace().collect();
                    if !input.ends_with(' ') {
                        words.pop();
                    }
                    *input = format!(
                        "{} ",
                        words
                            .into_iter()
                            .chain([first.as_str()])
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
            } else if up || down {
                let count = app.command_history.len();
                if count > 0 {
                    let next = match (*history, up) {
                        (None, true) => Some(count - 1),
                        (Some(i), true) => Some(i.saturating_sub(1)),
                        (Some(i), false) if i + 1 < count => Some(i + 1),
                        _ => None,
                    };
                    *history = next;
                    *input = next
                        .map(|i| app.command_history[i].clone())
                        .unwrap_or_default();
                }
            } else if edit_text(input, &key) {
                *error = None;
                *term = None;
            }
        }
        Overlay::Actions {
            items,
            query,
            selected,
            ..
        } => {
            let filtered = filter_items(items, query);
            if esc {
                keep = false;
            } else if up {
                *selected = selected.saturating_sub(1);
            } else if down {
                *selected = (*selected + 1).min(filtered.len().saturating_sub(1));
            } else if enter {
                keep = false;
                if let Some(item) = filtered.get(*selected) {
                    then = Then::Run(item.target.clone());
                }
            } else if let KeyCode::Char(c) = key.code
                && query.is_empty()
                && let Some(item) = items.iter().find(|i| i.detail == format!("key {c}"))
            {
                // Single-key shortcuts listed in the palette (§11).
                keep = false;
                then = Then::Run(item.target.clone());
            } else if edit_text(query, &key) {
                *selected = 0;
            }
        }
        Overlay::Navigation { query, selected } => {
            let matches = nav_matches(query);
            if esc {
                keep = false;
            } else if up {
                *selected = selected.saturating_sub(1);
            } else if down {
                *selected = (*selected + 1).min(matches.len().saturating_sub(1));
            } else if enter {
                keep = false;
                if let Some(route) = matches.get(*selected) {
                    then = Then::Navigate(route.clone());
                }
            } else if edit_text(query, &key) {
                *selected = 0;
            }
        }
        Overlay::Confirm { args, label, .. } => {
            if enter {
                keep = false;
                then = Then::Issue {
                    label: label.clone(),
                    args: args.clone(),
                    show: label.starts_with(':'),
                    confirmed: true,
                };
            } else if esc || matches!(key.code, KeyCode::Char('q' | 'n')) {
                keep = false;
            }
        }
        Overlay::Prompt {
            input,
            args,
            suffix,
            confirm,
            label,
            ..
        } => {
            if esc {
                keep = false;
            } else if enter && !input.trim().is_empty() {
                keep = false;
                let mut full = args.clone();
                full.push(input.trim().to_owned());
                full.extend(suffix.iter().cloned());
                then = Then::Run(Target::Run {
                    args: full,
                    confirm: *confirm,
                    label: label.clone(),
                });
            } else {
                edit_text(input, &key);
            }
        }
        Overlay::Review(form) => {
            let submit = key.code == KeyCode::Char('s')
                && key.modifiers.contains(KeyModifiers::CONTROL)
                || enter && form.field == 1;
            if esc {
                keep = false;
            } else if submit {
                if form.decision != 0 && form.comment.trim().is_empty() {
                    // The Calve review record keeps the reason for rejections and comments.
                    form.error = Some("A rejection or comment needs a reason.".into());
                } else {
                    keep = false;
                    let verb = ["approve", "reject", "comment"][form.decision];
                    let generation = form.generation.to_string();
                    let args = if verb == "comment" {
                        strings(&[
                            "review",
                            "comment",
                            &form.pack,
                            "--generation",
                            &generation,
                            form.comment.trim(),
                        ])
                    } else {
                        strings(&[
                            "pack",
                            verb,
                            &form.pack,
                            "--generation",
                            &generation,
                            "--reason",
                            form.comment.trim(),
                        ])
                    };
                    then = Then::Issue {
                        label: format!("Review: {verb}"),
                        args,
                        show: false,
                        confirmed: false,
                    };
                }
            } else if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
                form.field = 1 - form.field;
            } else if form.field == 0 {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        form.decision = form.decision.saturating_sub(1)
                    }
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Char(' ') => {
                        form.decision = (form.decision + 1) % 3
                    }
                    KeyCode::Enter => form.field = 1,
                    _ => {}
                }
            } else if edit_text(&mut form.comment, &key) {
                form.error = None;
            }
        }
        Overlay::Help | Overlay::Explain { .. } | Overlay::Result { .. } => {
            if esc || enter || matches!(key.code, KeyCode::Char('q' | '?' | 'x')) {
                keep = false;
            } else if key.code == KeyCode::Char('y')
                && let Overlay::Result { value, .. } = &overlay
            {
                then = Then::Copy(serde_json::to_string_pretty(value).unwrap_or_default());
            }
        }
    }
    if keep {
        app.overlays.push(overlay);
    }
    match then {
        Then::Nothing => {}
        Then::Run(target) => run_target(app, target),
        Then::Issue {
            label,
            args,
            show,
            confirmed,
        } => issue_with(app, &label, &args, show, confirmed),
        Then::CommandLine(text) => {
            if let Err(message) = run_command_line(app, &text) {
                app.overlays.push(Overlay::Command {
                    input: text,
                    history: None,
                    error: Some(message),
                    term: None,
                });
            }
            sync(app);
        }
        Then::Navigate(route) => {
            app.navigate(route);
            sync(app);
        }
        Then::Copy(text) => copy(app, text, "result"),
    }
}

/// Hands `text` to the runtime, which reports whether the clipboard took it (§52).
fn copy(app: &mut App, text: String, what: &str) {
    app.clipboard = Some(text);
    app.clipboard_label = what.to_owned();
}

/// Moves the selection of the current collection by `delta` rows (identity preserved).
fn move_selection(app: &mut App, delta: isize) {
    // Scrolling away from the newest entry pauses following (§42.3, §28).
    if app.route == Route::Events {
        app.events_live = false;
    }
    if matches!(app.route, Route::Execution(_)) && delta < 0 {
        app.log_follow = false;
    }
    let screen = screens::build(app);
    match &screen.body {
        Body::Table(table) => {
            let rows = visible_rows(app, table);
            if rows.is_empty() {
                return;
            }
            let current = selection(app, table).unwrap_or(0) as isize;
            let next = (current + delta).clamp(0, rows.len() as isize - 1) as usize;
            let id = rows[next].id.clone();
            let state = app.collection(&table.key);
            state.selected_id = Some(id);
            state.selected_index = next;
        }
        Body::Diff(_) if app.diff_lines => scroll_diff(app, delta),
        Body::Diff(_) => {
            if let Route::ChangePack(id) = &app.route {
                let count = app
                    .value(&format!("pack:{id}"))
                    .and_then(|p| p["files"].as_array())
                    .map_or(0, Vec::len);
                let state = app.collection(&format!("diff-files:{id}"));
                state.selected_index = (state.selected_index as isize + delta)
                    .clamp(0, count.saturating_sub(1) as isize)
                    as usize;
                app.diff_scroll = 0;
            }
        }
        Body::Graph(graph) => {
            let direction = if delta > 0 {
                Direction::Down
            } else {
                Direction::Up
            };
            move_graph(app, graph, direction);
        }
        Body::Text(_) | Body::Status { .. } => {
            let key = format!("text:{}", crate::model::tab_key(&app.route));
            let state = app.collection(&key);
            state.scroll = (state.scroll as isize + delta).max(0) as usize;
        }
    }
    sync(app);
}

fn move_graph(app: &mut App, graph: &screens::Graph, direction: Direction) {
    let placement = graph::layout(graph.nodes.len(), &graph.edges);
    let key = graph.key.clone();
    let current = app
        .collections
        .get(&key)
        .and_then(|c| c.selected_id.as_ref())
        .and_then(|id| graph.nodes.iter().position(|n| &n.id == id))
        .unwrap_or(0);
    if let Some(next) = graph::neighbor(&placement.positions, current, direction) {
        app.collection(&key).selected_id = Some(graph.nodes[next].id.clone());
        app.graph_edge = None;
    }
}

/// Tab / Shift+Tab: the next node in stable traversal order, among `/` matches if filtering.
fn step_graph(app: &mut App, graph: &screens::Graph, forward: bool) {
    let placement = graph::layout(graph.nodes.len(), &graph.edges);
    let filter = app
        .collections
        .get(&graph.key)
        .map(|c| c.filter.clone())
        .unwrap_or_default();
    let order: Vec<usize> = graph::traversal(&placement)
        .into_iter()
        .filter(|&n| filter.is_empty() || screens::matches_search(&graph.nodes[n].search, &filter))
        .collect();
    if order.is_empty() {
        return;
    }
    let current = app
        .collections
        .get(&graph.key)
        .and_then(|c| c.selected_id.as_ref())
        .and_then(|id| graph.nodes.iter().position(|n| &n.id == id))
        .and_then(|n| order.iter().position(|&o| o == n));
    let next = match (current, forward) {
        (Some(i), true) => (i + 1) % order.len(),
        (Some(i), false) => (i + order.len() - 1) % order.len(),
        (None, _) => 0,
    };
    app.collection(&graph.key).selected_id = Some(graph.nodes[order[next]].id.clone());
    app.graph_edge = None;
}

fn open_selected(app: &mut App) {
    let screen = screens::build(app);
    let row = match &screen.body {
        Body::Table(table) => selection(app, table).map(|i| visible_rows(app, table)[i].clone()),
        _ => None,
    };
    if let Some(row) = row {
        if app.route == Route::Projects
            && let Some(Target::OpenProject { .. }) = screen.actions.first().map(|a| &a.target)
        {
            let target = screen.actions[0].target.clone();
            run_target(app, target);
            return;
        }
        if let Some(route) = row.open {
            app.navigate(route.clone());
            // The row's native context: a tab, an intent's tasks, or the event itself (§25.2).
            if let Some(tab) = row.tab
                && let Some(index) = app.route.tabs().iter().position(|t| *t == tab)
            {
                app.set_tab(index);
            }
            if route == Route::Work
                && let Some(intent) = row.id.strip_prefix("intent:")
            {
                app.collection("work").filter = format!("intent:{intent}");
            }
            if route == Route::Events {
                app.collection("events").selected_id = Some(row.id.clone());
            }
        } else if let Some((title, lines)) = screen.detail.clone() {
            app.overlays.push(Overlay::Explain { title, lines });
        } else if app.width() != Width::Wide && app.focus == Focus::Workspace {
            app.focus = Focus::Inspector;
        }
        sync(app);
        return;
    }
    if matches!(screen.body, Body::Graph(_))
        && let Some((title, lines)) = screen.detail.clone()
    {
        // An inspected relationship opens its detail (§23).
        app.overlays.push(Overlay::Explain { title, lines });
        return;
    }
    let route = match &screen.body {
        Body::Graph(graph) => app
            .collections
            .get(&graph.key)
            .and_then(|c| c.selected_id.as_ref())
            .and_then(|id| graph.nodes.iter().find(|n| &n.id == id))
            .and_then(|n| n.open.clone()),
        _ => None,
    };
    if let Some(route) = route {
        app.navigate(route);
    } else if app.width() != Width::Wide && app.focus == Focus::Workspace {
        app.focus = Focus::Inspector;
    }
    sync(app);
}

/// The user-facing reference of the selection: what `y` copies and actions are titled with.
fn selected_id(app: &App, screen: &Screen) -> Option<String> {
    match &screen.body {
        Body::Table(table) => selection(app, table).map(|i| {
            let row = visible_rows(app, table)[i];
            row.copy.clone().unwrap_or_else(|| row.id.clone())
        }),
        Body::Diff(_) => diff_path(app),
        Body::Graph(graph) => app
            .collections
            .get(&graph.key)
            .and_then(|c| c.selected_id.clone()),
        _ => match &app.route {
            Route::ChangePack(id)
            | Route::Baseline(id)
            | Route::Task(id)
            | Route::Execution(id) => Some(id.clone()),
            _ => None,
        },
    }
}

/// The selected file of the Diff tab.
fn diff_path(app: &App) -> Option<String> {
    let Route::ChangePack(id) = &app.route else {
        return None;
    };
    let files = app.value(&format!("pack:{id}"))?["files"].as_array()?;
    let index = app
        .collections
        .get(&format!("diff-files:{id}"))
        .map_or(0, |c| c.selected_index);
    files.get(index.min(files.len().saturating_sub(1)))?["path"]
        .as_str()
        .map(str::to_owned)
}

/// Texts of the open file's diff lines.
fn diff_texts(app: &App) -> Vec<String> {
    let (Route::ChangePack(id), Some(path)) = (&app.route, diff_path(app)) else {
        return vec![];
    };
    app.value(&format!("diff:{id}:{path}"))
        .and_then(|d| d["lines"].as_array())
        .map(|lines| {
            lines
                .iter()
                .map(|l| l["text"].as_str().unwrap_or("").to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

/// Scrolls the open diff, never past its last line (§33.1).
fn scroll_diff(app: &mut App, delta: isize) {
    let last = diff_texts(app).len().saturating_sub(1) as isize;
    app.diff_scroll = (app.diff_scroll as isize + delta).clamp(0, last.max(0)) as usize;
}

/// `/` search in the open diff: the next (or previous) matching line from the current one.
fn jump_match(app: &mut App, forward: bool, include_current: bool) {
    let Some(term) = crate::render::table_key(&screens::build(app))
        .and_then(|key| app.collections.get(key))
        .map(|c| c.filter.to_lowercase())
        .filter(|t| !t.is_empty())
    else {
        return;
    };
    let hits: Vec<usize> = diff_texts(app)
        .iter()
        .enumerate()
        .filter(|(_, text)| text.contains(&term))
        .map(|(i, _)| i)
        .collect();
    let at = app.diff_scroll;
    let target = if forward {
        hits.iter()
            .find(|&&h| h > at || include_current && h == at)
            .or(hits.first())
    } else {
        hits.iter().rev().find(|&&h| h < at).or(hits.last())
    };
    match target {
        Some(&line) => {
            app.diff_scroll = line;
            app.diff_lines = true;
        }
        None => app.notify(Tone::Neutral, format!("No matches for “{term}”")),
    }
}

fn jump_hunk(app: &mut App, forward: bool) {
    let Route::ChangePack(id) = app.route.clone() else {
        return;
    };
    let Some(pack) = app.value(&format!("pack:{id}")) else {
        return;
    };
    let files = pack["files"].as_array().cloned().unwrap_or_default();
    let index = app
        .collections
        .get(&format!("diff-files:{id}"))
        .map_or(0, |c| c.selected_index);
    let Some(path) = files.get(index).and_then(|f| f["path"].as_str()) else {
        return;
    };
    let Some(diff) = app.value(&format!("diff:{id}:{path}")) else {
        return;
    };
    let hunks: Vec<usize> = diff["lines"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .filter(|(_, l)| l["kind"] == "hunk")
        .map(|(i, _)| i)
        .collect();
    let target = if forward {
        hunks.iter().find(|&&h| h > app.diff_scroll).copied()
    } else {
        hunks.iter().rev().find(|&&h| h < app.diff_scroll).copied()
    };
    if let Some(target) = target {
        app.diff_scroll = target;
    }
}

pub fn handle_key(app: &mut App, key: KeyEvent) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    if ctrl && key.code == KeyCode::Char('c') {
        if app.overlays.is_empty() && !app.filter_editing {
            app.quit = true;
        } else {
            app.overlays.clear();
            app.filter_editing = false;
        }
        return;
    }
    if !app.overlays.is_empty() {
        handle_overlay(app, key);
        return;
    }
    let screen = screens::build(app);
    if app.filter_editing {
        let Some(table_key) = crate::render::table_key(&screen).map(str::to_owned) else {
            app.filter_editing = false;
            return;
        };
        match key.code {
            KeyCode::Esc => {
                app.collection(&table_key).filter.clear();
                app.filter_editing = false;
            }
            KeyCode::Enter => {
                app.filter_editing = false;
                if matches!(screen.body, Body::Diff(_)) {
                    jump_match(app, true, true);
                }
            }
            _ => {
                let state = app.collection(&table_key);
                edit_text(&mut state.filter, &key);
            }
        }
        sync(app);
        return;
    }
    if let Some(pending) = app.pending_key.take()
        && key.code == KeyCode::Char('c')
    {
        jump_hunk(app, pending == ']');
        return;
    }
    // `[console.keys]` remaps translate to the default key; a remapped-away default is inert.
    let key = match key.code {
        KeyCode::Char(c) if !ctrl => match app.keymap.get(&c) {
            Some('\0') => return,
            Some(default) => KeyEvent::new(KeyCode::Char(*default), key.modifiers),
            None => key,
        },
        _ => key,
    };
    if key.code == KeyCode::Char('s')
        && let Body::Table(table) = &screen.body
        && table.sections.len() == 1
    {
        // Cycle: column 1 asc, column 1 desc, column 2 asc, ... then unsorted.
        let columns = table.sections[0].columns.len();
        let state = app.collection(&table.key);
        state.sort = match state.sort {
            None => Some((0, false)),
            Some((col, false)) => Some((col, true)),
            Some((col, true)) if col + 1 < columns => Some((col + 1, false)),
            Some(_) => None,
        };
        let label = match state.sort {
            Some((col, desc)) => format!(
                "Sorted by {} {}",
                table.sections[0].columns[col].title,
                if desc { "descending" } else { "ascending" }
            ),
            None => "Unsorted".into(),
        };
        app.notify(Tone::Neutral, label);
        return;
    }
    let on_tabs = !app.route.tabs().is_empty();
    let diff = matches!(screen.body, Body::Diff(_));
    match key.code {
        KeyCode::Char('q') => {
            if app.fullscreen {
                app.fullscreen = false;
            } else {
                app.quit = true;
            }
        }
        KeyCode::Char('?') => app.overlays.push(Overlay::Help),
        KeyCode::Char('p') if ctrl => {
            for (key, action) in [
                ("packs", &["view", "packs"][..]),
                ("baselines", &["baseline", "list"][..]),
                ("tasks", &["task", "list"][..]),
            ] {
                if app.value(key).is_none() {
                    app.request(
                        key,
                        parse_action(&strings(action)).expect("valid index request"),
                    );
                }
            }
            app.overlays.push(Overlay::Palette {
                query: String::new(),
                selected: 0,
            });
        }
        KeyCode::Char('l') if ctrl => {
            app.drawer = !app.drawer;
            // The drawer shows recent daemon events next to console actions (§43).
            if app.drawer {
                app.request(
                    "events",
                    parse_action(&strings(&["activity"])).expect("valid"),
                );
            }
        }
        KeyCode::Char(':') => app.overlays.push(Overlay::Command {
            input: String::new(),
            history: None,
            error: None,
            term: None,
        }),
        KeyCode::Char('/') if crate::render::table_key(&screen).is_some() => {
            app.filter_editing = true;
        }
        KeyCode::Char('g') if !ctrl && let Body::Graph(graph) = &screen.body => {
            app.overlays.push(Overlay::Actions {
                title: "Go to node".into(),
                items: graph
                    .nodes
                    .iter()
                    .map(|n| PaletteItem {
                        group: "Nodes",
                        label: n.label.clone(),
                        detail: n.id.clone(),
                        target: Target::Select {
                            key: graph.key.clone(),
                            id: n.id.clone(),
                        },
                    })
                    .collect(),
                query: String::new(),
                selected: 0,
            })
        }
        KeyCode::Char('f') if matches!(screen.body, Body::Graph(_)) => {
            app.graph_depth = match app.graph_depth {
                None => Some(1),
                Some(1) => Some(2),
                _ => None,
            };
        }
        KeyCode::Char('e') if matches!(screen.body, Body::Graph(_)) => {
            app.graph_edge = Some(app.graph_edge.map_or(0, |i| i + 1));
        }
        KeyCode::Tab | KeyCode::BackTab
            if app.focus == Focus::Workspace && let Body::Graph(graph) = &screen.body =>
        {
            step_graph(app, graph, key.code == KeyCode::Tab);
        }
        KeyCode::Char('g') if !ctrl => app.overlays.push(Overlay::Navigation {
            query: String::new(),
            selected: 0,
        }),
        KeyCode::Char('a') => {
            if !app.can_act() {
                app.notify(Tone::Warning, "Offline: actions are disabled");
            } else if screen.actions.is_empty() {
                app.notify(Tone::Neutral, "No actions for this selection");
            } else {
                let title = selected_id(app, &screen)
                    .map(|id| crate::text::short_id(&id, 20, app.symbols.ellipsis()))
                    .unwrap_or_else(|| app.route.title());
                app.overlays.push(Overlay::Actions {
                    title,
                    items: screen.actions.clone(),
                    query: String::new(),
                    selected: 0,
                });
            }
        }
        KeyCode::Char('x') => match &screen.explain {
            Some((title, lines)) => app.overlays.push(Overlay::Explain {
                title: title.clone(),
                lines: lines.clone(),
            }),
            None => app.notify(Tone::Neutral, "Nothing to explain here"),
        },
        KeyCode::Char('z') => app.fullscreen = !app.fullscreen,
        KeyCode::Char('y') => match selected_id(app, &screen) {
            Some(id) => copy(
                app,
                id.clone(),
                &crate::text::short_id(&id, 24, app.symbols.ellipsis()),
            ),
            None => app.notify(Tone::Warning, "Nothing selected to copy"),
        },
        // Verify tab (§94.4): r reruns verification, e shows the evidence it produced.
        KeyCode::Char('r') if app.tab_name() == Some("Verify") => {
            match screen.actions.iter().find(|a| {
                matches!(&a.target, Target::Run { args, .. } if args.get(1).map(String::as_str) == Some("verify"))
            }) {
                Some(item) => run_target(app, item.target.clone()),
                None => app.notify(Tone::Warning, "Rerun is not available in this state"),
            }
        }
        KeyCode::Char('e') if app.tab_name() == Some("Verify") => {
            if let Some(index) = app.route.tabs().iter().position(|t| *t == "Evidence") {
                app.set_tab(index);
                sync(app);
            }
        }
        KeyCode::Char('r') if app.tab_name() == Some("Review") => {
            if let Some(item) = screen
                .actions
                .iter()
                .find(|a| matches!(a.target, Target::Review { .. }))
            {
                run_target(app, item.target.clone());
            } else {
                app.notify(Tone::Warning, "Review is available once the pack is sealed");
            }
        }
        KeyCode::Char('r') | KeyCode::F(5) => {
            app.refresh();
            app.notify(Tone::Neutral, "Refreshing");
        }
        KeyCode::Char('v') if matches!(screen.body, Body::Graph(_)) || app.graph_list => {
            app.graph_list = !app.graph_list;
            sync(app);
        }
        KeyCode::Char('w') if diff => app.diff_wrap = !app.diff_wrap,
        KeyCode::Char('f') if app.route == Route::Events => {
            app.events_live = !app.events_live;
            sync(app);
        }
        KeyCode::Char('f') if matches!(app.route, Route::Execution(_)) => {
            app.log_follow = !app.log_follow;
        }
        KeyCode::Char(']') | KeyCode::Char('[') if diff => {
            app.pending_key = Some(if key.code == KeyCode::Char(']') {
                ']'
            } else {
                '['
            })
        }
        KeyCode::Char('J') if diff => scroll_diff(app, 1),
        KeyCode::Char('K') if diff => scroll_diff(app, -1),
        KeyCode::Char('d') if ctrl && diff => scroll_diff(app, 20),
        KeyCode::Char('u') if ctrl && diff => scroll_diff(app, -20),
        KeyCode::Char('n') if diff => jump_match(app, true, false),
        KeyCode::Char('N') if diff => jump_match(app, false, false),
        KeyCode::Enter if diff && app.focus == Focus::Workspace => app.diff_lines = true,
        KeyCode::Char(' ') => {
            if let Body::Table(table) = &screen.body
                && let Some(index) = selection(app, table)
            {
                let id = visible_rows(app, table)[index].id.clone();
                let state = app.collection(&table.key);
                if !state.marked.remove(&id) {
                    state.marked.insert(id);
                }
                let count = app
                    .collections
                    .get(&table.key)
                    .map_or(0, |c| c.marked.len());
                app.notify(Tone::Neutral, format!("{count} selected"));
            }
        }
        KeyCode::Char(c @ '1'..='9') if on_tabs => {
            app.set_tab(c as usize - '1' as usize);
            sync(app);
        }
        KeyCode::Tab | KeyCode::BackTab => {
            let back = key.code == KeyCode::BackTab;
            if on_tabs && app.focus != Focus::Navigation {
                let count = app.route.tabs().len();
                let next = if back {
                    (app.tab() + count - 1) % count
                } else {
                    app.tab() + 1
                };
                app.set_tab(next);
            } else {
                app.focus = match (app.focus, back, app.width()) {
                    (Focus::Navigation, false, _) => Focus::Workspace,
                    (Focus::Workspace, false, _) => Focus::Inspector,
                    (Focus::Inspector, false, Width::Wide) => Focus::Navigation,
                    (Focus::Inspector, false, _) => Focus::Workspace,
                    (Focus::Navigation, true, _) => Focus::Inspector,
                    (Focus::Workspace, true, Width::Wide) => Focus::Navigation,
                    (Focus::Workspace, true, _) => Focus::Inspector,
                    (Focus::Inspector, true, _) => Focus::Workspace,
                };
            }
            sync(app);
        }
        KeyCode::Left if alt => {
            app.go_back();
            sync(app);
        }
        KeyCode::Right if alt => {
            app.go_forward();
            sync(app);
        }
        KeyCode::Backspace => {
            app.go_back();
            sync(app);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.focus == Focus::Navigation {
                app.nav_index = (app.nav_index + 1).min(nav_routes().len() - 1);
            } else if app.focus == Focus::Inspector {
                app.collection("inspector").scroll += 1;
            } else {
                move_selection(app, 1);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.focus == Focus::Navigation {
                app.nav_index = app.nav_index.saturating_sub(1);
            } else if app.focus == Focus::Inspector {
                let state = app.collection("inspector");
                state.scroll = state.scroll.saturating_sub(1);
            } else {
                move_selection(app, -1);
            }
        }
        KeyCode::PageDown => move_selection(app, 10),
        KeyCode::PageUp => move_selection(app, -10),
        KeyCode::Home => move_selection(app, -100_000),
        KeyCode::End | KeyCode::Char('G') => move_selection(app, 100_000),
        KeyCode::Right | KeyCode::Char('l') => {
            if let Body::Graph(graph) = &screen.body
                && app.focus == Focus::Workspace
            {
                move_graph(app, graph, Direction::Right);
            } else {
                app.focus = match app.focus {
                    Focus::Navigation => Focus::Workspace,
                    _ => Focus::Inspector,
                };
            }
            sync(app);
        }
        KeyCode::Left | KeyCode::Char('h') => {
            if let Body::Graph(graph) = &screen.body
                && app.focus == Focus::Workspace
            {
                move_graph(app, graph, Direction::Left);
            } else {
                app.focus = match (app.focus, app.width()) {
                    (Focus::Inspector, _) => Focus::Workspace,
                    (_, Width::Medium) => {
                        app.overlays.push(Overlay::Navigation {
                            query: String::new(),
                            selected: 0,
                        });
                        Focus::Workspace
                    }
                    _ => Focus::Navigation,
                };
            }
            sync(app);
        }
        KeyCode::Enter => {
            if app.focus == Focus::Navigation {
                if let Some(route) = nav_routes().get(app.nav_index).cloned() {
                    app.navigate(route);
                    app.focus = Focus::Workspace;
                }
                sync(app);
            } else {
                open_selected(app);
            }
        }
        KeyCode::Esc => {
            // Outward, one step at a time (§9.1).
            if let Some(key) = crate::render::table_key(&screen).map(str::to_owned)
                && !app.collection(&key).filter.is_empty()
            {
                app.collection(&key).filter.clear();
            } else if app.fullscreen {
                app.fullscreen = false;
            } else if diff && app.diff_lines {
                app.diff_lines = false;
            } else if app.focus == Focus::Inspector {
                app.focus = Focus::Workspace;
            } else if matches!(
                app.route,
                Route::ChangePack(_) | Route::Baseline(_) | Route::Task(_) | Route::Execution(_)
            ) {
                if !app.go_back() {
                    let section = app.route.section();
                    app.navigate(section);
                }
            } else if app.width() == Width::Narrow && app.focus == Focus::Workspace {
                app.focus = Focus::Navigation;
            }
            sync(app);
        }
        _ => {}
    }
}

/// Bracketed paste (§72): text lands in the focused field as one line and never submits.
pub fn handle_paste(app: &mut App, pasted: &str) {
    let text = crate::text::line(pasted);
    let field = match app.overlays.last_mut() {
        Some(Overlay::Command { input, .. })
        | Some(Overlay::Prompt { input, .. })
        | Some(Overlay::Palette { query: input, .. })
        | Some(Overlay::Actions { query: input, .. })
        | Some(Overlay::Navigation { query: input, .. }) => Some(input),
        Some(Overlay::Review(form)) if form.field == 1 => Some(&mut form.comment),
        Some(_) => None,
        None if app.filter_editing => {
            let screen = screens::build(app);
            crate::render::table_key(&screen)
                .map(str::to_owned)
                .map(|key| &mut app.collection(&key).filter)
        }
        None => None,
    };
    if let Some(field) = field {
        field.push_str(&text);
    }
    sync(app);
}

pub fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    if !app.overlays.is_empty() {
        return;
    }
    match mouse.kind {
        MouseEventKind::ScrollDown => move_selection(app, 3),
        MouseEventKind::ScrollUp => move_selection(app, -3),
        MouseEventKind::Down(MouseButton::Left) => {
            let hit = app
                .hits
                .borrow()
                .iter()
                .find(|(rect, _)| {
                    rect.x <= mouse.column
                        && mouse.column < rect.x + rect.width
                        && rect.y <= mouse.row
                        && mouse.row < rect.y + rect.height
                })
                .map(|(_, hit)| hit.clone());
            let double = app.last_click.is_some_and(|(tick, x, y)| {
                app.tick.saturating_sub(tick) <= 4 && x == mouse.column && y == mouse.row
            });
            app.last_click = Some((app.tick, mouse.column, mouse.row));
            match hit {
                Some(Hit::Nav(index)) => {
                    app.nav_index = index;
                    if let Some(route) = nav_routes().get(index).cloned() {
                        app.navigate(route);
                    }
                }
                Some(Hit::Tab(index)) => app.set_tab(index),
                Some(Hit::Row { key, id }) => {
                    app.focus = Focus::Workspace;
                    app.collection(&key).selected_id = Some(id);
                    if double {
                        open_selected(app);
                    }
                }
                None => {}
            }
            sync(app);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ids_outrank_fuzzy_matches() {
        assert_eq!(score("cpk_184", &["cpk_184"]), Some(0));
        assert_eq!(score("cpk", &["cpk_184"]), Some(1));
        assert_eq!(score("184", &["cpk_184"]), Some(2));
        assert!(score("c1", &["cpk_184"]).unwrap() >= 3);
        assert_eq!(score("zz", &["cpk_184"]), None);
    }

    #[test]
    fn command_words_respect_quotes() {
        assert_eq!(
            split_words("intent create \"Ship it\""),
            vec!["intent", "create", "Ship it"]
        );
        assert_eq!(split_words("a  'b c' d"), vec!["a", "b c", "d"]);
        assert!(destructive(&strings(&["pack", "promote", "x"])));
        assert!(!destructive(&strings(&["pack", "list"])));
        assert!(command_suggestions("pa").contains(&"pack".to_owned()));
        assert!(command_suggestions("pack s").iter().any(|s| s == "seal"));
    }
}
