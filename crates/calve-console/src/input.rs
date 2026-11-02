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
                if let Some((key, action)) = detail_request(&app.route, &id) {
                    app.request_once(&key, action);
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
                    let mut words = vec!["view", "pack-diff", id.as_str(), path.as_str()];
                    let context = app.diff_context.map(|n| n.to_string());
                    if let Some(n) = &context {
                        words.extend(["--context", n.as_str()]);
                    }
                    app.request_once(&key, parse_action(&strings(&words)).expect("valid view"));
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
        "rollback",
        "resolve",
    ];
    words.iter().take(3).any(|w| risky.contains(w))
        || words.contains(&"--apply")
        || words.first() == Some(&"recover") && words.get(1) == Some(&"apply")
}

/// Baseline comparison (§40.2): members only in each side and the shared count, named by
/// pack title where a loaded Baseline view knows it.
fn compare_view(app: &App, value: &Value) -> Overlay {
    let name = |digest: &str| {
        app.data
            .iter()
            .filter(|(k, _)| k.starts_with("baseline:"))
            .filter_map(|(_, l)| l.value.as_ref())
            .flat_map(|b| b["members"].as_array().into_iter().flatten())
            .find(|m| m["digest"] == digest)
            .and_then(|m| m["title"].as_str().map(str::to_owned))
            .unwrap_or_else(|| crate::text::middle(digest, 24, app.symbols.ellipsis()))
    };
    let side = |key: &str| -> Vec<String> {
        value[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(name)
            .collect()
    };
    let left = value["left"].as_str().unwrap_or("left");
    let right = value["right"].as_str().unwrap_or("right");
    let mut lines = Vec::new();
    for (title, key) in [(left, "only_left_members"), (right, "only_right_members")] {
        lines.push((Tone::Neutral, format!("Only in {title}")));
        let names = side(key);
        if names.is_empty() {
            lines.push((Tone::Neutral, "  none".into()));
        }
        lines.extend(names.into_iter().map(|n| (Tone::Review, n)));
        lines.push((Tone::Neutral, String::new()));
    }
    let shared = value["shared_members"].as_array().map_or(0, Vec::len);
    lines.push((Tone::Neutral, format!("Shared      {shared} ChangePacks")));
    let edges = |key: &str| value[key].as_array().map_or(0, Vec::len);
    lines.push((
        Tone::Neutral,
        format!(
            "Relations   {} shared, {} only left, {} only right",
            edges("shared_edges"),
            edges("only_left_edges"),
            edges("only_right_edges")
        ),
    ));
    Overlay::Explain {
        title: format!(
            "Compare {} ↔ {}",
            crate::text::short_id(left, 14, app.symbols.ellipsis()),
            crate::text::short_id(right, 14, app.symbols.ellipsis())
        ),
        lines,
    }
}

/// What a destructive command does (§60), by command.
fn consequence(args: &[String]) -> &'static str {
    let word = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    match (word(0), word(1)) {
        ("pack", "promote") => "Creates an immutable promoted ChangePack in accepted history.",
        ("pack", "abandon") => "Closes the pack without promoting it; its history is kept.",
        ("pack", "reject") => "Records a rejecting review of the sealed candidate.",
        ("pack", "quarantine") => {
            "Blocks every further transition until the quarantine is released."
        }
        ("pack", "reopen") => {
            "Starts a new generation; checks, evaluations and reviews of this candidate become stale."
        }
        ("baseline", "activate") => {
            "Moves the active Baseline pointer; the working tree is not written."
        }
        ("baseline", "materialize") => {
            "Writes the Baseline's accepted files into the working tree."
        }
        ("execution", "cancel") => "Stops the execution; effects it has not applied are discarded.",
        ("project", "unregister") => "Forgets the registration; the Project's files are kept.",
        ("extension", "disable") => {
            "The extension's tools and providers stop working in this Project."
        }
        ("extension", "enable") => {
            "Enables the extension; it gets only the capabilities you grant."
        }
        ("extension", "update") => {
            "Installs a newer version; any widened permission needs a grant."
        }
        ("inbox", "clear-resolved") => {
            "Forgets resolved inbox items; the audit history is untouched."
        }
        ("recover", "apply") => "Applies the recovery plan to this Project.",
        _ => "This changes authoritative state and cannot be silently undone.",
    }
}

/// A confirmation that names the target, the consequence, eligibility and affected Baseline
/// it knows of, and the backend's own preflight for a promotion (§21, §60).
fn confirm_dialog(app: &mut App, title: String, args: Vec<String>, label: String) {
    let mut lines = vec![consequence(&args).to_owned(), String::new()];
    if let Some(target) = args.get(2).filter(|t| !t.starts_with('-')) {
        lines.push(format!("Target      {target}"));
    }
    let word = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    if (word(0), word(1)) == ("baseline", "activate") {
        let active = app
            .value("status")
            .and_then(|s| s["active_baseline"]["id"].as_str())
            .unwrap_or("none")
            .to_owned();
        lines.push(format!("Active      {active} → {}", word(2)));
    }
    if word(0) == "pack"
        && let Some(pack) = app.value(&format!("pack:{}", word(2)))
    {
        for entry in pack["explain"]["satisfied"]
            .as_array()
            .into_iter()
            .flatten()
        {
            lines.push(format!("✓ {}", entry["condition"].as_str().unwrap_or("")));
        }
        for entry in pack["explain"]["missing"].as_array().into_iter().flatten() {
            lines.push(format!("× {}", entry["condition"].as_str().unwrap_or("")));
        }
    }
    if (word(0), word(1)) == ("pack", "promote") {
        lines.push("Baselines   none change; add the promoted pack to one afterwards".into());
    }
    let preflight = ((word(0), word(1)) == ("pack", "promote")).then(|| {
        let key = format!("preflight:{}", args.join(" "));
        let mut words = args.clone();
        words.push("--preflight".into());
        if let Ok(action) = parse_action(&words) {
            if let Some(entry) = app.data.get_mut(&key) {
                entry.loading = false;
            }
            app.request(&key, action);
        }
        key
    });
    lines.push(String::new());
    lines.push(format!("calve {}", args.join(" ")));
    app.overlays.push(Overlay::Confirm {
        title,
        lines,
        args,
        label,
        preflight,
    });
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
            app.in_flight.insert(key.clone(), args.to_vec());
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
    let sent = app.in_flight.remove(key).unwrap_or_default();
    // A bulk action that succeeded is done with its selection.
    if result.is_ok() && sent.first().map(String::as_str) == Some("inbox") {
        app.collection("inbox").marked.clear();
    }
    let mut parts = rest.splitn(3, ':');
    let (_, show, label) = (
        parts.next(),
        parts.next() == Some("1"),
        parts.next().unwrap_or("command"),
    );
    match result {
        Ok(value) => {
            app.notify(Tone::Success, label.to_owned());
            // An operation with an execution identity links to it (§83–84).
            let execution = [&value["execution"], &value["execution"]["id"], &value["id"]]
                .into_iter()
                .filter_map(Value::as_str)
                .find(|id| id.starts_with("exe_"))
                .map(str::to_owned);
            if value.get("only_left_members").is_some() {
                app.overlays.push(compare_view(app, &value));
            } else if let Some(id) = execution {
                // The request returns when the run ends.
                let state = value["state"].as_str().unwrap_or("finished").to_lowercase();
                app.overlays.push(Overlay::Actions {
                    title: format!("{label}: {state}"),
                    items: vec![PaletteItem {
                        group: "Actions",
                        label: "Open execution".into(),
                        detail: crate::text::short_id(&id, 24, app.symbols.ellipsis()),
                        target: Target::Open(Route::Execution(id)),
                    }],
                    query: String::new(),
                    selected: 0,
                });
            } else if show {
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
            app.data_version += 1;
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
            // A native extension needs the same explicit acknowledgment as the CLI's
            // --acknowledge-native: the dialog states the backend's reason first.
            if error.contains("T2_ACKNOWLEDGMENT_REQUIRED") && !sent.is_empty() {
                let mut args = sent;
                args.push("--acknowledge-native".into());
                app.overlays.push(Overlay::Confirm {
                    title: "Native extension (T2)".into(),
                    lines: vec![
                        crate::text::line(&error),
                        String::new(),
                        "Enter acknowledges that it runs unconfined with your permissions,".into(),
                        "and enables it.".into(),
                        String::new(),
                        format!("calve {}", args.join(" ")),
                    ],
                    args,
                    label: label.to_owned(),
                    preflight: None,
                });
                return;
            }
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
            } else if error.contains("PROJECT_LOCKED") {
                app.notify(
                    Tone::Warning,
                    format!(
                        "{label}: a running execution holds this Project. Retry when it ends, or cancel it."
                    ),
                );
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
                confirm_dialog(app, format!("{label}?"), args, label);
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
        Target::OpenTab(route, tab) => {
            app.navigate(route);
            if let Some(index) = app.route.tabs().iter().position(|t| *t == tab) {
                app.set_tab(index);
            }
        }
        Target::Select { key, id } => {
            if key == "events" {
                app.navigate(Route::Events);
            }
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

/// The palette's searchable objects (§10.2): projects, ChangePacks, Baselines, intents, tasks,
/// executions, evidence and events from the loaded read models.
fn palette_objects(app: &App) -> Vec<(Vec<String>, PaletteItem)> {
    let str_of = |v: &Value, k: &str| v[k].as_str().unwrap_or("").to_owned();
    let short = |id: &str| crate::text::short_id(id, 16, app.symbols.ellipsis());
    let list = |key: &str| {
        app.value(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let object = |id: String, title: String, kind: &str, target: Target| {
        (
            vec![id.clone(), title.clone()],
            PaletteItem {
                group: "Objects",
                label: format!("{} · {kind}", short(&id)),
                detail: title,
                target,
            },
        )
    };
    let mut out = Vec::new();
    for p in list("projects") {
        let (id, name) = (str_of(&p, "project_id"), str_of(&p, "name"));
        out.push(object(
            id,
            name,
            "Project",
            Target::OpenProject {
                root: str_of(&p, "path"),
                route: Route::Overview,
            },
        ));
    }
    for p in app.pages("packs").items {
        let id = str_of(&p, "id");
        out.push(object(
            id.clone(),
            str_of(&p, "title"),
            "ChangePack",
            Target::Open(Route::ChangePack(id)),
        ));
    }
    for b in list("baselines") {
        let id = str_of(&b, "id");
        out.push(object(
            id.clone(),
            str_of(&b, "label"),
            "Baseline",
            Target::Open(Route::Baseline(id)),
        ));
    }
    for i in list("intents") {
        out.push(object(
            str_of(&i, "id"),
            str_of(&i, "title"),
            "Intent",
            Target::Open(Route::Intent(str_of(&i, "id"))),
        ));
    }
    for t in list("tasks") {
        let id = str_of(&t, "id");
        out.push(object(
            id.clone(),
            str_of(&t, "title"),
            "Task",
            Target::Open(Route::Task(id)),
        ));
        for e in t["linked_executions"].as_array().into_iter().flatten() {
            let e = e.as_str().unwrap_or_default().to_owned();
            out.push(object(
                e.clone(),
                format!("execution of {}", str_of(&t, "title")),
                "Execution",
                Target::Open(Route::Execution(e)),
            ));
        }
    }
    if let Some(status) = app.value("status") {
        for e in status["active_executions"].as_array().into_iter().flatten() {
            let id = str_of(e, "id");
            out.push(object(
                id.clone(),
                format!("{} {}", str_of(e, "state"), str_of(e, "harness")),
                "Execution",
                Target::Open(Route::Execution(id)),
            ));
        }
    }
    for e in app.pages("evidence").items {
        let pack = str_of(&e, "pack");
        out.push(object(
            str_of(&e["evidence"], "id"),
            format!(
                "{} for {}",
                crate::text::label(&str_of(&e["evidence"], "kind")),
                str_of(&e, "pack_title")
            ),
            "Evidence",
            Target::OpenTab(Route::ChangePack(pack), "Evidence"),
        ));
    }
    for e in list("events").into_iter().take(200) {
        out.push(object(
            crate::screens::event_id(&e),
            format!("{} {}", str_of(&e, "kind"), str_of(&e, "subject")),
            "Event",
            Target::Select {
                key: "events".into(),
                id: crate::screens::event_id(&e),
            },
        ));
    }
    out
}

/// Actions on the object a query found (§10.2: "Open / Review / Compare CP-0184").
fn object_actions(item: &PaletteItem) -> Vec<PaletteItem> {
    let act = |label: String, target: Target| PaletteItem {
        group: "Actions",
        label,
        detail: item.detail.clone(),
        target,
    };
    let name = item
        .label
        .split(" · ")
        .next()
        .unwrap_or_default()
        .to_owned();
    match &item.target {
        Target::Open(Route::ChangePack(id)) => vec![
            act(format!("Open {name}"), item.target.clone()),
            act(
                format!("Review {name}"),
                Target::OpenTab(Route::ChangePack(id.clone()), "Review"),
            ),
            act(
                format!("Verify {name}"),
                Target::OpenTab(Route::ChangePack(id.clone()), "Verify"),
            ),
            act(
                format!("Show evidence for {name}"),
                Target::OpenTab(Route::ChangePack(id.clone()), "Evidence"),
            ),
            act(
                format!("Diff {name}"),
                Target::OpenTab(Route::ChangePack(id.clone()), "Diff"),
            ),
        ],
        Target::Open(Route::Baseline(id)) => vec![
            act(format!("Open {name}"), item.target.clone()),
            act(
                format!("Compare {name}…"),
                Target::Prompt {
                    args: vec!["baseline".into(), "compare".into(), id.clone()],
                    suffix: vec![],
                    field: "Compare with Baseline".into(),
                    confirm: false,
                    label: format!("Compare {name}"),
                },
            ),
            act(
                format!("Explain {name}"),
                Target::OpenTab(Route::Baseline(id.clone()), "Explain"),
            ),
        ],
        Target::Select { .. } => vec![act(format!("Show event {name}"), item.target.clone())],
        _ => vec![act(format!("Open {name}"), item.target.clone())],
    }
}

/// Objects, actions, destinations and commands; groups ordered by their best match. `tab`
/// keeps one group family (§10.2: All / Objects / Actions / Commands).
pub fn palette_items(app: &App, screen: &Screen, query: &str, tab: usize) -> Vec<PaletteItem> {
    // (score, not recently used, insertion order) — recency never outranks identity.
    let mut all: Vec<((usize, bool, usize), PaletteItem)> = Vec::new();
    let recent = |id: &str| app.recent.iter().any(|r| r == id);
    let mut best: Option<((usize, bool, usize), PaletteItem)> = None;
    for (fields, item) in palette_objects(app) {
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        if let Some(score) = score(query, &refs) {
            let key = (score, !recent(&fields[0]), all.len());
            if !query.is_empty() && best.as_ref().is_none_or(|(k, _)| key < *k) {
                best = Some((key, item.clone()));
            }
            all.push((key, item));
        }
    }
    // The best-matching object's own actions come first among actions.
    if let Some((key, object)) = best {
        for action in object_actions(&object) {
            all.push(((key.0, key.1, all.len()), action));
        }
    }
    for action in &screen.actions {
        if let Some(s) = score(query, &[&action.label, &action.detail]) {
            all.push(((s + 1, true, all.len()), action.clone()));
        }
    }
    for route in nav_routes() {
        let title = route.title();
        if let Some(s) = score(query, &[&title]) {
            all.push((
                (s, true, all.len()),
                PaletteItem {
                    group: "Go to",
                    label: title.clone(),
                    detail: String::new(),
                    target: Target::Open(route),
                },
            ));
        }
    }
    for (label, command) in [
        ("New intent", "intent create "),
        ("New ChangePack", "pack create "),
        ("Status", "status"),
        ("Doctor", "doctor"),
        ("Maintenance check", "maintenance check"),
    ] {
        if let Some(s) = score(query, &[label, command]) {
            all.push((
                (s, true, all.len()),
                PaletteItem {
                    group: "Commands",
                    label: format!(":{command}"),
                    detail: label.to_owned(),
                    target: Target::Command(command.to_owned()),
                },
            ));
        }
    }
    let family = |group: &str| match group {
        "Objects" => 1,
        "Actions" | "Unavailable" => 2,
        _ => 3,
    };
    all.retain(|(_, item)| tab == 0 || family(item.group) == tab);
    let group_rank = |group: &str| {
        all.iter()
            .filter(|(_, i)| i.group == group)
            .map(|(k, _)| *k)
            .min()
    };
    let order = ["Objects", "Actions", "Unavailable", "Go to", "Commands"];
    let mut groups: Vec<&str> = order.to_vec();
    if !query.is_empty() {
        groups.sort_by_key(|g| {
            (
                group_rank(g).unwrap_or((usize::MAX, true, 0)),
                order.iter().position(|o| o == g),
            )
        });
    }
    let mut out = Vec::new();
    for group in groups {
        let mut items: Vec<&((usize, bool, usize), PaletteItem)> =
            all.iter().filter(|(_, i)| i.group == group).collect();
        items.sort_by_key(|(k, _)| *k);
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
    // `:task blocked`: a task state, not an id, filters Work (§10.3).
    if first == "task"
        && words.len() == 2
        && !words[1].contains('_')
        && parse_action(&words).is_err()
    {
        app.navigate(Route::Work);
        app.collection("work").filter = format!("state:{}", words[1]);
        return Ok(());
    }
    // `:verify <pack>` opens the pack's Verify tab.
    if first == "verify" && words.len() == 2 {
        run_target(
            app,
            Target::OpenTab(Route::ChangePack(words[1].clone()), "Verify"),
        );
        return Ok(());
    }
    // `:project <name or id>` switches Projects (§44).
    if first == "project" && words.len() == 2 && parse_action(&words).is_err() {
        let wanted = words[1].to_lowercase();
        let found = app
            .value("projects")
            .and_then(Value::as_array)
            .and_then(|list| {
                list.iter().find(|p| {
                    p["name"]
                        .as_str()
                        .is_some_and(|n| n.to_lowercase() == wanted)
                        || p["project_id"] == words[1].as_str()
                })
            });
        match found.and_then(|p| p["path"].as_str()).map(str::to_owned) {
            Some(root) => run_target(
                app,
                Target::OpenProject {
                    root,
                    route: Route::Overview,
                },
            ),
            None => {
                app.navigate(Route::Projects);
                app.collection("projects").filter = words[1].clone();
            }
        }
        return Ok(());
    }
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
        confirm_dialog(app, "Run command?".into(), words, label);
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
    First,
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
        Overlay::Palette {
            query,
            selected,
            tab,
        } => {
            let items = palette_items(app, &screen, query, *tab);
            if esc {
                keep = false;
            } else if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
                *tab = if key.code == KeyCode::Tab {
                    (*tab + 1) % 4
                } else {
                    (*tab + 3) % 4
                };
                *selected = 0;
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
            if key.code == KeyCode::Char('g') && query.is_empty() {
                // `gg`: first row (§51).
                keep = false;
                then = Then::First;
            } else if esc {
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
            // Ctrl+Enter submits (§59); terminals without key reporting send it as Ctrl+J.
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            let submit = ctrl && matches!(key.code, KeyCode::Enter | KeyCode::Char('j' | 's'))
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
        Then::First => move_selection(app, -100_000),
    }
}

/// Quits, unless commands are still in flight: then it says so and quits on the next q or
/// Ctrl+C (§9.2: no accidental exit while a process is active).
fn request_quit(app: &mut App) {
    if app.in_flight.is_empty() || app.quit_armed {
        app.quit = true;
    } else {
        app.quit_armed = true;
        app.notify(
            Tone::Warning,
            format!(
                "{} command(s) still running. A run goes on under the daemon, and can be cancelled from its Execution screen. Press q again to quit",
                app.in_flight.len()
            ),
        );
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
    let following = app.log_follow;
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
        Body::Log { key, lines, .. } => {
            if delta < 0 {
                app.log_follow = false;
            }
            let last = lines.len().saturating_sub(1) as isize;
            let viewport = app.size.1 as usize;
            let state = app.collection(key);
            // Leaving follow starts from what was on screen, not from the top.
            if following && delta < 0 {
                state.scroll = lines.len().saturating_sub(viewport);
            }
            state.scroll = (state.scroll as isize + delta).clamp(0, last.max(0)) as usize;
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
    let count = match (&app.route, diff_path(app)) {
        (Route::ChangePack(id), Some(path)) => app
            .value(&format!("diff:{id}:{path}"))
            .and_then(|d| d["lines"].as_array())
            .map_or(0, Vec::len),
        _ => 0,
    };
    let last = count.saturating_sub(1) as isize;
    app.diff_scroll = (app.diff_scroll as isize + delta).clamp(0, last.max(0)) as usize;
}

/// `/` search in output or raw text: scrolls to the next (or previous) matching line.
fn jump_log(app: &mut App, key: &str, lines: &[screens::LogLine], forward: bool) {
    let term = app
        .collections
        .get(key)
        .map(|c| c.filter.to_lowercase())
        .unwrap_or_default();
    if term.is_empty() {
        return;
    }
    let at = app.collections.get(key).map_or(0, |c| c.scroll);
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.text.to_lowercase().contains(&term))
        .map(|(i, _)| i)
        .collect();
    let target = if forward {
        hits.iter().find(|&&h| h > at).or(hits.first())
    } else {
        hits.iter().rev().find(|&&h| h < at).or(hits.last())
    };
    match target {
        Some(&line) => {
            app.log_follow = false;
            app.collection(key).scroll = line;
        }
        None => app.notify(Tone::Neutral, format!("No matches for “{term}”")),
    }
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
        // Terminal convention (§9.2): cancel what is active, otherwise exit.
        if !app.overlays.is_empty() || app.filter_editing {
            app.overlays.clear();
            app.filter_editing = false;
        } else {
            request_quit(app);
        }
        return;
    }
    if key.code != KeyCode::Char('q') {
        app.quit_armed = false;
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
                if let Body::Log {
                    key: log, lines, ..
                } = &screen.body
                {
                    app.collection(log).scroll = 0;
                    jump_log(app, log, lines, true);
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
        // q closes the innermost transient layer first; it quits only from the main shell.
        KeyCode::Char('q') => {
            if app.drawer {
                app.drawer = false;
            } else if app.fullscreen {
                app.fullscreen = false;
            } else if app.focus == Focus::Inspector {
                app.focus = Focus::Workspace;
            } else {
                request_quit(app);
            }
        }
        KeyCode::Char('b') if ctrl => app.panes_hidden = !app.panes_hidden,
        KeyCode::Char('?') => app.overlays.push(Overlay::Help),
        KeyCode::Char('p') if ctrl => {
            for (key, action) in [
                ("packs", &["view", "packs"][..]),
                ("baselines", &["baseline", "list"][..]),
                ("tasks", &["task", "list"][..]),
                ("intents", &["intent", "list"][..]),
                ("projects", &["project", "list"][..]),
                ("evidence", &["view", "evidence"][..]),
                ("events", &["activity"][..]),
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
                tab: 0,
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
        // y on output or raw text copies the text itself (§24, §28).
        KeyCode::Char('y') if let Body::Log { key: log, lines, .. } = &screen.body => {
            let text = lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n");
            let what = if log.starts_with("raw:") { "raw document" } else { "output" };
            copy(app, text, what);
        }
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
        // ChangePack keys (§51): e evidence; r review when a review can be recorded.
        KeyCode::Char('e') if matches!(app.route, Route::ChangePack(_)) => {
            if let Some(index) = app.route.tabs().iter().position(|t| *t == "Evidence") {
                app.set_tab(index);
                sync(app);
            }
        }
        KeyCode::Char('r')
            if matches!(app.route, Route::ChangePack(_))
                && screen
                    .actions
                    .iter()
                    .any(|a| matches!(a.target, Target::Review { .. })) =>
        {
            if let Some(item) = screen
                .actions
                .iter()
                .find(|a| matches!(a.target, Target::Review { .. }))
            {
                run_target(app, item.target.clone());
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
        KeyCode::Char('v')
            if matches!(screen.body, Body::Graph(_))
                || (app.graph_list
                    && matches!(app.route, Route::ChangeGraph | Route::Baseline(_))) =>
        {
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
        // `[` `]` switch the pack inspector's tabs (§30.2).
        KeyCode::Char(']') | KeyCode::Char('[')
            if !diff && matches!(app.route, Route::ChangePack(_) | Route::ChangePacks) =>
        {
            let n = crate::screens::PACK_INSPECTOR_TABS.len();
            app.inspector_tab = if key.code == KeyCode::Char(']') {
                (app.inspector_tab + 1) % n
            } else {
                (app.inspector_tab + n - 1) % n
            };
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
        KeyCode::Char('n' | 'N') if let Body::Log { key: log, lines, .. } = &screen.body => {
            jump_log(app, log, lines, key.code == KeyCode::Char('n'));
        }
        KeyCode::Char('w') if matches!(screen.body, Body::Log { .. }) => {
            app.wrap_logs = !app.wrap_logs;
        }
        KeyCode::Char('t') if matches!(screen.body, Body::Log { .. }) => {
            app.log_timestamps = !app.log_timestamps;
        }
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
            } else if app.drawer {
                app.drawer = false;
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
        // Direct object shortcuts (§51): a key no binding above claims runs the backend action
        // listed under it (`a` shows every action with its key).
        KeyCode::Char(c) if !ctrl && !alt => {
            match screen.actions.iter().find(|a| a.detail == format!("key {c}")) {
                Some(item) if app.can_act() => run_target(app, item.target.clone()),
                Some(_) => app.notify(Tone::Warning, "Offline: actions are disabled"),
                None => {}
            }
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
                Some(Hit::Action(index)) => {
                    let screen = screens::build(app);
                    if let Some(item) = screen
                        .actions
                        .iter()
                        .filter(|a| a.group == "Actions")
                        .nth(index)
                        && app.can_act()
                    {
                        run_target(app, item.target.clone());
                    }
                }
                None => {}
            }
            sync(app);
        }
        // Right-click: select the row and open its actions (§53 context menu).
        MouseEventKind::Down(MouseButton::Right) => {
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
            if let Some(Hit::Row { key, id }) = hit {
                app.collection(&key).selected_id = Some(id);
                sync(app);
                handle_key(app, KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
            }
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
