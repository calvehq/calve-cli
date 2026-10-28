//! Screen adapters: read models → presentation models (console-ux §63). They choose fields,
//! labels, grouping and ordering; they never decide eligibility. Actions and explanations
//! are passed through from the backend read models.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use serde_json::{Value, json};

use crate::model::{App, PaletteItem, Route, Target};
use crate::text::{self, label, line, relative, scalar, unix_seconds};
use crate::theme::{Tone, state_tone};

#[derive(Clone)]
pub struct Col {
    pub title: &'static str,
    pub width: u16,
    /// 1 is always shown; higher numbers disappear first as width shrinks (§5.3).
    pub priority: u8,
    pub fill: bool,
}

pub fn col(title: &'static str, width: u16, priority: u8) -> Col {
    Col {
        title,
        width,
        priority,
        fill: false,
    }
}

pub fn fill(title: &'static str, width: u16, priority: u8) -> Col {
    Col {
        title,
        width,
        priority,
        fill: true,
    }
}

#[derive(Clone)]
pub struct Cell {
    pub text: String,
    pub style: Style,
}

#[derive(Clone)]
pub struct Row {
    pub id: String,
    pub cells: Vec<Cell>,
    pub open: Option<Route>,
    /// What `y` copies when the row id is not the user-facing reference (§52).
    pub copy: Option<String>,
    /// The tab `open` lands on (Overview items open Verify or Review, §25.2).
    pub tab: Option<&'static str>,
    /// Lowercased text matched by `/` filters and structured `field:value` tokens.
    pub search: Vec<(&'static str, String)>,
}

#[derive(Clone)]
pub struct Section {
    pub title: Option<String>,
    pub columns: Vec<Col>,
    pub rows: Vec<Row>,
}

pub struct Table {
    pub key: String,
    pub sections: Vec<Section>,
    pub empty: (String, String),
    /// Quick state chips shown above the table (ChangePacks).
    pub chips: Vec<(String, usize)>,
    /// Rows in the whole collection when only some pages are loaded.
    pub total: Option<usize>,
}

pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub tone: Tone,
    pub open: Option<Route>,
    /// Fields the `/` filter highlights by.
    pub search: Vec<(&'static str, String)>,
}

pub struct Graph {
    pub key: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<(usize, usize)>,
    /// Relation of each edge (`depends_on`, `produces`, `requires`, …).
    pub kinds: Vec<String>,
    pub legend: bool,
    /// Nodes before the neighborhood limit (§29.3).
    pub total: usize,
}

/// A graph limited to the selected node's neighborhood when `app.graph_depth` is set.
fn graph_body(
    app: &App,
    key: String,
    nodes: Vec<GraphNode>,
    edges: Vec<(usize, usize, String)>,
    legend: bool,
) -> Body {
    let total = nodes.len();
    let pairs: Vec<(usize, usize)> = edges.iter().map(|(a, b, _)| (*a, *b)).collect();
    let center = selected_row_id(app, &key).and_then(|id| nodes.iter().position(|n| n.id == id));
    let keep = match (app.graph_depth, center) {
        (Some(depth), Some(center)) => crate::graph::neighborhood(total, &pairs, center, depth),
        _ => vec![true; total],
    };
    let mut index = vec![usize::MAX; total];
    let mut kept = Vec::new();
    for (i, node) in nodes.into_iter().enumerate() {
        if keep[i] {
            index[i] = kept.len();
            kept.push(node);
        }
    }
    let (edges, kinds) = edges
        .into_iter()
        .filter(|(a, b, _)| keep[*a] && keep[*b])
        .map(|(a, b, kind)| ((index[a], index[b]), kind))
        .unzip();
    Body::Graph(Graph {
        key,
        nodes: kept,
        edges,
        kinds,
        legend,
        total,
    })
}

/// The edges touching `node` (incoming, then outgoing) as (other end, relation, outgoing).
pub fn node_edges<'a>(edges: &'a [Value], node: &str) -> Vec<&'a Value> {
    edges
        .iter()
        .filter(|e| e["to"] == node)
        .chain(edges.iter().filter(|e| e["from"] == node))
        .collect()
}

/// Edge detail (§23): the relation in words; a reason only when one is recorded.
fn edge_detail(edge: &Value, name: &dyn Fn(&str) -> String) -> Detail {
    let from = name(str_of(edge, "from"));
    let to = name(str_of(edge, "to"));
    let kind = str_of(edge, "kind");
    let sentence = match kind {
        "depends_on" => format!("{to} depends on {from}"),
        "produces" => format!("{from} produces {to}"),
        "requires" => format!("{from} requires {to}"),
        other => format!("{from} {} {to}", label(other).to_lowercase()),
    };
    let mut lines = vec![(Tone::Neutral, sentence), (Tone::Neutral, String::new())];
    match edge["reason"].as_str() {
        Some(reason) => lines.push((Tone::Neutral, format!("Reason: {reason}"))),
        None => lines.push((Tone::Neutral, "Reason not recorded.".into())),
    }
    (label(kind), lines)
}

pub enum Body {
    Table(Table),
    Text(Vec<Line<'static>>),
    Graph(Graph),
    /// The Diff workstation; the key holds its file selection and `/` search term.
    Diff(String),
    Status {
        tone: Tone,
        title: String,
        body: String,
    },
}

pub struct Screen {
    pub body: Body,
    pub inspector: Vec<Line<'static>>,
    pub hints: Vec<(&'static str, &'static str)>,
    pub actions: Vec<PaletteItem>,
    pub explain: Option<(String, Vec<(Tone, String)>)>,
    /// What Enter opens for a selected row that has no screen of its own (check, receipt,
    /// event detail).
    pub detail: Option<Detail>,
}

/// A titled explanation or detail overlay's content.
pub type Detail = (String, Vec<(Tone, String)>);

impl Screen {
    fn new(body: Body) -> Self {
        Self {
            body,
            inspector: Vec::new(),
            hints: Vec::new(),
            actions: Vec::new(),
            explain: None,
            detail: None,
        }
    }
}

pub fn cell(text: impl AsRef<str>, style: Style) -> Cell {
    Cell {
        text: line(text.as_ref()),
        style,
    }
}

fn plain(app: &App, text: impl AsRef<str>) -> Cell {
    cell(text, app.theme.text())
}

fn muted(app: &App, text: impl AsRef<str>) -> Cell {
    cell(text, app.theme.muted())
}

fn id_cell(app: &App, id: &str) -> Cell {
    cell(
        text::short_id(id, 14, app.symbols.ellipsis()),
        app.theme.accent(),
    )
}

pub fn state_cell(app: &App, state: &str) -> Cell {
    let tone = state_tone(state);
    cell(
        format!("{} {}", app.symbols.tone(tone), state.to_uppercase()),
        app.theme.tone(tone),
    )
}

fn age_cell(app: &App, value: &Value) -> Cell {
    muted(app, age(app, value))
}

/// A table time in the user's style (`[console] time`, §54).
pub fn age(app: &App, value: &Value) -> String {
    use crate::model::TimeStyle;
    unix_seconds(value)
        .map(|t| match app.time {
            TimeStyle::Relative => relative(t, app.now),
            TimeStyle::Absolute => text::clock(t, app.now),
            TimeStyle::Both => format!("{} · {}", relative(t, app.now), text::clock(t, app.now)),
        })
        .unwrap_or_else(|| "—".into())
}

/// Inspector time: relative and exact, with the zone stated (§54).
pub fn exact(app: &App, value: &Value) -> String {
    unix_seconds(value)
        .map(|t| format!("{} ago · {}", relative(t, app.now), text::absolute(t)))
        .unwrap_or_else(|| "—".into())
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}

fn search(pairs: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    pairs.iter().map(|(k, v)| (*k, v.to_lowercase())).collect()
}

fn heading(app: &App, text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(text.into(), app.theme.heading()))
}

fn field(app: &App, name: &str, value: impl AsRef<str>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:<12}", name), app.theme.muted()),
        Span::styled(line(value.as_ref()), app.theme.text()),
    ])
}

fn field_state(app: &App, name: &str, state: &str) -> Line<'static> {
    let tone = state_tone(state);
    Line::from(vec![
        Span::styled(format!("{:<12}", name), app.theme.muted()),
        Span::styled(
            format!("{} {}", app.symbols.tone(tone), state.to_uppercase()),
            app.theme.tone(tone).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn blank() -> Line<'static> {
    Line::from("")
}

fn text_line(app: &App, value: impl AsRef<str>) -> Line<'static> {
    Line::from(Span::styled(line(value.as_ref()), app.theme.text()))
}

fn muted_line(app: &App, value: impl AsRef<str>) -> Line<'static> {
    Line::from(Span::styled(line(value.as_ref()), app.theme.muted()))
}

fn toned(app: &App, tone: Tone, value: impl AsRef<str>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{} ", app.symbols.tone(tone)), app.theme.tone(tone)),
        Span::styled(line(value.as_ref()), app.theme.text()),
    ])
}

/// Loading, error and empty states (§17–19) share one shape.
fn status_or<'a>(app: &'a App, key: &str, what: &str) -> Result<&'a Value, Box<Screen>> {
    match app.loaded(key) {
        Some(loaded) if loaded.value.is_some() => Ok(loaded.value.as_ref().expect("checked")),
        Some(loaded) if loaded.error.is_some() => Err(Box::new(Screen::new(Body::Status {
            tone: Tone::Danger,
            title: format!("Could not load {what}"),
            body: format!(
                "{}\n\nr refresh",
                line(loaded.error.as_deref().unwrap_or(""))
            ),
        }))),
        _ => Err(Box::new(Screen::new(Body::Status {
            tone: Tone::Running,
            title: format!("Loading {what}{}", app.symbols.ellipsis()),
            body: String::new(),
        }))),
    }
}

fn run(label: &str, args: &[&str], confirm: bool) -> Target {
    Target::Run {
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        confirm,
        label: label.to_owned(),
    }
}

fn item(label: &str, detail: &str, target: Target) -> PaletteItem {
    PaletteItem {
        group: "Actions",
        label: label.to_owned(),
        detail: detail.to_owned(),
        target,
    }
}

/// Backend-provided action descriptors (`views.rs`) become palette entries unchanged.
fn backend_actions(value: &Value) -> Vec<PaletteItem> {
    let mut items = Vec::new();
    for entry in value["actions"].as_array().into_iter().flatten() {
        let args: Vec<String> = entry["args"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect();
        let label = str_of(entry, "label").to_owned();
        let destructive = entry["destructive"] == true;
        let target = match entry["id"].as_str() {
            Some("approve") | Some("reject") => {
                let generation = value["generation"].as_u64().unwrap_or(0);
                Target::Review {
                    pack: str_of(value, "id").to_owned(),
                    generation,
                }
            }
            Some("quarantine") => Target::Prompt {
                args,
                suffix: vec![],
                field: "Reason".into(),
                confirm: true,
                label: label.clone(),
            },
            _ => Target::Run {
                args,
                confirm: destructive,
                label: label.clone(),
            },
        };
        items.push(PaletteItem {
            group: "Actions",
            label,
            detail: format!("key {}", str_of(entry, "key")),
            target,
        });
    }
    for entry in value["unavailable_actions"]
        .as_array()
        .into_iter()
        .flatten()
    {
        items.push(PaletteItem {
            group: "Unavailable",
            label: str_of(entry, "label").to_owned(),
            detail: str_of(entry, "reason").to_owned(),
            target: Target::Unavailable(str_of(entry, "reason").to_owned()),
        });
    }
    items
}

/// Explain mode content quoted from the backend's authoritative explanation.
fn pack_explain(app: &App, pack: &Value) -> (String, Vec<(Tone, String)>) {
    let explain = &pack["explain"];
    let mut lines = Vec::new();
    lines.push((
        Tone::Neutral,
        format!("State: {}", str_of(explain, "state")),
    ));
    lines.push((Tone::Neutral, String::new()));
    lines.push((Tone::Neutral, "Satisfied".into()));
    let mut any = false;
    for entry in explain["satisfied"].as_array().into_iter().flatten() {
        any = true;
        lines.push((
            Tone::Success,
            format!("{}{}", str_of(entry, "condition"), policy_suffix(entry)),
        ));
    }
    if !any {
        lines.push((Tone::Neutral, "nothing yet".into()));
    }
    lines.push((Tone::Neutral, String::new()));
    lines.push((Tone::Neutral, "Missing".into()));
    let mut any = false;
    for entry in explain["missing"].as_array().into_iter().flatten() {
        any = true;
        let detail = str_of(entry, "detail");
        lines.push((
            Tone::Danger,
            format!(
                "{}{}{}",
                str_of(entry, "condition"),
                policy_suffix(entry),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(" — {detail}")
                }
            ),
        ));
    }
    if !any {
        lines.push((Tone::Neutral, "nothing".into()));
    }
    if let Some(decision) = explain["decision"].as_object() {
        lines.push((Tone::Neutral, String::new()));
        lines.push((
            state_tone(
                decision
                    .get("outcome")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            ),
            format!(
                "OpenAEVC decision: {}",
                decision
                    .get("outcome")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_uppercase()
            ),
        ));
        for rule in decision
            .get("rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let passed = rule["passed"] == true;
            lines.push((
                if passed { Tone::Success } else { Tone::Danger },
                format!("rule {}", str_of(rule, "rule")),
            ));
        }
    }
    if let Some(next) = explain["next"].as_str() {
        lines.push((Tone::Neutral, String::new()));
        lines.push((Tone::Review, format!("Next valid action: {}", label(next))));
    }
    lines.push((Tone::Neutral, String::new()));
    lines.push((
        Tone::Neutral,
        format!("Source: {}", str_of(explain, "source")),
    ));
    let title = format!(
        "Why is {} {}?",
        text::short_id(str_of(pack, "id"), 18, app.symbols.ellipsis()),
        str_of(pack, "state")
    );
    (title, lines)
}

fn policy_suffix(entry: &Value) -> String {
    match entry["policy"].as_str() {
        Some(policy) => format!(" ({policy})"),
        None => String::new(),
    }
}

pub fn build(app: &App) -> Screen {
    let mut screen = match &app.route {
        Route::Overview => overview(app),
        Route::Work => work(app),
        Route::Task(id) => task(app, id),
        Route::Execution(id) => execution(app, id),
        Route::ChangeGraph => change_graph(app),
        Route::ChangePacks => packs(app),
        Route::ChangePack(id) => pack(app, id),
        Route::Baselines => baselines(app),
        Route::Baseline(id) => baseline(app, id),
        Route::Evidence => evidence(app),
        Route::Events => events(app),
        Route::Projects => projects(app),
        Route::Inbox => inbox(app),
        Route::Doctor => doctor(app),
        Route::Extensions => extensions(app),
    };
    if screen.hints.is_empty() {
        screen.hints = vec![
            ("↑↓", "navigate"),
            ("enter", "open"),
            ("/", "filter"),
            ("a", "actions"),
        ];
    }
    screen
        .hints
        .extend([("^P", "commands"), (":", "command"), ("?", "help")]);
    screen
}

fn overview(app: &App) -> Screen {
    let value = match status_or(app, "overview", "overview") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let attention_kind = |kind: &str| match kind {
        "failure" => Tone::Danger,
        "blocked" | "warning" | "stale" => Tone::Warning,
        "review" => Tone::Review,
        "running" => Tone::Running,
        _ => Tone::Neutral,
    };
    // Enter opens the item's native context (§25.2).
    let route_for = |kind: &str, id: &str| match kind {
        "pack" | "quarantined_pack" | "stale_review" => Some(Route::ChangePack(id.to_owned())),
        "task" | "task_inconsistency" => Some(Route::Task(id.to_owned())),
        "execution" => Some(Route::Execution(id.to_owned())),
        "baseline" => Some(Route::Baseline(id.to_owned())),
        _ => route_for_id(id),
    };
    let tab_for = |kind: &str, subject_kind: &str| match (kind, subject_kind) {
        (_, "baseline") => Some("Explain"),
        ("failure", "pack") => Some("Verify"),
        ("review" | "stale", _) | (_, "stale_review") => Some("Review"),
        _ => None,
    };
    let attention: Vec<Row> = value["needs_attention"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            let tone = attention_kind(str_of(entry, "kind"));
            let subject = str_of(entry, "subject");
            Row {
                id: format!("attention:{subject}:{}", str_of(entry, "kind")),
                cells: vec![
                    cell(app.symbols.tone(tone), app.theme.tone(tone)),
                    id_cell(app, subject),
                    plain(app, str_of(entry, "message")),
                    age_cell(app, &entry["at"]),
                ],
                copy: Some(subject.to_owned()),
                tab: tab_for(str_of(entry, "kind"), str_of(entry, "subject_kind")),
                open: route_for(str_of(entry, "subject_kind"), subject),
                search: search(&[
                    ("id", subject),
                    ("text", str_of(entry, "message")),
                    ("type", str_of(entry, "kind")),
                ]),
            }
        })
        .collect();
    let work: Vec<Row> = value["active_work"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| Row {
            id: format!("intent:{}", str_of(entry, "id")),
            cells: vec![
                plain(app, str_of(entry, "title")),
                muted(
                    app,
                    format!("{}/{}", entry["tasks_done"], entry["tasks_total"]),
                ),
                muted(app, entry["packs"].to_string()),
                state_cell(app, str_of(entry, "state")),
            ],
            copy: Some(str_of(entry, "id").to_owned()),
            tab: None,
            // Opens Work filtered to this intent's tasks (see `input::open_selected`).
            open: Some(Route::Work),
            search: search(&[
                ("text", str_of(entry, "title")),
                ("state", str_of(entry, "state")),
            ]),
        })
        .collect();
    let activity: Vec<Row> = value["recent_activity"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| activity_row(app, entry, true))
        .collect();
    let mut sections = vec![Section {
        title: Some("Needs attention".into()),
        columns: vec![
            col("", 3, 1),
            col("Subject", 16, 1),
            fill("", 20, 1),
            col("", 6, 2),
        ],
        rows: attention,
    }];
    sections.push(Section {
        title: Some("Active work".into()),
        columns: vec![
            fill("Intent", 20, 1),
            col("Tasks", 7, 2),
            col("Packs", 6, 3),
            col("State", 13, 1),
        ],
        rows: work,
    });
    sections.push(Section {
        title: Some("Recent activity".into()),
        columns: activity_columns(),
        rows: activity,
    });
    let mut screen = Screen::new(Body::Table(Table {
        key: "overview".into(),
        sections,
        empty: (
            "Nothing needs attention.".into(),
            "Create an intent and a ChangePack to begin.".into(),
        ),
        chips: vec![],
        total: None,
    }));
    screen.inspector = vec![
        heading(app, str_of(&value["project"], "name")),
        muted_line(app, str_of(&value["project"], "id")),
        blank(),
        field(app, "ChangePacks", value["counts"]["packs"].to_string()),
        field(app, "Intents", value["counts"]["intents"].to_string()),
        field(app, "Baselines", value["counts"]["baselines"].to_string()),
        field(
            app,
            "Attention",
            value["needs_attention"]
                .as_array()
                .map_or(0, Vec::len)
                .to_string(),
        ),
    ];
    screen
}

/// The native screen of an OpenAEVC/Calve ID, from its type prefix.
pub fn route_for_id(id: &str) -> Option<Route> {
    let (prefix, _) = id.split_once('_')?;
    Some(match prefix {
        "cpk" => Route::ChangePack(id.to_owned()),
        "exe" => Route::Execution(id.to_owned()),
        "tsk" => Route::Task(id.to_owned()),
        "bsl" => Route::Baseline(id.to_owned()),
        _ => return None,
    })
}

/// Time, actor, event, object (§42, §25 Recent activity).
fn activity_columns() -> Vec<Col> {
    vec![
        col("Time", 9, 1),
        col("Actor", 14, 2),
        fill("Event", 20, 1),
        col("Object", 16, 2),
    ]
}

/// The stable reference of an activity entry: its event id, never its position (§16).
pub fn event_id(entry: &Value) -> String {
    match entry["id"].as_str() {
        Some(id) => id.to_owned(),
        None => format!("{}:{}", str_of(entry, "source"), entry["source_sequence"]),
    }
}

fn event_time(entry: &Value) -> &Value {
    if entry["created_at"].is_null() {
        &entry["timestamp"]
    } else {
        &entry["created_at"]
    }
}

/// `open_subject`: Enter opens the event's object (Overview) rather than the event.
fn activity_row(app: &App, entry: &Value, open_subject: bool) -> Row {
    let kind = str_of(entry, "kind");
    let subject = entry["subject"]
        .as_str()
        .or_else(|| entry["subjects"][0].as_str())
        .unwrap_or("");
    let actor = entry["actor"].as_str().unwrap_or(str_of(entry, "source"));
    let id = event_id(entry);
    // Activity reads as a timeline: clock times unless the user asked for both (§25, §42).
    let time = match app.time {
        crate::model::TimeStyle::Both => age(app, event_time(entry)),
        _ => unix_seconds(event_time(entry))
            .map(|t| text::clock(t, app.now))
            .unwrap_or_else(|| "—".into()),
    };
    Row {
        cells: vec![
            muted(app, time),
            muted(app, text::short_id(actor, 14, app.symbols.ellipsis())),
            plain(app, kind),
            id_cell(app, subject),
        ],
        copy: None,
        tab: None,
        open: if open_subject {
            route_for_id(subject).or(Some(Route::Events))
        } else {
            None
        },
        search: search(&[
            ("type", kind),
            ("actor", actor),
            ("object", subject),
            ("source", str_of(entry, "source")),
            ("id", &id),
        ]),
        id,
    }
}

fn work(app: &App) -> Screen {
    let (intents, tasks) = match (
        status_or(app, "intents", "intents"),
        status_or(app, "tasks", "tasks"),
    ) {
        (Ok(i), Ok(t)) => (i, t),
        (Err(screen), _) | (_, Err(screen)) => return *screen,
    };
    let empty = Vec::new();
    let rollup: Vec<Value> = app
        .value("overview")
        .and_then(|v| v["active_work"].as_array().cloned())
        .unwrap_or_default();
    let mut sections = Vec::new();
    for intent in intents.as_array().unwrap_or(&empty) {
        let intent_id = str_of(intent, "id");
        let state = rollup
            .iter()
            .find(|w| w["id"] == intent["id"])
            .map(|w| str_of(w, "state").to_owned())
            .unwrap_or_else(|| str_of(intent, "state").to_owned());
        let rows: Vec<Row> = tasks
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter(|task| task["intent_id"] == intent["id"])
            .map(|task| Row {
                id: str_of(task, "id").to_owned(),
                cells: vec![
                    plain(app, str_of(task, "title")),
                    muted(app, task["assignee"].as_str().unwrap_or("—")),
                    muted(app, str_of(task, "priority")),
                    state_cell(app, str_of(task, "state")),
                    age_cell(app, &task["updated_at"]),
                ],
                copy: None,
                tab: None,
                open: Some(Route::Task(str_of(task, "id").to_owned())),
                search: search(&[
                    ("text", str_of(task, "title")),
                    ("state", str_of(task, "state")),
                    ("actor", task["assignee"].as_str().unwrap_or("")),
                    ("id", str_of(task, "id")),
                    ("intent", intent_id),
                ]),
            })
            .collect();
        let done = tasks
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter(|t| t["intent_id"] == intent["id"] && t["state"] == "COMPLETE")
            .count();
        sections.push(Section {
            title: Some(format!(
                "{}  {}/{} · {} {}",
                line(str_of(intent, "title")),
                done,
                rows.len(),
                app.symbols.tone(state_tone(&state)),
                state
            )),
            columns: vec![
                fill("Task", 20, 1),
                col("Actor", 12, 3),
                col("Priority", 9, 4),
                col("State", 14, 1),
                col("Updated", 8, 2),
            ],
            rows,
        });
    }
    let mut screen = Screen::new(Body::Table(Table {
        key: "work".into(),
        sections,
        empty: (
            "No intents yet.".into(),
            "Create one with :intent create \"goal\".".into(),
        ),
        chips: vec![],
        total: None,
    }));
    let selected = selected_row_id(app, "work");
    if let Some(task) =
        selected.and_then(|id| tasks.as_array()?.iter().find(|t| t["id"] == id.as_str()))
    {
        screen.inspector = task_inspector(app, task);
        screen.actions = task_actions(task);
        screen.explain = task_explain(task);
    }
    screen.hints = vec![
        ("↑↓", "navigate"),
        ("enter", "open task"),
        ("a", "actions"),
        ("x", "explain"),
    ];
    screen
}

fn task_inspector(app: &App, task: &Value) -> Vec<Line<'static>> {
    let mut lines = vec![
        heading(app, str_of(task, "title")),
        muted_line(app, str_of(task, "id")),
        blank(),
        field_state(app, "State", str_of(task, "state")),
        field(app, "Intent", str_of(task, "intent_id")),
        field(app, "Actor", task["assignee"].as_str().unwrap_or("—")),
        field(app, "Priority", str_of(task, "priority")),
        field(app, "Updated", age(app, &task["updated_at"])),
    ];
    if let Some(reason) = task["blocked_reason"].as_str() {
        lines.push(field(app, "Blocked", reason));
    }
    for (name, key) in [
        ("Depends on", "depends_on"),
        ("Packs", "linked_packs"),
        ("Executions", "linked_executions"),
    ] {
        let items = task[key].as_array().cloned().unwrap_or_default();
        if !items.is_empty() {
            lines.push(blank());
            lines.push(heading(app, name));
            for entry in items {
                lines.push(Line::from(Span::styled(
                    format!("  {} {}", app.symbols.arrow(), scalar(&entry)),
                    app.theme.accent(),
                )));
            }
        }
    }
    lines
}

fn task_actions(task: &Value) -> Vec<PaletteItem> {
    let id = str_of(task, "id");
    let state = str_of(task, "state");
    let mut items = Vec::new();
    if state == "OPEN" || state == "BLOCKED" {
        items.push(item(
            "Start",
            "task start",
            run("Start task", &["task", "start", id], false),
        ));
    }
    if state != "COMPLETE" {
        items.push(item(
            "Complete",
            "task complete",
            run("Complete task", &["task", "complete", id], false),
        ));
        items.push(item(
            "Block",
            "task block --reason",
            Target::Prompt {
                args: vec!["task".into(), "block".into(), id.into(), "--reason".into()],
                suffix: vec![],
                field: "Reason".into(),
                confirm: false,
                label: "Block task".into(),
            },
        ));
    }
    if state == "BLOCKED" {
        items.push(item(
            "Unblock",
            "task unblock",
            run("Unblock task", &["task", "unblock", id], false),
        ));
    }
    if state == "COMPLETE" {
        items.push(item(
            "Reopen",
            "task reopen",
            run("Reopen task", &["task", "reopen", id], false),
        ));
    }
    items.push(item(
        "Assign",
        "task assign",
        Target::Prompt {
            args: vec!["task".into(), "assign".into(), id.into()],
            suffix: vec![],
            field: "Assignee".into(),
            confirm: false,
            label: "Assign task".into(),
        },
    ));
    items
}

fn task_explain(task: &Value) -> Option<(String, Vec<(Tone, String)>)> {
    let mut lines = vec![(Tone::Neutral, format!("State: {}", str_of(task, "state")))];
    if let Some(reason) = task["blocked_reason"].as_str() {
        lines.push((Tone::Warning, format!("Blocked: {reason}")));
    }
    for blocker in task["blocked_by"].as_array().into_iter().flatten() {
        lines.push((Tone::Danger, format!("Waiting on task {}", scalar(blocker))));
    }
    for issue in task["inconsistencies"].as_array().into_iter().flatten() {
        lines.push((Tone::Warning, scalar(issue)));
    }
    if lines.len() == 1 {
        lines.push((Tone::Success, "No recorded blockers".into()));
    }
    Some((format!("Task {}", str_of(task, "title")), lines))
}

fn task(app: &App, id: &str) -> Screen {
    let value = match status_or(app, &format!("task:{id}"), "task") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let body = match app.tab_name() {
        Some("Executions") => {
            let rows: Vec<Row> = value["linked_executions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|execution| Row {
                    id: execution.to_owned(),
                    cells: vec![id_cell(app, execution)],
                    copy: None,
                    tab: None,
                    open: Some(Route::Execution(execution.to_owned())),
                    search: search(&[("id", execution)]),
                })
                .collect();
            Body::Table(Table {
                key: format!("task-executions:{id}"),
                sections: vec![Section {
                    title: None,
                    columns: vec![fill("Execution", 20, 1)],
                    rows,
                }],
                empty: (
                    "No executions linked.".into(),
                    "Link one with :task link-execution.".into(),
                ),
                chips: vec![],
                total: None,
            })
        }
        Some("Raw") => Body::Text(raw_lines(app, value)),
        _ => Body::Text(task_inspector(app, value)),
    };
    let mut screen = Screen::new(body);
    screen.actions = task_actions(value);
    screen.explain = task_explain(value);
    screen.inspector = vec![heading(app, "Work units")];
    for unit in value["work_units"].as_array().into_iter().flatten() {
        screen.inspector.push(toned(
            app,
            state_tone(str_of(unit, "state")),
            format!("{} {}", str_of(unit, "id"), str_of(unit, "state")),
        ));
    }
    screen.hints = vec![
        ("tab", "tabs"),
        ("a", "actions"),
        ("x", "explain"),
        ("esc", "back"),
    ];
    screen
}

fn execution(app: &App, id: &str) -> Screen {
    let value = match status_or(app, &format!("execution:{id}"), "execution") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let exec = &value["execution"];
    let summary = vec![
        heading(app, format!("Execution {}", str_of(exec, "id"))),
        blank(),
        field_state(app, "State", str_of(exec, "state")),
        field(app, "Pack", str_of(exec, "pack")),
        field(app, "Harness", str_of(exec, "harness")),
        field(app, "Provider", str_of(exec, "provider")),
        field(app, "Actor", str_of(exec, "actor")),
        field(
            app,
            "Attempt",
            format!("{} of {}", exec["attempt"], exec["max_attempts"]),
        ),
        field(app, "Generation", exec["generation"].to_string()),
        field(app, "Retry of", exec["retry_of"].as_str().unwrap_or("—")),
        field(
            app,
            "Output",
            format!("{} lines", value["output"].as_array().map_or(0, Vec::len)),
        ),
        field(
            app,
            "Effects",
            value["effects"].as_array().map_or(0, Vec::len).to_string(),
        ),
    ];
    let body = match app.tab_name() {
        Some("Output") => {
            let lines = value["output"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|entry| {
                    let style = if entry["stream"] == "stderr" {
                        app.theme.tone(Tone::Warning)
                    } else {
                        app.theme.text()
                    };
                    Line::from(Span::styled(line(str_of(entry, "text")), style))
                })
                .collect::<Vec<_>>();
            if lines.is_empty() {
                Body::Status {
                    tone: Tone::Neutral,
                    title: "No output recorded.".into(),
                    body: "Workers record output as observations.".into(),
                }
            } else {
                Body::Text(lines)
            }
        }
        Some("Observations") => table_body(
            app,
            format!("exec-obs:{id}"),
            &value["observations"],
            &[("kind", "Kind"), ("at", "Observed")],
            "No observations.",
        ),
        Some("Effects") => table_body(
            app,
            format!("exec-effects:{id}"),
            &value["effects"],
            &[
                ("target", "Resource"),
                ("kind", "Effect"),
                ("digest", "Digest"),
            ],
            "No effects proposed.",
        ),
        Some("Events") => table_body(
            app,
            format!("exec-events:{id}"),
            &value["events"],
            &[("kind", "Event"), ("timestamp", "Time")],
            "No events.",
        ),
        Some("Raw") => Body::Text(raw_lines(app, value)),
        _ => Body::Text(summary.clone()),
    };
    let mut screen = Screen::new(body);
    screen.inspector = summary;
    let state = str_of(exec, "state");
    if matches!(state, "RUNNING" | "STARTING" | "ADMITTED" | "PENDING") {
        screen.actions.push(item(
            "Cancel",
            "execution cancel",
            run("Cancel execution", &["execution", "cancel", id], true),
        ));
    }
    if matches!(state, "FAILED" | "LOST" | "CANCELLED") {
        screen.actions.push(item(
            "Retry",
            "execution retry (new attempt)",
            run("Retry execution", &["execution", "retry", id], false),
        ));
    }
    if let Some(pack) = exec["pack"].as_str() {
        screen.actions.push(item(
            "Open ChangePack",
            pack,
            Target::Open(Route::ChangePack(pack.to_owned())),
        ));
    }
    screen.hints = vec![
        ("tab", "tabs"),
        ("f", "follow"),
        ("a", "actions"),
        ("esc", "back"),
    ];
    screen
}

/// A record's stable row id: its digest, id or sequence; the position only as a last resort.
fn row_key(entry: &Value, index: usize) -> String {
    entry["digest"]
        .as_str()
        .or(entry["id"].as_str())
        .map(str::to_owned)
        .or_else(|| entry["sequence"].as_u64().map(|n| n.to_string()))
        .unwrap_or_else(|| index.to_string())
}

/// Generic table for low-frequency objects (§81–82).
fn table_body(
    app: &App,
    key: String,
    rows: &Value,
    fields: &[(&'static str, &'static str)],
    empty: &str,
) -> Body {
    let columns: Vec<Col> = fields
        .iter()
        .enumerate()
        .map(|(i, (_, title))| {
            if i == 0 {
                fill(title, 16, 1)
            } else {
                col(title, 18, (i + 1) as u8)
            }
        })
        .collect();
    let rows = rows
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, entry)| Row {
            id: row_key(entry, index),
            cells: fields
                .iter()
                .map(|(key, _)| {
                    let value = &entry[*key];
                    if key.ends_with("at") || *key == "timestamp" || key.ends_with("_at") {
                        muted(app, age(app, value))
                    } else if *key == "digest" {
                        muted(
                            app,
                            text::middle(&scalar(value), 22, app.symbols.ellipsis()),
                        )
                    } else if *key == "state" || *key == "status" {
                        state_cell(app, &scalar(value))
                    } else {
                        plain(app, scalar(value))
                    }
                })
                .collect(),
            copy: None,
            tab: None,
            open: None,
            search: fields
                .iter()
                .map(|(key, _)| (*key, scalar(&entry[*key]).to_lowercase()))
                .collect(),
        })
        .collect();
    Body::Table(Table {
        key,
        sections: vec![Section {
            title: None,
            columns,
            rows,
        }],
        empty: (empty.to_owned(), String::new()),
        chips: vec![],
        total: None,
    })
}

fn change_graph(app: &App) -> Screen {
    let value = match status_or(app, "graph", "change graph") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let empty = Vec::new();
    let all_nodes = value["nodes"].as_array().unwrap_or(&empty);
    let all_edges = value["edges"].as_array().unwrap_or(&empty);
    let route = |node: &Value| {
        let id = str_of(node, "id").to_owned();
        if node["kind"] == "pack" {
            Route::ChangePack(id)
        } else {
            Route::Task(id)
        }
    };
    let nodes: Vec<GraphNode> = all_nodes
        .iter()
        .map(|node| GraphNode {
            id: str_of(node, "id").to_owned(),
            label: str_of(node, "label").to_owned(),
            tone: state_tone(str_of(node, "state")),
            open: Some(route(node)),
            search: search(&[
                ("text", str_of(node, "label")),
                ("id", str_of(node, "id")),
                ("state", str_of(node, "state")),
                ("type", str_of(node, "kind")),
            ]),
        })
        .collect();
    let index = |id: &str| nodes.iter().position(|n| n.id == id);
    let edges: Vec<(usize, usize, String)> = all_edges
        .iter()
        .filter_map(|edge| {
            Some((
                index(edge["from"].as_str()?)?,
                index(edge["to"].as_str()?)?,
                str_of(edge, "kind").to_owned(),
            ))
        })
        .collect();
    let selected = selected_row_id(app, "graph");
    let node = selected
        .as_deref()
        .and_then(|id| all_nodes.iter().find(|n| n["id"] == id));
    let mut screen = if app.graph_list || nodes.is_empty() {
        let mut screen = Screen::new(table_body(
            app,
            "graph".into(),
            &value["nodes"],
            &[
                ("label", "Node"),
                ("kind", "Kind"),
                ("state", "State"),
                ("id", "ID"),
            ],
            "No tasks or packs in the change graph.",
        ));
        if let Body::Table(table) = &mut screen.body {
            for row in &mut table.sections[0].rows {
                row.open = all_nodes
                    .iter()
                    .find(|n| n["id"] == row.id.as_str())
                    .map(route);
            }
        }
        screen
    } else {
        Screen::new(graph_body(app, "graph".into(), nodes, edges, true))
    };
    if let Some(node) = node {
        let id = str_of(node, "id");
        let name = |id: &str| {
            all_nodes
                .iter()
                .find(|n| n["id"] == id)
                .map(|n| str_of(n, "label").to_owned())
                .unwrap_or_else(|| id.to_owned())
        };
        screen.inspector = vec![
            heading(app, str_of(node, "label")),
            muted_line(app, id),
            blank(),
            field_state(app, "State", str_of(node, "state")),
            field(app, "Kind", label(str_of(node, "kind"))),
        ];
        let (lines, detail) = relations(app, all_edges, id, &name);
        screen.inspector.extend(lines);
        screen.detail = detail;
    }
    screen.hints = vec![
        ("hjkl", "move"),
        ("tab", "next node"),
        ("e", "edges"),
        ("f", "neighborhood"),
        ("v", "list/graph"),
        ("enter", "open"),
    ];
    screen
}

/// The selected node's relationships, the selected one (key `e`) marked; Enter on it opens
/// its detail (§23).
fn relations(
    app: &App,
    edges: &[Value],
    node: &str,
    name: &dyn Fn(&str) -> String,
) -> (Vec<Line<'static>>, Option<Detail>) {
    let list = node_edges(edges, node);
    if list.is_empty() {
        return (vec![], None);
    }
    let mut lines = vec![blank(), heading(app, "Relationships")];
    let chosen = app.graph_edge.map(|i| i % list.len());
    for (i, edge) in list.iter().enumerate() {
        let (arrow, other) = if edge["to"] == node {
            (app.symbols.back_arrow(), name(str_of(edge, "from")))
        } else {
            (app.symbols.arrow(), name(str_of(edge, "to")))
        };
        let text = format!(
            "{} {arrow} {other} ({})",
            if chosen == Some(i) { "▶" } else { " " },
            label(str_of(edge, "kind")).to_lowercase()
        );
        lines.push(if chosen == Some(i) {
            Line::from(Span::styled(line(&text), app.theme.selected(true)))
        } else {
            muted_line(app, text)
        });
    }
    lines.push(muted_line(app, "e next edge · enter edge detail"));
    (lines, chosen.map(|i| edge_detail(list[i], name)))
}

fn packs(app: &App) -> Screen {
    let first = match status_or(app, "packs", "ChangePacks") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    // Keyset pages, newest first; counts come from the pack index, not the loaded rows.
    let pages = app.pages("packs");
    let counts = &first["counts"];
    let count = |state: &str| counts[state].as_u64().unwrap_or(0) as usize;
    let total: usize = counts.as_object().map_or(0, |c| {
        c.values().filter_map(Value::as_u64).sum::<u64>() as usize
    });
    let chips = vec![
        ("All".into(), total),
        ("Open".into(), count("OPEN")),
        ("Sealed".into(), count("SEALED")),
        ("Qualified".into(), count("QUALIFIED")),
        ("Promoted".into(), count("PROMOTED")),
        ("Quarantined".into(), count("QUARANTINED")),
    ];
    let rows: Vec<Row> = pages
        .items
        .iter()
        .map(|pack| {
            let id = str_of(pack, "id");
            Row {
                id: id.to_owned(),
                cells: vec![
                    id_cell(app, id),
                    state_cell(app, str_of(pack, "state")),
                    plain(app, str_of(pack, "title")),
                    muted(app, format!("{} files", pack["changed"])),
                    age_cell(app, &pack["updated_at"]),
                ],
                copy: None,
                tab: None,
                open: Some(Route::ChangePack(id.to_owned())),
                search: search(&[
                    ("id", id),
                    ("state", str_of(pack, "state")),
                    ("text", str_of(pack, "title")),
                    ("intent", pack["intent"].as_str().unwrap_or("")),
                ]),
            }
        })
        .collect();
    let mut screen = Screen::new(Body::Table(Table {
        key: "packs".into(),
        sections: vec![Section {
            title: None,
            columns: vec![
                col("ID", 16, 1),
                col("State", 15, 1),
                fill("Title", 18, 1),
                col("Changed", 10, 3),
                col("Updated", 8, 2),
            ],
            rows,
        }],
        empty: (
            "No ChangePacks yet.".into(),
            "Create one with :pack create \"title\", capture files, then seal it to start review."
                .into(),
        ),
        chips,
        total: pages.next.is_some().then_some(total),
    }));
    if let Some(id) = selected_row_id(app, "packs") {
        match app.value(&format!("pack:{id}")) {
            Some(detail) => {
                screen.inspector = pack_inspector(app, detail);
                screen.actions = backend_actions(detail);
                screen.explain = Some(pack_explain(app, detail));
            }
            None => {
                screen.inspector = vec![muted_line(
                    app,
                    format!("Loading {id}{}", app.symbols.ellipsis()),
                )]
            }
        }
    }
    screen.hints = vec![
        ("↑↓", "select"),
        ("enter", "open"),
        ("a", "actions"),
        ("x", "explain"),
        ("/", "filter"),
    ];
    screen
}

fn pack_inspector(app: &App, pack: &Value) -> Vec<Line<'static>> {
    let summary = &pack["summary"];
    let mut lines = vec![
        heading(
            app,
            text::short_id(str_of(pack, "id"), 24, app.symbols.ellipsis()),
        ),
        text_line(app, str_of(pack, "title")),
        blank(),
        field_state(app, "State", str_of(pack, "state")),
        field(app, "Generation", pack["generation"].to_string()),
        field(
            app,
            "Created",
            format!("{} ago", age(app, &pack["created_at"])),
        ),
        Line::from(vec![
            Span::styled(format!("{:<12}", "Changed"), app.theme.muted()),
            Span::styled(format!("{} files  ", summary["files"]), app.theme.text()),
            Span::styled(
                format!("+{}", summary["added"]),
                Style::default().fg(app.theme.diff_add),
            ),
            Span::raw(" "),
            Span::styled(
                format!("-{}", summary["removed"]),
                Style::default().fg(app.theme.diff_delete),
            ),
        ]),
    ];
    let verifications = pack["verifications"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let current: Vec<&Value> = verifications
        .iter()
        .filter(|v| v["current"] == true)
        .collect();
    if !current.is_empty() {
        let passed = current.iter().filter(|v| v["status"] == "PASS").count();
        lines.push(field(app, "Checks", format!("{passed}/{}", current.len())));
    }
    lines.push(field(
        app,
        "Evidence",
        pack["evidence"]["items"]
            .as_array()
            .map_or(0, Vec::len)
            .to_string(),
    ));
    if pack["requires_review"] == true {
        let approved = pack["reviews"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|r| r["decision"] == "APPROVE" && r["stale"] == false);
        lines.push(field_state(
            app,
            "Review",
            if approved { "APPROVED" } else { "WAITING" },
        ));
    }
    if let Some(intent) = pack["intent"].as_object() {
        lines.push(blank());
        lines.push(heading(app, "Intent"));
        lines.push(text_line(
            app,
            intent.get("title").and_then(Value::as_str).unwrap_or(""),
        ));
    }
    let deps = pack["dependencies"].as_array().cloned().unwrap_or_default();
    if !deps.is_empty() {
        lines.push(blank());
        lines.push(heading(app, "Dependencies"));
        for dep in deps {
            lines.push(muted_line(
                app,
                format!(
                    "  {} {} {}",
                    str_of(&dep, "from"),
                    app.symbols.arrow(),
                    str_of(&dep, "to")
                ),
            ));
        }
    }
    let unavailable = pack["unavailable_actions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !unavailable.is_empty() {
        lines.push(blank());
        for entry in unavailable {
            lines.push(toned(
                app,
                Tone::Warning,
                format!("{}: {}", str_of(&entry, "label"), str_of(&entry, "reason")),
            ));
        }
        lines.push(muted_line(app, "x explain"));
    }
    lines
}

fn pack(app: &App, id: &str) -> Screen {
    let value = match status_or(app, &format!("pack:{id}"), "ChangePack") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let tab = app.tab_name().unwrap_or("Summary");
    let body = match tab {
        "Diff" => Body::Diff(format!("diff-files:{id}")),
        "Verify" => verify_body(app, id, value),
        "Risk" => {
            let rows = value["evaluations"].clone();
            table_body(
                app,
                format!("risk:{id}"),
                &rows,
                &[
                    ("evaluator", "Evaluator"),
                    ("verdict", "Verdict"),
                    ("generation", "Generation"),
                    ("at", "When"),
                ],
                "No evaluations recorded. Risk is shown only when an evaluator reports it.",
            )
        }
        "Evidence" => evidence_tab(app, id, value),
        "Review" => {
            let mut lines = Vec::new();
            let reviews = value["reviews"].as_array().cloned().unwrap_or_default();
            let current: Vec<&Value> = reviews.iter().filter(|r| r["stale"] == false).collect();
            let status = if current.iter().any(|r| r["decision"] == "REJECT") {
                "REJECTED"
            } else if current.iter().any(|r| r["decision"] == "APPROVE") {
                "APPROVED"
            } else {
                "WAITING"
            };
            lines.push(field_state(app, "Review", status));
            lines.push(field(
                app,
                "Required",
                if value["requires_review"] == true {
                    "yes, by pack policy"
                } else {
                    "no review policy on this pack"
                },
            ));
            lines.push(blank());
            lines.push(heading(app, "Decisions"));
            if reviews.is_empty() {
                lines.push(muted_line(app, "No reviews yet."));
            }
            for review in &reviews {
                let stale = review["stale"] == true;
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(
                            "{} ",
                            app.symbols.tone(state_tone(str_of(review, "decision")))
                        ),
                        app.theme.tone(state_tone(str_of(review, "decision"))),
                    ),
                    Span::styled(
                        format!("{:<8}", str_of(review, "decision")),
                        app.theme.text(),
                    ),
                    Span::styled(
                        format!(
                            " {:<14}",
                            text::short_id(str_of(review, "reviewer"), 14, app.symbols.ellipsis())
                        ),
                        app.theme.muted(),
                    ),
                    Span::styled(line(str_of(review, "reason")), app.theme.text()),
                    Span::styled(
                        if stale {
                            "  (stale: candidate changed)".to_owned()
                        } else {
                            String::new()
                        },
                        app.theme.tone(Tone::Warning),
                    ),
                ]));
            }
            lines.push(blank());
            lines.push(heading(app, "Evidence"));
            for (condition, tone) in value["explain"]["satisfied"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| (str_of(e, "condition").to_owned(), Tone::Success))
                .chain(
                    value["explain"]["missing"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|e| (str_of(e, "condition").to_owned(), Tone::Danger)),
                )
            {
                lines.push(toned(app, tone, condition));
            }
            if value["state"] == "SEALED" {
                lines.push(blank());
                lines.push(Line::from(Span::styled(
                    "r begin review",
                    app.theme.accent(),
                )));
            }
            Body::Text(lines)
        }
        "Receipts" => table_body(
            app,
            format!("receipts:{id}"),
            &value["receipts"],
            &[
                ("command", "Command"),
                ("caller", "Actor"),
                ("at", "When"),
                ("digest", "Receipt"),
            ],
            "No receipts recorded for this ChangePack.",
        ),
        "Events" => table_body(
            app,
            format!("pack-events:{id}"),
            &value["events"],
            &[("kind", "Event"), ("actor", "Actor"), ("at", "When")],
            "No events.",
        ),
        "Raw" => Body::Text(raw_lines(app, &value["raw"])),
        _ => Body::Text(pack_summary(app, value)),
    };
    let mut screen = Screen::new(body);
    screen.inspector = pack_inspector(app, value);
    match tab {
        "Diff" => screen.inspector = diff_inspector(app, id, value),
        "Verify" => {
            let (inspector, detail) = verify_inspector(app, id, value);
            screen.inspector = inspector;
            screen.detail = detail;
        }
        "Evidence" => {
            if let Some(selected) = selected_row_id(app, &format!("evidence:{id}"))
                && let Some(e) = value["evidence"]["items"]
                    .as_array()
                    .and_then(|v| v.iter().find(|e| e["digest"] == selected.as_str()))
            {
                let status = if e["stale"] == true { "STALE" } else { "VALID" };
                screen.inspector = evidence_inspector(app, e, &e["evidence"], status);
            }
        }
        "Receipts" | "Events" => {
            let (key, list) = if tab == "Receipts" {
                (format!("receipts:{id}"), &value["receipts"])
            } else {
                (format!("pack-events:{id}"), &value["events"])
            };
            if let Some(selected) = selected_row_id(app, &key)
                && let Some((_, entry)) = list.as_array().and_then(|v| {
                    v.iter()
                        .enumerate()
                        .find(|(i, e)| row_key(e, *i) == selected)
                })
            {
                screen.detail = Some(record_detail(app, tab, entry));
            }
        }
        _ => {}
    }
    screen.actions = backend_actions(value);
    screen.explain = Some(pack_explain(app, value));
    screen.hints = match tab {
        "Diff" => vec![
            ("↑↓", if app.diff_lines { "lines" } else { "files" }),
            ("enter", "open file"),
            ("]c/[c", "hunks"),
            ("/", "search"),
            ("n/N", "matches"),
            ("w", "wrap"),
        ],
        "Review" => vec![
            ("r", "review"),
            ("x", "explain"),
            ("a", "actions"),
            ("tab", "tabs"),
        ],
        "Verify" => vec![
            ("↑↓", "select"),
            ("enter", "details"),
            ("r", "rerun"),
            ("e", "evidence"),
        ],
        _ => vec![
            ("tab", "tabs"),
            ("a", "actions"),
            ("x", "explain"),
            ("esc", "back"),
        ],
    };
    screen
}

fn pack_summary(app: &App, pack: &Value) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::styled(
            format!(
                "{} · ",
                text::short_id(str_of(pack, "id"), 22, app.symbols.ellipsis())
            ),
            app.theme.accent(),
        ),
        Span::styled(line(str_of(pack, "title")), app.theme.heading()),
        Span::styled(
            format!(
                "   {} {}",
                app.symbols.tone(state_tone(str_of(pack, "state"))),
                str_of(pack, "state")
            ),
            app.theme.tone(state_tone(str_of(pack, "state"))),
        ),
    ])];
    if let Some(intent) = pack["intent"].as_object() {
        lines.push(blank());
        lines.push(heading(app, "Intent"));
        lines.push(text_line(
            app,
            format!(
                "  {}",
                intent.get("title").and_then(Value::as_str).unwrap_or("")
            ),
        ));
        if let Some(description) = intent.get("description").and_then(Value::as_str) {
            lines.push(muted_line(app, format!("  {description}")));
        }
    }
    let summary = &pack["summary"];
    lines.push(blank());
    lines.push(heading(app, "Changes"));
    lines.push(Line::from(vec![
        Span::styled(format!("  {} files   ", summary["files"]), app.theme.text()),
        Span::styled(
            format!("+{}", summary["added"]),
            Style::default().fg(app.theme.diff_add),
        ),
        Span::raw(" "),
        Span::styled(
            format!("-{}", summary["removed"]),
            Style::default().fg(app.theme.diff_delete),
        ),
    ]));
    let verifications: Vec<&Value> = pack["verifications"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v["current"] == true)
        .collect();
    if !verifications.is_empty() {
        lines.push(blank());
        lines.push(heading(app, "Verification"));
        for v in verifications {
            let tone = state_tone(str_of(v, "status"));
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {} ", app.symbols.tone(tone)),
                    app.theme.tone(tone),
                ),
                Span::styled(
                    format!("{:<28}", label(str_of(v, "verifier"))),
                    app.theme.text(),
                ),
                Span::styled(str_of(v, "status").to_owned(), app.theme.tone(tone)),
            ]));
        }
    }
    let evaluations = pack["evaluations"].as_array().cloned().unwrap_or_default();
    if let Some(latest) = evaluations.last() {
        lines.push(blank());
        lines.push(heading(app, "Risk"));
        lines.push(toned(
            app,
            state_tone(str_of(latest, "verdict")),
            format!(
                "{}  {}",
                label(str_of(latest, "evaluator")),
                str_of(latest, "verdict")
            ),
        ));
    }
    if pack["revision"].is_object() {
        lines.push(blank());
        lines.push(heading(app, "Revision"));
        lines.push(muted_line(
            app,
            format!("  {}", scalar(&pack["revision"]["relation"])),
        ));
    }
    if let Some(quarantine) = pack["quarantine"].as_object() {
        lines.push(blank());
        lines.push(toned(
            app,
            Tone::Warning,
            format!(
                "Quarantined: {}",
                quarantine
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ),
        ));
    }
    lines
}

/// Seconds as `12.4s`, `3m 33s`, `1h 02m`.
pub fn duration(seconds: f64) -> String {
    let whole = seconds as u64;
    match whole {
        0..=59 => format!("{seconds:.1}s"),
        60..=3599 => format!("{}m {:02}s", whole / 60, whole % 60),
        _ => format!("{}h {:02}m", whole / 3600, whole % 3600 / 60),
    }
}

/// Completed checks plus the ones still running, in a fixed name order so rows never jump
/// as checks finish (§34, §34.2).
fn verify_body(app: &App, id: &str, value: &Value) -> Body {
    let mut rows: Vec<(String, Row)> = Vec::new();
    for v in value["verifications"].as_array().into_iter().flatten() {
        let findings = v["findings"].as_array().map_or(0, Vec::len);
        let name = label(str_of(v, "verifier"));
        rows.push((
            name.clone(),
            Row {
                id: str_of(v, "digest").to_owned(),
                cells: vec![
                    plain(app, &name),
                    state_cell(app, str_of(v, "status")),
                    muted(
                        app,
                        if findings == 0 {
                            "no findings".to_owned()
                        } else {
                            format!("{findings} findings")
                        },
                    ),
                    // The verifier records no start or end, so no duration is invented.
                    muted(app, "—"),
                    muted(
                        app,
                        if v["current"] == true {
                            "current".to_owned()
                        } else {
                            format!("gen {}", v["generation"])
                        },
                    ),
                    age_cell(app, &v["at"]),
                ],
                copy: Some(str_of(v, "digest").to_owned()),
                tab: None,
                open: None,
                search: search(&[
                    ("text", str_of(v, "verifier")),
                    ("status", str_of(v, "status")),
                ]),
            },
        ));
    }
    for e in value["running"].as_array().into_iter().flatten() {
        let name = label(str_of(e, "harness"));
        let elapsed = unix_seconds(&e["started_at"])
            .map(|t| duration((app.now - t).max(0) as f64))
            .unwrap_or_else(|| "—".into());
        rows.push((
            name.clone(),
            Row {
                id: str_of(e, "id").to_owned(),
                cells: vec![
                    plain(app, &name),
                    state_cell(app, str_of(e, "state")),
                    muted(app, str_of(e, "provider")),
                    muted(app, elapsed),
                    muted(app, "current"),
                    age_cell(app, &e["started_at"]),
                ],
                copy: None,
                tab: None,
                open: Some(Route::Execution(str_of(e, "id").to_owned())),
                search: search(&[
                    ("text", str_of(e, "harness")),
                    ("status", str_of(e, "state")),
                ]),
            },
        ));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Body::Table(Table {
        key: format!("verify:{id}"),
        sections: vec![Section {
            title: None,
            columns: vec![
                fill("Check", 18, 1),
                col("Status", 16, 1),
                col("Output", 14, 2),
                col("Duration", 9, 2),
                col("Generation", 11, 3),
                col("When", 6, 4),
            ],
            rows: rows.into_iter().map(|(_, r)| r).collect(),
        }],
        empty: (
            "No verification has run for this pack.".into(),
            "Seal the pack, then run verification or language checks from Actions.".into(),
        ),
        chips: vec![],
        total: None,
    })
}

/// Verification summary (§34) and the selected check's detail (§34.1).
fn verify_inspector(app: &App, id: &str, pack: &Value) -> (Vec<Line<'static>>, Option<Detail>) {
    let current: Vec<&Value> = pack["verifications"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v["current"] == true)
        .collect();
    let passed = current.iter().filter(|v| v["status"] == "PASS").count();
    let running = pack["running"].as_array().map_or(0, Vec::len);
    let mut lines = vec![heading(app, "Verification summary"), blank()];
    lines.push(if current.is_empty() {
        muted_line(app, "No current checks")
    } else if passed == current.len() {
        toned(app, Tone::Success, "All checks passed")
    } else {
        toned(
            app,
            Tone::Danger,
            format!("{} checks failing", current.len() - passed),
        )
    });
    lines.push(text_line(
        app,
        format!("{passed} / {} checks", current.len()),
    ));
    if running > 0 {
        lines.push(toned(app, Tone::Running, format!("{running} running")));
    }
    if let Some(last) = current.iter().filter_map(|v| v["at"].as_str()).max() {
        lines.push(field(app, "Last run", exact(app, &Value::from(last))));
    }
    let selected = selected_row_id(app, &format!("verify:{id}"));
    let check = selected.as_deref().and_then(|d| {
        pack["verifications"]
            .as_array()?
            .iter()
            .find(|v| v["digest"] == d)
    });
    let Some(v) = check else {
        return (lines, None);
    };
    let mut detail = vec![
        (
            Tone::Neutral,
            format!("Check       {}", str_of(v, "verifier")),
        ),
        (
            state_tone(str_of(v, "status")),
            format!("Status      {}", str_of(v, "status")),
        ),
        (
            Tone::Neutral,
            format!(
                "Generation  {}{}",
                v["generation"],
                if v["current"] == true {
                    " (current)"
                } else {
                    " (earlier candidate)"
                }
            ),
        ),
        (
            Tone::Neutral,
            format!("Completed   {}", exact(app, &v["at"])),
        ),
        (
            Tone::Neutral,
            "Duration    not recorded by the verifier".into(),
        ),
        (
            Tone::Neutral,
            format!("Record      {}", str_of(v, "digest")),
        ),
        (Tone::Neutral, String::new()),
        (Tone::Neutral, "Findings".into()),
    ];
    let findings = v["findings"].as_array().cloned().unwrap_or_default();
    if findings.is_empty() {
        detail.push((Tone::Success, "none".into()));
    }
    for finding in findings {
        detail.push((Tone::Warning, scalar(&finding)));
    }
    detail.push((Tone::Neutral, String::new()));
    detail.push((Tone::Neutral, "Evidence produced".into()));
    match v["evidence"].as_array().filter(|e| !e.is_empty()) {
        Some(evidence) => detail.extend(evidence.iter().map(|e| (Tone::Neutral, scalar(e)))),
        None => detail.push((Tone::Neutral, "none recorded".into())),
    }
    detail.push((Tone::Neutral, String::new()));
    detail.push((
        Tone::Neutral,
        if pack["actions"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|a| a["id"] == "verify")
        {
            "r rerun verification".into()
        } else {
            "Rerun is not available in this state.".into()
        },
    ));
    lines.push(blank());
    lines.push(heading(app, label(str_of(v, "verifier"))));
    lines.push(field_state(app, "Status", str_of(v, "status")));
    lines.push(muted_line(app, "enter details"));
    (lines, Some((label(str_of(v, "verifier")), detail)))
}

/// Evidence grouped by purpose with the requirement tally (§36).
fn evidence_tab(app: &App, id: &str, pack: &Value) -> Body {
    let group = |kind: &str| {
        let kind = kind.to_lowercase();
        if kind.contains("review") || kind.contains("approval") || kind.contains("rejection") {
            "Review"
        } else if kind.contains("verif") || kind.contains("check") || kind.contains("test") {
            "Verification"
        } else {
            "Artifacts"
        }
    };
    let items = pack["evidence"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let satisfied = pack["explain"]["satisfied"].as_array().map_or(0, Vec::len);
    let missing = pack["explain"]["missing"].as_array().map_or(0, Vec::len);
    let mut sections = Vec::new();
    for name in ["Verification", "Artifacts", "Review"] {
        let rows: Vec<Row> = items
            .iter()
            .filter(|e| group(str_of(&e["evidence"], "kind")) == name)
            .map(|e| {
                let body = &e["evidence"];
                let stale = e["stale"] == true;
                Row {
                    id: str_of(e, "digest").to_owned(),
                    cells: vec![
                        id_cell(app, str_of(body, "id")),
                        plain(app, label(str_of(body, "kind"))),
                        state_cell(app, if stale { "STALE" } else { "VALID" }),
                        age_cell(app, &body["created_at"]),
                    ],
                    copy: Some(str_of(e, "digest").to_owned()),
                    tab: None,
                    open: None,
                    search: search(&[
                        ("type", str_of(body, "kind")),
                        ("status", if stale { "stale" } else { "valid" }),
                        ("digest", str_of(e, "digest")),
                    ]),
                }
            })
            .collect();
        if !rows.is_empty() {
            sections.push(Section {
                title: Some(name.into()),
                columns: vec![
                    col("ID", 16, 1),
                    fill("Type", 18, 1),
                    col("Status", 11, 1),
                    col("Created", 8, 2),
                ],
                rows,
            });
        }
    }
    if !sections.is_empty() {
        sections[0].title = Some(format!(
            "Required {satisfied} / {} satisfied · {}",
            satisfied + missing,
            sections[0].title.clone().unwrap_or_default()
        ));
    }
    Body::Table(Table {
        key: format!("evidence:{id}"),
        sections,
        empty: (
            "No evidence is attached to this ChangePack.".into(),
            format!("Required {satisfied} / {} satisfied.", satisfied + missing),
        ),
        chips: vec![],
        total: None,
    })
}

/// Receipt (§38) or event detail behind Enter.
fn record_detail(app: &App, tab: &str, entry: &Value) -> (String, Vec<(Tone, String)>) {
    let mut lines = Vec::new();
    if tab == "Receipts" {
        lines.push((
            Tone::Neutral,
            format!("Command   {}", str_of(entry, "command")),
        ));
        lines.push((
            Tone::Neutral,
            format!("Actor     {}", str_of(entry, "caller")),
        ));
        lines.push((
            Tone::Neutral,
            format!("Time      {}", exact(app, &entry["at"])),
        ));
        lines.push((
            Tone::Neutral,
            format!("Receipt   {}", str_of(entry, "digest")),
        ));
        lines.push((Tone::Neutral, String::new()));
        lines.push((Tone::Neutral, "Result".into()));
    } else {
        lines.push((
            Tone::Neutral,
            format!("Event     {}", str_of(entry, "kind")),
        ));
        lines.push((
            Tone::Neutral,
            format!("Actor     {}", entry["actor"].as_str().unwrap_or("—")),
        ));
        lines.push((
            Tone::Neutral,
            format!("Time      {}", exact(app, &entry["at"])),
        ));
        lines.push((Tone::Neutral, format!("Sequence  {}", entry["sequence"])));
        lines.push((Tone::Neutral, String::new()));
        lines.push((Tone::Neutral, "Body".into()));
    }
    let raw = if tab == "Receipts" {
        &entry["result"]
    } else {
        &entry["body"]
    };
    for line in serde_json::to_string_pretty(raw)
        .unwrap_or_default()
        .lines()
    {
        lines.push((Tone::Neutral, format!("  {}", text::line(line))));
    }
    let title = if tab == "Receipts" {
        format!("Receipt · {}", str_of(entry, "command"))
    } else {
        format!("Event · {}", str_of(entry, "kind"))
    };
    (title, lines)
}

fn diff_inspector(app: &App, id: &str, pack: &Value) -> Vec<Line<'static>> {
    let files = pack["files"].as_array().cloned().unwrap_or_default();
    let index = app
        .collections
        .get(&format!("diff-files:{id}"))
        .map_or(0, |c| c.selected_index);
    let Some(file) = files.get(index.min(files.len().saturating_sub(1))) else {
        return vec![muted_line(app, "No files in this ChangePack.")];
    };
    let path = str_of(file, "path");
    let mut lines = vec![
        heading(app, "File"),
        text_line(app, text::middle(path, 40, app.symbols.ellipsis())),
        blank(),
        field_state(app, "Status", str_of(file, "status")),
        Line::from(vec![
            Span::styled(format!("{:<12}", "Lines"), app.theme.muted()),
            Span::styled(
                format!("+{}", file["added"]),
                Style::default().fg(app.theme.diff_add),
            ),
            Span::raw(" "),
            Span::styled(
                format!("-{}", file["removed"]),
                Style::default().fg(app.theme.diff_delete),
            ),
        ]),
        field(app, "Size", format!("{} bytes", file["size"])),
        field(
            app,
            "Digest",
            text::middle(str_of(file, "digest"), 24, app.symbols.ellipsis()),
        ),
    ];
    if let Some(diff) = app.value(&format!("diff:{id}:{path}")) {
        let hunks = diff["lines"]
            .as_array()
            .map_or(0, |l| l.iter().filter(|x| x["kind"] == "hunk").count());
        lines.push(field(app, "Hunks", hunks.to_string()));
        if diff["truncated"] == true {
            lines.push(toned(app, Tone::Warning, "diff truncated"));
        }
    }
    lines
}

fn baselines(app: &App) -> Screen {
    let value = match status_or(app, "baselines", "Baselines") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let aliases = app.value("aliases").cloned().unwrap_or(json!([]));
    let active = app
        .value("status")
        .and_then(|s| s["active_baseline"]["id"].as_str())
        .map(str::to_owned);
    let rows: Vec<Row> = value
        .as_array()
        .into_iter()
        .flatten()
        .rev()
        .map(|b| {
            let id = str_of(b, "id");
            let names: Vec<String> = aliases
                .as_array()
                .into_iter()
                .flatten()
                .filter(|a| a["baseline_id"] == id)
                .map(|a| str_of(a, "alias").to_owned())
                .collect();
            let detail = app.value(&format!("baseline:{id}"));
            let state = match detail {
                Some(d) if d["validation"]["valid"] == true => "VALID",
                Some(_) => "INVALID",
                None => "—",
            };
            Row {
                id: id.to_owned(),
                cells: vec![
                    id_cell(app, id),
                    plain(app, str_of(b, "label")),
                    muted(app, names.join(", ")),
                    muted(
                        app,
                        detail.map_or("—".into(), |d| {
                            d["members"].as_array().map_or(0, Vec::len).to_string()
                        }),
                    ),
                    if state == "—" {
                        muted(app, state)
                    } else {
                        state_cell(app, state)
                    },
                    muted(
                        app,
                        if active.as_deref() == Some(id) {
                            "active"
                        } else {
                            ""
                        },
                    ),
                    age_cell(app, &b["created_at"]),
                ],
                copy: None,
                tab: None,
                open: Some(Route::Baseline(id.to_owned())),
                search: search(&[
                    ("id", id),
                    ("text", str_of(b, "label")),
                    ("alias", &names.join(" ")),
                ]),
            }
        })
        .collect();
    let mut screen = Screen::new(Body::Table(Table {
        key: "baselines".into(),
        sections: vec![Section {
            title: None,
            columns: vec![col("ID", 16, 1), fill("Label", 12, 1), col("Aliases", 12, 3), col("Packs", 6, 2), col("State", 11, 1), col("", 7, 2), col("Created", 8, 4)],
            rows,
        }],
        empty: ("No Baselines yet.".into(), "A Baseline is an independent composition of promoted ChangePacks. Create one with :baseline create <label> <promoted digest…>.".into()),
        chips: vec![],
        total: None,
    }));
    if let Some(id) = selected_row_id(app, "baselines") {
        match app.value(&format!("baseline:{id}")) {
            Some(detail) => {
                screen.inspector = baseline_inspector(app, detail);
                screen.actions = baseline_actions(&id);
            }
            None => {
                screen.inspector = vec![muted_line(
                    app,
                    format!("Loading {id}{}", app.symbols.ellipsis()),
                )]
            }
        }
    }
    screen
}

fn baseline_inspector(app: &App, b: &Value) -> Vec<Line<'static>> {
    let mut lines = vec![
        heading(
            app,
            format!(
                "Baseline {}",
                text::short_id(str_of(b, "id"), 20, app.symbols.ellipsis())
            ),
        ),
        text_line(app, b["label"].as_str().unwrap_or("")),
        blank(),
        field_state(
            app,
            "Validation",
            if b["validation"]["valid"] == true {
                "VALID"
            } else {
                "INVALID"
            },
        ),
        field(
            app,
            "Members",
            b["members"].as_array().map_or(0, Vec::len).to_string(),
        ),
        field(
            app,
            "Heads",
            b["heads"].as_array().map_or(0, Vec::len).to_string(),
        ),
        field(
            app,
            "Active",
            if b["active"] == true { "yes" } else { "no" },
        ),
    ];
    for problem in b["validation"]["problems"].as_array().into_iter().flatten() {
        lines.push(toned(app, Tone::Danger, scalar(problem)));
    }
    lines
}

fn baseline_actions(id: &str) -> Vec<PaletteItem> {
    vec![
        item(
            "Activate",
            "baseline activate (active pointer only)",
            run("Activate baseline", &["baseline", "activate", id], true),
        ),
        item(
            "Validate",
            "baseline validate",
            run("Validate baseline", &["baseline", "validate", id], false),
        ),
        item(
            "Plan materialization",
            "baseline materialize (dry run)",
            run(
                "Plan materialization",
                &["baseline", "materialize", id],
                false,
            ),
        ),
        item(
            "Set alias",
            "baseline alias set",
            Target::Prompt {
                args: vec!["baseline".into(), "alias".into(), "set".into()],
                suffix: vec![id.into()],
                field: "Alias".into(),
                confirm: false,
                label: "Set alias".into(),
            },
        ),
        item(
            "Graph",
            "baseline graph closure",
            run("Baseline closure", &["baseline", "graph", id], false),
        ),
    ]
}

fn baseline(app: &App, id: &str) -> Screen {
    let value = match status_or(app, &format!("baseline:{id}"), "Baseline") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let members = value["members"].as_array().cloned().unwrap_or_default();
    let tab = app.tab_name().unwrap_or("Graph");
    let body = match tab {
        "Packs" => {
            let rows = members
                .iter()
                .map(|m| {
                    let pack = m["pack"].as_str().unwrap_or("");
                    Row {
                        id: str_of(m, "digest").to_owned(),
                        cells: vec![
                            id_cell(app, pack),
                            plain(app, m["title"].as_str().unwrap_or("(not in this Project)")),
                            state_cell(app, m["state"].as_str().unwrap_or("UNKNOWN")),
                            muted(app, if m["head"] == true { "head" } else { "" }),
                            muted(
                                app,
                                text::middle(str_of(m, "digest"), 22, app.symbols.ellipsis()),
                            ),
                        ],
                        copy: None,
                        tab: None,
                        open: (!pack.is_empty()).then(|| Route::ChangePack(pack.to_owned())),
                        search: search(&[
                            ("id", pack),
                            ("text", m["title"].as_str().unwrap_or("")),
                        ]),
                    }
                })
                .collect();
            Body::Table(Table {
                key: format!("baseline-packs:{id}"),
                sections: vec![Section {
                    title: None,
                    columns: vec![
                        col("Pack", 16, 1),
                        fill("Title", 14, 1),
                        col("State", 14, 2),
                        col("", 5, 3),
                        col("Promoted digest", 22, 4),
                    ],
                    rows,
                }],
                empty: ("This Baseline has no members.".into(), String::new()),
                chips: vec![],
                total: None,
            })
        }
        "Relations" => table_body(
            app,
            format!("baseline-edges:{id}"),
            &value["edges"],
            &[("from", "From"), ("kind", "Relation"), ("to", "To")],
            "No composition relations recorded between members.",
        ),
        "History" => match app.value(&format!("baseline-history:{id}")) {
            Some(history) => {
                let rows = history
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|e| activity_row(app, e, true))
                    .collect();
                Body::Table(Table {
                    key: format!("baseline-history:{id}"),
                    sections: vec![Section {
                        title: None,
                        columns: activity_columns(),
                        rows,
                    }],
                    empty: (
                        "No recorded history for this Baseline.".into(),
                        String::new(),
                    ),
                    chips: vec![],
                    total: None,
                })
            }
            None => Body::Status {
                tone: Tone::Running,
                title: "Loading history…".into(),
                body: String::new(),
            },
        },
        "Explain" => Body::Text(
            baseline_explain(app, value)
                .1
                .into_iter()
                .map(|(tone, text)| {
                    if text.is_empty() {
                        blank()
                    } else {
                        toned(app, tone, text)
                    }
                })
                .collect(),
        ),
        "Raw" => Body::Text(raw_lines(app, &value["raw"])),
        _ => {
            let digest_index = |digest: &Value| members.iter().position(|m| m["digest"] == *digest);
            let nodes = members
                .iter()
                .map(|m| GraphNode {
                    id: str_of(m, "digest").to_owned(),
                    label: m["title"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| text::middle(str_of(m, "digest"), 14, "…")),
                    tone: state_tone(m["state"].as_str().unwrap_or("")),
                    open: m["pack"].as_str().map(|p| Route::ChangePack(p.to_owned())),
                    search: search(&[
                        ("text", m["title"].as_str().unwrap_or("")),
                        ("id", m["pack"].as_str().unwrap_or("")),
                        ("digest", str_of(m, "digest")),
                        ("state", m["state"].as_str().unwrap_or("")),
                    ]),
                })
                .collect();
            let edges = value["edges"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| {
                    Some((
                        digest_index(&e["from"])?,
                        digest_index(&e["to"])?,
                        str_of(e, "kind").to_owned(),
                    ))
                })
                .collect();
            if app.graph_list {
                return baseline_list_fallback(app, id, value);
            }
            graph_body(app, format!("baseline-graph:{id}"), nodes, edges, false)
        }
    };
    let mut screen = Screen::new(body);
    screen.inspector = baseline_inspector(app, value);
    if tab == "Graph"
        && let Some(selected) = selected_row_id(app, &format!("baseline-graph:{id}"))
        && let Some(member) = members.iter().find(|m| m["digest"] == selected.as_str())
    {
        screen.inspector.push(blank());
        screen
            .inspector
            .push(heading(app, member["title"].as_str().unwrap_or("member")));
        screen.inspector.push(field_state(
            app,
            "State",
            member["state"].as_str().unwrap_or("UNKNOWN"),
        ));
        screen
            .inspector
            .push(field(app, "Pack", member["pack"].as_str().unwrap_or("—")));
        screen.inspector.push(field(
            app,
            "Head",
            if member["head"] == true { "yes" } else { "no" },
        ));
        let name = |digest: &str| {
            members
                .iter()
                .find(|m| m["digest"] == digest)
                .and_then(|m| m["title"].as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| text::middle(digest, 18, app.symbols.ellipsis()))
        };
        let empty = Vec::new();
        let edges = value["edges"].as_array().unwrap_or(&empty);
        let (lines, detail) = relations(app, edges, &selected, &name);
        screen.inspector.extend(lines);
        screen.detail = detail;
    }
    screen.actions = baseline_actions(id);
    screen.explain = Some(baseline_explain(app, value));
    screen.hints = vec![
        ("tab", "tabs"),
        ("hjkl", "navigate"),
        ("v", "list"),
        ("z", "fullscreen"),
        ("x", "explain"),
    ];
    screen
}

fn baseline_list_fallback(app: &App, id: &str, value: &Value) -> Screen {
    let mut screen = Screen::new(table_body(
        app,
        format!("baseline-graph:{id}"),
        &value["members"],
        &[
            ("title", "Pack"),
            ("state", "State"),
            ("head", "Head"),
            ("digest", "Digest"),
        ],
        "This Baseline has no members.",
    ));
    screen.inspector = baseline_inspector(app, value);
    screen.actions = baseline_actions(id);
    screen
}

fn baseline_explain(app: &App, value: &Value) -> (String, Vec<(Tone, String)>) {
    let mut lines = Vec::new();
    let valid = value["validation"]["valid"] == true;
    lines.push((
        if valid { Tone::Success } else { Tone::Danger },
        format!(
            "OpenAEVC validation: {}",
            if valid { "valid" } else { "invalid" }
        ),
    ));
    for problem in value["validation"]["problems"]
        .as_array()
        .into_iter()
        .flatten()
    {
        lines.push((Tone::Danger, scalar(problem)));
    }
    lines.push((Tone::Neutral, String::new()));
    lines.push((
        Tone::Neutral,
        "A Baseline is an independent composition commitment, not a version of another Baseline."
            .into(),
    ));
    lines.push((
        Tone::Neutral,
        format!(
            "{} members, {} lineage heads.",
            value["members"].as_array().map_or(0, Vec::len),
            value["heads"].as_array().map_or(0, Vec::len)
        ),
    ));
    let _ = app;
    (format!("Baseline {}", str_of(value, "id")), lines)
}

fn evidence(app: &App) -> Screen {
    if let Err(screen) = status_or(app, "evidence", "evidence") {
        return *screen;
    }
    let pages = app.pages("evidence");
    let status = |e: &Value| if e["stale"] == true { "STALE" } else { "VALID" };
    let rows: Vec<Row> = pages
        .items
        .iter()
        .map(|e| {
            let digest = str_of(e, "digest");
            let body = &e["evidence"];
            let attached = e["pack_title"].as_str().unwrap_or(str_of(e, "pack"));
            Row {
                id: digest.to_owned(),
                cells: vec![
                    id_cell(app, str_of(body, "id")),
                    plain(app, label(str_of(body, "kind"))),
                    muted(
                        app,
                        text::short_id(str_of(body, "producer"), 14, app.symbols.ellipsis()),
                    ),
                    plain(app, attached),
                    state_cell(app, status(e)),
                    age_cell(app, &body["created_at"]),
                ],
                copy: None,
                tab: None,
                open: e["pack"].as_str().map(|p| Route::ChangePack(p.to_owned())),
                search: search(&[
                    ("digest", digest),
                    ("id", str_of(body, "id")),
                    ("type", str_of(body, "kind")),
                    ("producer", str_of(body, "producer")),
                    ("attached", &format!("{} {attached}", str_of(e, "pack"))),
                    ("status", status(e)),
                    ("created", str_of(body, "created_at")),
                    ("text", attached),
                ]),
            }
        })
        .collect();
    let mut screen = Screen::new(Body::Table(Table {
        key: "evidence".into(),
        sections: vec![Section {
            title: None,
            columns: vec![
                col("ID", 16, 1),
                fill("Type", 16, 1),
                col("Producer", 14, 3),
                col("Attached to", 20, 2),
                col("Status", 11, 1),
                col("Created", 8, 2),
            ],
            rows,
        }],
        empty: (
            "No evidence recorded yet.".into(),
            "Evidence is registered against sealed candidates by checks, reviews and tools.".into(),
        ),
        chips: vec![],
        total: None,
    }));
    if let Some(id) = selected_row_id(app, "evidence")
        && let Some(e) = pages.items.iter().find(|e| e["digest"] == id.as_str())
    {
        screen.inspector = evidence_inspector(app, e, &e["evidence"], status(e));
        // Reverse references (§41): every event naming this digest, from the event index.
        screen.inspector.push(blank());
        screen.inspector.push(heading(app, "Used by"));
        match app
            .value(&format!("evidence-refs:{id}"))
            .and_then(Value::as_array)
        {
            Some(refs) => {
                for r in refs.iter().filter(|r| r["kind"] != "evidence.registered") {
                    screen.inspector.push(muted_line(
                        app,
                        format!("  {} {}", str_of(r, "kind"), str_of(r, "subject")),
                    ));
                }
                if refs.iter().all(|r| r["kind"] == "evidence.registered") {
                    screen
                        .inspector
                        .push(muted_line(app, "  no other references"));
                }
            }
            None => screen.inspector.push(muted_line(
                app,
                format!("  Loading{}", app.symbols.ellipsis()),
            )),
        }
        screen.actions.push(item(
            "Show evidence",
            "evidence show",
            run("Evidence", &["evidence", "show", &id], false),
        ));
    }
    screen.hints = vec![
        ("↑↓", "navigate"),
        ("enter", "open pack"),
        ("/", "filter type: producer: attached: status: created:"),
    ];
    screen
}

/// Evidence detail shared by the Evidence screen and the ChangePack Evidence tab (§36).
fn evidence_inspector(app: &App, row: &Value, body: &Value, status: &str) -> Vec<Line<'static>> {
    vec![
        heading(app, format!("Evidence {}", str_of(body, "id"))),
        blank(),
        field(app, "Type", label(str_of(body, "kind"))),
        field(
            app,
            "Digest",
            text::middle(str_of(row, "digest"), 30, app.symbols.ellipsis()),
        ),
        field(app, "Created", exact(app, &body["created_at"])),
        field(app, "Producer", str_of(body, "producer")),
        field(app, "Media", str_of(body, "media_type")),
        field(
            app,
            "Attached to",
            row["pack_title"].as_str().unwrap_or(str_of(body, "pack")),
        ),
        field(app, "Generation", body["generation"].to_string()),
        field_state(app, "Status", status),
    ]
}

fn events(app: &App) -> Screen {
    let value = match status_or(app, "events", "events") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let rows: Vec<Row> = value
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| activity_row(app, e, false))
        .collect();
    let mut screen = Screen::new(Body::Table(Table {
        key: "events".into(),
        sections: vec![Section {
            title: None,
            columns: activity_columns(),
            rows,
        }],
        empty: ("No events yet.".into(), String::new()),
        chips: vec![],
        total: None,
    }));
    if let Some(id) = selected_row_id(app, "events")
        && let Some(e) = value
            .as_array()
            .and_then(|v| v.iter().find(|e| event_id(e) == id))
    {
        screen.inspector = event_inspector(app, e);
        if let Some(route) = e["subject"]
            .as_str()
            .or_else(|| e["subjects"][0].as_str())
            .and_then(route_for_id)
        {
            screen
                .actions
                .push(item("Open object", &route.title(), Target::Open(route)));
        }
    }
    screen.hints = vec![
        ("↑↓", "navigate"),
        ("/", "filter actor: type: object: after:"),
        (
            "f",
            if app.events_live {
                "pause live"
            } else {
                "live"
            },
        ),
    ];
    screen
}

/// Event detail (§42.2): exact time, actor, type, object, related references, raw event.
fn event_inspector(app: &App, e: &Value) -> Vec<Line<'static>> {
    let mut lines = vec![
        heading(app, str_of(e, "kind")),
        muted_line(app, event_id(e)),
        blank(),
        field(app, "Time", exact(app, event_time(e))),
        field(app, "Actor", e["actor"].as_str().unwrap_or("—")),
        field(app, "Source", str_of(e, "source")),
    ];
    let subjects: Vec<String> = e["subjects"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect();
    if !subjects.is_empty() {
        lines.push(blank());
        lines.push(heading(app, "Objects"));
        for subject in subjects {
            lines.push(muted_line(
                app,
                format!("  {} {subject}", app.symbols.arrow()),
            ));
        }
    }
    if let Some(detail) = e["detail"].as_str() {
        lines.push(field(app, "Detail", detail));
    }
    lines.push(blank());
    lines.push(heading(app, "Raw"));
    lines.extend(raw_lines(app, e));
    lines
}

fn projects(app: &App) -> Screen {
    let value = match status_or(app, "projects", "projects") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let current = app
        .value("status")
        .and_then(|s| s["project"]["project_id"].as_str())
        .map(str::to_owned);
    let rows: Vec<Row> = value
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            let id = str_of(p, "project_id");
            let health = app
                .value(&format!("project-health:{id}"))
                .map(|h| str_of(h, "status").to_owned());
            Row {
                id: id.to_owned(),
                cells: vec![
                    plain(app, str_of(p, "name")),
                    muted(
                        app,
                        text::middle(str_of(p, "path"), 34, app.symbols.ellipsis()),
                    ),
                    match &health {
                        Some(state) => state_cell(app, state),
                        None => muted(app, "—"),
                    },
                    muted(
                        app,
                        if current.as_deref() == Some(id) {
                            "current"
                        } else {
                            ""
                        },
                    ),
                ],
                copy: Some(str_of(p, "path").to_owned()),
                tab: None,
                open: None,
                search: search(&[
                    ("text", str_of(p, "name")),
                    ("id", id),
                    ("path", str_of(p, "path")),
                ]),
            }
        })
        .collect();
    // First run (§87): no Project is open, so the registered ones are the way in.
    let title = app
        .welcome
        .as_ref()
        .map(|_| "Welcome to Calve · No project is currently open · Detected projects".to_owned());
    let empty = if app.welcome.is_some() {
        (
            "No Calve project found.".into(),
            "Run calve init <path>, or :project register <path>.".into(),
        )
    } else {
        (
            "No registered Projects.".into(),
            "Run calve init in a directory, or :project register <path>.".into(),
        )
    };
    let mut screen = Screen::new(Body::Table(Table {
        key: "projects".into(),
        sections: vec![Section {
            title,
            columns: vec![
                fill("Project", 14, 1),
                col("Path", 34, 3),
                col("Health", 20, 1),
                col("", 8, 2),
            ],
            rows,
        }],
        empty,
        chips: vec![],
        total: None,
    }));
    let register = item(
        "Register",
        "project register <path>",
        Target::Prompt {
            args: vec!["project".into(), "register".into()],
            suffix: vec![],
            field: "Project directory".into(),
            confirm: false,
            label: "Register project".into(),
        },
    );
    if let Some(id) = selected_row_id(app, "projects")
        && let Some(project) = value
            .as_array()
            .and_then(|v| v.iter().find(|p| p["project_id"] == id.as_str()))
    {
        let root = str_of(project, "path").to_owned();
        screen.inspector = vec![
            heading(app, str_of(project, "name")),
            muted_line(app, &id),
            muted_line(app, &root),
        ];
        if let Some(health) = app.value(&format!("project-health:{id}")) {
            screen.inspector.push(blank());
            screen
                .inspector
                .push(field_state(app, "Health", str_of(health, "status")));
            for finding in health["findings"].as_array().into_iter().flatten() {
                screen
                    .inspector
                    .push(toned(app, Tone::Warning, str_of(finding, "message")));
            }
        }
        screen.actions = vec![
            item(
                "Open",
                "switch the console to this Project",
                Target::OpenProject {
                    root: root.clone(),
                    route: Route::Overview,
                },
            ),
            item(
                "Doctor",
                "open this Project's diagnostics",
                Target::OpenProject {
                    root,
                    route: Route::Doctor,
                },
            ),
            item(
                "Health check",
                "project health",
                run("Project health", &["project", "health", &id], false),
            ),
            register,
            item(
                "Relocate",
                "project relocate <new path>",
                Target::Prompt {
                    args: vec!["project".into(), "relocate".into(), id.clone()],
                    suffix: vec![],
                    field: "New directory".into(),
                    confirm: false,
                    label: "Relocate project".into(),
                },
            ),
            item(
                "Unregister",
                "project unregister",
                run("Unregister project", &["project", "unregister", &id], true),
            ),
        ];
    } else {
        screen.actions = vec![register];
    }
    screen.hints = vec![
        ("↑↓", "navigate"),
        ("enter", "open project"),
        ("a", "actions"),
    ];
    screen
}

fn inbox(app: &App) -> Screen {
    let value = match status_or(app, "inbox", "inbox") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let rows: Vec<Row> = value
        .as_array()
        .into_iter()
        .flatten()
        .map(|i| {
            let key = str_of(i, "source_key");
            let tone = match str_of(i, "severity") {
                "danger" => Tone::Danger,
                "warning" => Tone::Warning,
                _ => Tone::Neutral,
            };
            let subject = str_of(i, "subject");
            Row {
                id: key.to_owned(),
                cells: vec![
                    cell(
                        format!("{} {}", app.symbols.tone(tone), str_of(i, "severity")),
                        app.theme.tone(tone),
                    ),
                    muted(app, label(str_of(i, "kind"))),
                    plain(app, str_of(i, "summary")),
                    muted(
                        app,
                        if i["acknowledged_at"].is_null() {
                            ""
                        } else {
                            "ack"
                        },
                    ),
                    age_cell(app, &i["first_seen"]),
                ],
                copy: None,
                tab: None,
                open: match str_of(i, "kind") {
                    "execution" => Some(Route::Execution(subject.to_owned())),
                    "task_inconsistency" => Some(Route::Task(subject.to_owned())),
                    _ => Some(Route::ChangePack(subject.to_owned())),
                },
                search: search(&[
                    ("type", str_of(i, "kind")),
                    ("text", str_of(i, "summary")),
                    ("severity", str_of(i, "severity")),
                ]),
            }
        })
        .collect();
    let mut screen = Screen::new(Body::Table(Table {
        key: "inbox".into(),
        sections: vec![Section { title: None, columns: vec![col("Severity", 11, 1), col("Type", 18, 2), fill("Message", 20, 1), col("", 4, 3), col("Age", 6, 2)], rows }],
        empty: ("Inbox is clear.".into(), "Attention items appear when executions fail, packs are quarantined or reviews go stale.".into()),
        chips: vec![],
        total: None,
    }));
    let marked: Vec<String> = app
        .collections
        .get("inbox")
        .map(|c| c.marked.iter().cloned().collect())
        .unwrap_or_default();
    if !marked.is_empty() {
        // Bulk actions state their count (§16).
        let mut args = vec!["inbox".to_owned(), "ack".to_owned()];
        args.extend(marked.iter().cloned());
        screen.actions.push(item(
            &format!("Acknowledge {} selected", marked.len()),
            "inbox ack (marked items)",
            Target::Run {
                args,
                confirm: false,
                label: format!("Acknowledge {} items", marked.len()),
            },
        ));
    }
    if let Some(key) = selected_row_id(app, "inbox") {
        screen.actions.extend([
            item(
                "Acknowledge",
                "inbox ack",
                run("Acknowledge", &["inbox", "ack", &key], false),
            ),
            item(
                "Unacknowledge",
                "inbox unack",
                run("Unacknowledge", &["inbox", "unack", &key], false),
            ),
            item(
                "Snooze",
                "inbox snooze --until (e.g. 2h)",
                Target::Prompt {
                    args: vec![
                        "inbox".into(),
                        "snooze".into(),
                        key.clone(),
                        "--until".into(),
                    ],
                    suffix: vec![],
                    field: "Until".into(),
                    confirm: false,
                    label: "Snooze".into(),
                },
            ),
            item(
                "Clear resolved",
                "inbox clear-resolved",
                run("Clear resolved", &["inbox", "clear-resolved"], true),
            ),
        ]);
    }
    screen.hints = vec![
        ("↑↓", "navigate"),
        ("enter", "open source"),
        ("a", "actions"),
    ];
    screen
}

fn doctor(app: &App) -> Screen {
    let value = match status_or(app, "doctor", "diagnostics") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let mut checks = vec![
        (
            "Product database",
            if value["product_db"]["ok"] == true {
                "PASS"
            } else {
                "FAIL"
            },
            str_of(&value["product_db"], "integrity").to_owned(),
        ),
        (
            "OpenAEVC runtime",
            "PASS",
            format!("protocol {}", str_of(&value["compatibility"], "protocol")),
        ),
        (
            "Extension contract",
            "PASS",
            str_of(&value["compatibility"], "extension_contract").to_owned(),
        ),
    ];
    for extension in value["extensions"].as_array().into_iter().flatten() {
        checks.push((
            "Extension",
            if extension["healthy"] == true {
                "PASS"
            } else {
                "WARN"
            },
            str_of(extension, "id").to_owned(),
        ));
    }
    for finding in value["findings"].as_array().into_iter().flatten() {
        checks.push(("Finding", "WARN", str_of(finding, "message").to_owned()));
    }
    let rows: Vec<Row> = checks
        .iter()
        .enumerate()
        .map(|(i, (name, state, detail))| Row {
            id: format!("check:{i}"),
            cells: vec![
                plain(app, *name),
                state_cell(app, state),
                muted(app, detail),
            ],
            copy: None,
            tab: None,
            open: None,
            search: search(&[("text", name), ("status", state)]),
        })
        .collect();
    let mut screen = Screen::new(Body::Table(Table {
        key: "doctor".into(),
        sections: vec![Section {
            title: None,
            columns: vec![
                col("Check", 20, 1),
                col("Status", 10, 1),
                fill("Detail", 20, 2),
            ],
            rows,
        }],
        empty: ("No diagnostics.".into(), String::new()),
        chips: vec![],
        total: None,
    }));
    let index = app
        .collections
        .get("doctor")
        .map_or(0, |c| c.selected_index);
    let findings = value["findings"].as_array().cloned().unwrap_or_default();
    let base = checks.len() - findings.len();
    screen.inspector = if index >= base {
        let finding = &findings[index - base];
        vec![
            heading(app, str_of(finding, "code")),
            blank(),
            field_state(app, "Status", "WARN"),
            blank(),
            heading(app, "Finding"),
            text_line(app, str_of(finding, "message")),
            blank(),
            heading(app, "Suggested action"),
            text_line(app, str_of(finding, "remedy")),
        ]
    } else {
        vec![
            heading(app, "Project"),
            muted_line(app, str_of(value, "project_id")),
            field_state(
                app,
                "Overall",
                if value["healthy"] == true {
                    "HEALTHY"
                } else {
                    "DEGRADED"
                },
            ),
        ]
    };
    screen.actions = vec![
        item(
            "Maintenance check",
            "maintenance check",
            run("Maintenance check", &["maintenance", "check"], false),
        ),
        item(
            "Recovery plan",
            "recover plan",
            run("Recovery plan", &["recover", "plan"], false),
        ),
    ];
    screen
}

fn extensions(app: &App) -> Screen {
    let value = match status_or(app, "extensions", "extensions") {
        Ok(value) => value,
        Err(screen) => return *screen,
    };
    let health = app.value("extension-health").cloned().unwrap_or(json!([]));
    let catalog = app
        .value("extension-catalog")
        .cloned()
        .unwrap_or(json!({"packages":[]}));
    let mut rows = Vec::new();
    let enabled: Vec<&Value> = value.as_array().into_iter().flatten().collect();
    for entry in &enabled {
        let id = str_of(entry, "id");
        let healthy = health
            .as_array()
            .into_iter()
            .flatten()
            .find(|h| h["id"] == id)
            .is_none_or(|h| h["healthy"] == true);
        let newer = catalog["packages"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|p| p["id"] == id && p["version"].as_str() > entry["version"].as_str());
        let state = if !healthy {
            "ERROR"
        } else if newer {
            "UPDATE"
        } else if entry["active"] == true {
            "ACTIVE"
        } else {
            "DISABLED"
        };
        rows.push(Row {
            id: id.to_owned(),
            cells: vec![
                plain(app, id),
                muted(app, str_of(entry, "version")),
                state_cell(app, state),
                muted(app, scalar(&entry["granted_host_capabilities"])),
            ],
            copy: None,
            tab: None,
            open: None,
            search: search(&[("text", id), ("status", state)]),
        });
    }
    let available: Vec<Row> = catalog["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| !enabled.iter().any(|e| e["id"] == p["id"]))
        .map(|p| {
            let id = str_of(p, "id");
            Row {
                id: format!("available:{id}"),
                cells: vec![
                    plain(app, id),
                    muted(app, str_of(p, "version")),
                    muted(app, format!("○ {}", str_of(p, "catalog"))),
                    muted(app, p["summary"].as_str().unwrap_or("")),
                ],
                copy: None,
                tab: None,
                open: None,
                search: search(&[("text", id), ("status", "available")]),
            }
        })
        .collect();
    let mut screen = Screen::new(Body::Table(Table {
        key: "extensions".into(),
        sections: vec![
            Section {
                title: Some("Enabled in this Project".into()),
                columns: vec![
                    fill("Extension", 18, 1),
                    col("Version", 9, 2),
                    col("Status", 12, 1),
                    col("Granted", 18, 3),
                ],
                rows,
            },
            Section {
                title: Some("Available".into()),
                columns: vec![
                    fill("Extension", 18, 1),
                    col("Version", 9, 2),
                    col("Source", 12, 1),
                    col("Summary", 18, 3),
                ],
                rows: available,
            },
        ],
        empty: (
            "No extensions.".into(),
            "Enable the software extension with :extension enable.".into(),
        ),
        chips: vec![],
        total: None,
    }));
    if let Some(id) = selected_row_id(app, "extensions") {
        if let Some(name) = id.strip_prefix("available:") {
            screen.inspector = vec![
                heading(app, name),
                blank(),
                muted_line(app, "Not enabled in this Project."),
                muted_line(
                    app,
                    "Enabling grants no host capabilities until you grant them.",
                ),
            ];
            screen.actions = vec![item(
                "Enable",
                "extension enable",
                run(
                    &format!("Enable {name}"),
                    &["extension", "enable", name],
                    true,
                ),
            )];
        } else if let Some(entry) = enabled.iter().find(|e| e["id"] == id.as_str()) {
            screen.inspector = vec![
                heading(app, &id),
                blank(),
                field(app, "Version", str_of(entry, "version")),
                field(
                    app,
                    "Manifest",
                    text::middle(str_of(entry, "manifest"), 26, app.symbols.ellipsis()),
                ),
                field(app, "Granted", scalar(&entry["granted_host_capabilities"])),
                field(
                    app,
                    "Active",
                    if entry["active"] == true { "yes" } else { "no" },
                ),
            ];
            screen.actions = vec![
                item(
                    "Permissions",
                    "extension permissions",
                    run("Permissions", &["extension", "permissions", &id], false),
                ),
                item(
                    "Update",
                    "extension update (widening needs explicit grants)",
                    run(&format!("Update {id}"), &["extension", "update", &id], true),
                ),
                item(
                    "Disable",
                    "extension disable",
                    run(
                        &format!("Disable {id}"),
                        &["extension", "disable", &id],
                        true,
                    ),
                ),
            ];
        }
    }
    screen
}

/// JSON with key/value coloring; the escape hatch, never the primary view (§24).
pub fn raw_lines(app: &App, value: &Value) -> Vec<Line<'static>> {
    let text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.lines()
        .map(|raw| {
            let clean = sanitize_raw(raw);
            match clean.split_once("\": ") {
                Some((key, rest)) => Line::from(vec![
                    Span::styled(format!("{key}\": "), app.theme.accent()),
                    Span::styled(rest.to_owned(), app.theme.text()),
                ]),
                None => Line::from(Span::styled(clean, app.theme.muted())),
            }
        })
        .collect()
}

fn sanitize_raw(raw: &str) -> String {
    text::sanitize(raw)
}

/// The selected row id of a collection, resolved against the current rows.
pub fn selected_row_id(app: &App, key: &str) -> Option<String> {
    app.collections.get(key).and_then(|c| c.selected_id.clone())
}

/// Rows visible under the collection's active filter, flattened across sections.
pub fn visible_rows<'a>(app: &App, table: &'a Table) -> Vec<&'a Row> {
    let state = app.collections.get(&table.key);
    let filter = state.map(|c| c.filter.clone()).unwrap_or_default();
    let mut rows: Vec<&Row> = table
        .sections
        .iter()
        .flat_map(|section| section.rows.iter())
        .filter(|row| matches_filter(row, &filter))
        .collect();
    if table.sections.len() == 1
        && let Some((column, descending)) = state.and_then(|c| c.sort)
    {
        rows.sort_by(|a, b| {
            let key = |row: &Row| {
                row.cells
                    .get(column)
                    .map(|c| c.text.clone())
                    .unwrap_or_default()
            };
            let order = compare_cells(&key(a), &key(b));
            if descending { order.reverse() } else { order }
        });
    }
    rows
}

/// Numeric-aware ordering so "10 files" sorts after "9 files".
fn compare_cells(a: &str, b: &str) -> std::cmp::Ordering {
    let number = |s: &str| {
        s.split(|c: char| !c.is_ascii_digit())
            .find(|p| !p.is_empty())
            .and_then(|p| p.parse::<u64>().ok())
    };
    match (number(a), number(b)) {
        (Some(x), Some(y)) if x != y => x.cmp(&y),
        _ => a.to_lowercase().cmp(&b.to_lowercase()),
    }
}

/// `/` filter: plain words match any field; `field:value` matches that field (§10.1).
pub fn matches_filter(row: &Row, filter: &str) -> bool {
    matches_search(&row.search, filter)
}

pub fn matches_search(fields: &[(&'static str, String)], filter: &str) -> bool {
    filter.split_whitespace().all(|token| {
        let token = token.to_lowercase();
        match token.split_once(':') {
            Some((field, value)) if !field.is_empty() => fields
                .iter()
                .any(|(name, text)| *name == field && text.contains(value)),
            _ => fields.iter().any(|(_, text)| text.contains(&token)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        /// Tokens are conjunctive and case-insensitive; any substring of a field matches.
        #[test]
        fn filter_tokens_are_conjunctive_and_case_insensitive(
            state in "[a-z]{1,8}",
            text in "[a-z ]{1,16}",
            a in "[a-zA-Z]{0,4}",
            b in "[a-zA-Z]{0,4}",
            from in 0usize..8,
        ) {
            let row = Row {
                id: "r".into(),
                cells: vec![],
                copy: None,
                tab: None,
                open: None,
                search: vec![("state", state.clone()), ("text", text.clone())],
            };
            let both = format!("{a} {b}");
            proptest::prop_assert_eq!(
                matches_filter(&row, &both),
                matches_filter(&row, &a) && matches_filter(&row, &b)
            );
            proptest::prop_assert_eq!(matches_filter(&row, &a), matches_filter(&row, &a.to_uppercase()));
            let start = from.min(state.len() - 1);
            let field_token = format!("state:{}", &state[start..]);
            proptest::prop_assert!(matches_filter(&row, &field_token));
        }
    }

    #[test]
    fn structured_filters_match_fields() {
        let row = Row {
            id: "a".into(),
            cells: vec![],
            copy: None,
            tab: None,
            open: None,
            search: vec![("state", "sealed".into()), ("text", "add runner".into())],
        };
        assert!(matches_filter(&row, "state:seal"));
        assert!(matches_filter(&row, "runner"));
        assert!(!matches_filter(&row, "state:promoted"));
        assert!(matches_filter(&row, ""));
    }
}
