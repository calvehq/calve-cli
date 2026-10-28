//! Console state: routes, loaded read models, selection by identity, focus and overlays.
//! The state is synchronous; loading is expressed as requests the runtime (or a test) serves.

use std::collections::{BTreeMap, BTreeSet};

use calve_api::Action;
use serde_json::Value;

use crate::theme::{Symbols, Theme, Tone};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Overview,
    Work,
    Task(String),
    Execution(String),
    ChangeGraph,
    ChangePacks,
    ChangePack(String),
    Baselines,
    Baseline(String),
    Evidence,
    Events,
    Projects,
    Inbox,
    Doctor,
    Extensions,
}

/// Permanent navigation (console-ux §8).
pub const NAV: &[(&str, &[Route])] = &[
    (
        "PROJECT",
        &[
            Route::Overview,
            Route::Work,
            Route::ChangeGraph,
            Route::ChangePacks,
            Route::Baselines,
            Route::Evidence,
            Route::Events,
        ],
    ),
    (
        "SYSTEM",
        &[
            Route::Projects,
            Route::Inbox,
            Route::Doctor,
            Route::Extensions,
        ],
    ),
];

impl Route {
    pub fn title(&self) -> String {
        match self {
            Self::Overview => "Overview".into(),
            Self::Work => "Work".into(),
            Self::Task(id) => format!("Task {id}"),
            Self::Execution(id) => format!("Execution {id}"),
            Self::ChangeGraph => "Change Graph".into(),
            Self::ChangePacks => "ChangePacks".into(),
            Self::ChangePack(id) => format!("ChangePack {id}"),
            Self::Baselines => "Baselines".into(),
            Self::Baseline(id) => format!("Baseline {id}"),
            Self::Evidence => "Evidence".into(),
            Self::Events => "Events".into(),
            Self::Projects => "Projects".into(),
            Self::Inbox => "Inbox".into(),
            Self::Doctor => "Doctor".into(),
            Self::Extensions => "Extensions".into(),
        }
    }

    /// The navigation entry a route belongs to.
    pub fn section(&self) -> Route {
        match self {
            Self::Task(_) | Self::Execution(_) => Self::Work,
            Self::ChangePack(_) => Self::ChangePacks,
            Self::Baseline(_) => Self::Baselines,
            other => other.clone(),
        }
    }

    pub fn tabs(&self) -> &'static [&'static str] {
        match self {
            Self::ChangePack(_) => &[
                "Summary", "Diff", "Verify", "Risk", "Evidence", "Review", "Receipts", "Events",
                "Raw",
            ],
            Self::Baseline(_) => &["Graph", "Packs", "Relations", "History", "Explain", "Raw"],
            Self::Execution(_) => &[
                "Summary",
                "Output",
                "Observations",
                "Effects",
                "Events",
                "Raw",
            ],
            Self::Task(_) => &["Summary", "Executions", "Raw"],
            _ => &[],
        }
    }
}

/// A read-model request; the key identifies the cached result.
#[derive(Debug, Clone)]
pub struct Request {
    pub key: String,
    pub action: Action,
}

#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub value: Option<Value>,
    pub error: Option<String>,
    pub loading: bool,
    /// Wall-clock second of the last successful load; drives `STALE · last update Ns ago`.
    pub at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Navigation,
    Workspace,
    Inspector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Narrow,
    Medium,
    Wide,
}

impl Width {
    pub fn of(columns: u16) -> Self {
        match columns {
            0..=89 => Self::Narrow,
            90..=119 => Self::Medium,
            _ => Self::Wide,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connection {
    /// Starting or reaching the backend; nothing has answered yet (§88).
    Connecting,
    /// Talking to calved.
    Daemon,
    /// Running the application in-process.
    Local,
    /// The last request could not reach the backend.
    Offline,
    /// calved answered earlier and now does not (§6.2 `! daemon disconnected`).
    Disconnected,
}

impl Connection {
    /// The state after a reply that reached `backend` (`None`: nothing answered).
    pub fn after(self, backend: Option<Self>) -> Self {
        match backend {
            Some(state) => state,
            None if matches!(self, Self::Daemon | Self::Disconnected) => Self::Disconnected,
            None => Self::Offline,
        }
    }
}

/// How tables show times (`[console] time`, §54); inspectors always add the exact time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeStyle {
    #[default]
    Relative,
    Absolute,
    Both,
}

#[derive(Debug, Clone)]
pub struct PaletteItem {
    pub group: &'static str,
    pub label: String,
    pub detail: String,
    pub target: Target,
}

/// What activating a palette/action entry does.
#[derive(Debug, Clone)]
pub enum Target {
    Open(Route),
    /// CLI-grammar arguments for a typed request; `confirm` asks first.
    Run {
        args: Vec<String>,
        confirm: bool,
        label: String,
    },
    /// Needs one more value (`field`) inserted between `args` and `suffix` before running.
    Prompt {
        args: Vec<String>,
        suffix: Vec<String>,
        field: String,
        confirm: bool,
        label: String,
    },
    Unavailable(String),
    Review {
        pack: String,
        generation: u64,
    },
    Command(String),
    /// Switch the console to another registered Project, landing on `route` (§44).
    OpenProject {
        root: String,
        route: Route,
    },
}

#[derive(Debug, Clone)]
pub struct ReviewForm {
    pub pack: String,
    pub generation: u64,
    /// 0 approve, 1 reject, 2 comment.
    pub decision: usize,
    pub comment: String,
    /// 0 decision, 1 comment.
    pub field: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Overlay {
    Palette {
        query: String,
        selected: usize,
    },
    Command {
        input: String,
        history: Option<usize>,
        error: Option<String>,
        /// Ctrl+R history search term.
        term: Option<String>,
    },
    Actions {
        title: String,
        items: Vec<PaletteItem>,
        query: String,
        selected: usize,
    },
    Navigation {
        query: String,
        selected: usize,
    },
    Help,
    Confirm {
        title: String,
        lines: Vec<String>,
        args: Vec<String>,
        label: String,
    },
    Prompt {
        title: String,
        field: String,
        input: String,
        args: Vec<String>,
        suffix: Vec<String>,
        confirm: bool,
        label: String,
    },
    Review(ReviewForm),
    Explain {
        title: String,
        lines: Vec<(Tone, String)>,
    },
    Result {
        title: String,
        value: Value,
    },
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub tone: Tone,
    pub text: String,
    pub until: u64,
}

/// Per-collection view state, keyed by collection key.
#[derive(Debug, Clone, Default)]
pub struct CollectionState {
    pub selected_id: Option<String>,
    /// Row index cache used to pick the nearest neighbour when the selected row vanishes.
    pub selected_index: usize,
    pub scroll: usize,
    pub filter: String,
    pub marked: BTreeSet<String>,
    /// Sorted column and whether it is descending.
    pub sort: Option<(usize, bool)>,
}

/// What a mouse click at a rendered position means (filled by the renderer).
#[derive(Debug, Clone)]
pub enum Hit {
    Nav(usize),
    Row { key: String, id: String },
    Tab(usize),
}

pub struct App {
    pub route: Route,
    pub back: Vec<Route>,
    pub forward: Vec<Route>,
    pub focus: Focus,
    pub nav_index: usize,
    pub data: BTreeMap<String, Loaded>,
    pub outbox: Vec<Request>,
    pub collections: BTreeMap<String, CollectionState>,
    pub tabs: BTreeMap<String, usize>,
    pub overlays: Vec<Overlay>,
    pub notifications: Vec<Notification>,
    pub activity: Vec<(u64, Tone, String)>,
    pub drawer: bool,
    pub fullscreen: bool,
    pub filter_editing: bool,
    pub pending_key: Option<char>,
    pub command_history: Vec<String>,
    pub connection: Connection,
    pub tick: u64,
    /// Wall clock for relative times; injected so snapshots are deterministic.
    pub now: i64,
    pub size: (u16, u16),
    pub theme: Theme,
    pub symbols: Symbols,
    pub project: String,
    pub workspace: String,
    pub version: String,
    pub quit: bool,
    pub graph_list: bool,
    pub diff_scroll: usize,
    pub diff_wrap: bool,
    /// Execution output stays scrolled to the newest line (§28); scrolling up pauses it.
    pub log_follow: bool,
    /// Events screen live mode (§42.3): the newest event stays selected.
    pub events_live: bool,
    pub time: TimeStyle,
    pub show_footer: bool,
    pub wrap_logs: bool,
    pub log_timestamps: bool,
    /// Output viewer search term (§28).
    pub log_search: Option<String>,
    pub diff_context: Option<u32>,
    pub commands: u64,
    /// Text the runtime should place on the clipboard, and what it is (for the notice).
    pub clipboard: Option<String>,
    pub clipboard_label: String,
    pub hits: std::cell::RefCell<Vec<(ratatui::layout::Rect, Hit)>>,
    pub last_click: Option<(u64, u16, u16)>,
    /// Pressed key -> default key it stands for; `'\0'` means the default was remapped away.
    pub keymap: BTreeMap<char, char>,
    /// Remapped actions for the help overlay.
    pub custom_keys: Vec<(String, char)>,
    /// No Project is open: the backend's reason, shown on the welcome screen (§87).
    pub welcome: Option<String>,
    /// A Project root the runtime should switch the request scope to.
    pub open_project: Option<String>,
    /// Bumped on every Project switch; replies from an older epoch are dropped.
    pub epoch: u64,
}

impl App {
    pub fn new(theme: Theme, symbols: Symbols, connection: Connection, now: i64) -> Self {
        let mut app = Self {
            route: Route::Overview,
            back: Vec::new(),
            forward: Vec::new(),
            focus: Focus::Workspace,
            nav_index: 0,
            data: BTreeMap::new(),
            outbox: Vec::new(),
            collections: BTreeMap::new(),
            tabs: BTreeMap::new(),
            overlays: Vec::new(),
            notifications: Vec::new(),
            activity: Vec::new(),
            drawer: false,
            fullscreen: false,
            filter_editing: false,
            pending_key: None,
            command_history: Vec::new(),
            connection,
            tick: 0,
            now,
            size: (120, 36),
            theme,
            symbols,
            project: String::new(),
            workspace: String::new(),
            version: env!("CARGO_PKG_VERSION").into(),
            quit: false,
            graph_list: false,
            diff_scroll: 0,
            diff_wrap: false,
            log_follow: true,
            events_live: false,
            time: TimeStyle::Relative,
            show_footer: true,
            wrap_logs: false,
            log_timestamps: false,
            log_search: None,
            diff_context: None,
            commands: 0,
            clipboard: None,
            clipboard_label: String::new(),
            hits: std::cell::RefCell::new(Vec::new()),
            last_click: None,
            keymap: BTreeMap::new(),
            custom_keys: Vec::new(),
            welcome: None,
            open_project: None,
            epoch: 0,
        };
        app.load_route();
        app.request("status", status_action());
        app
    }

    /// Applies `[console.keys]` remaps (validated by configuration).
    pub fn set_keymap(&mut self, keys: &serde_json::Map<String, Value>) {
        for (action, default) in calve_api::CONSOLE_KEYS {
            let Some(custom) = keys
                .get(*action)
                .and_then(Value::as_str)
                .and_then(|k| k.chars().next())
            else {
                continue;
            };
            if custom != *default {
                self.keymap.insert(custom, *default);
                self.keymap.entry(*default).or_insert('\0');
                self.custom_keys.push(((*action).to_owned(), custom));
            }
        }
    }

    pub fn width(&self) -> Width {
        Width::of(self.size.0)
    }

    /// Queues a read model unless it is already loading.
    pub fn request(&mut self, key: &str, action: Action) {
        let entry = self.data.entry(key.to_owned()).or_default();
        if entry.loading {
            return;
        }
        entry.loading = true;
        self.outbox.push(Request {
            key: key.to_owned(),
            action,
        });
    }

    pub fn take_requests(&mut self) -> Vec<Request> {
        std::mem::take(&mut self.outbox)
    }

    pub fn respond(&mut self, key: &str, result: Result<Value, String>) {
        let now = self.now;
        let entry = self.data.entry(key.to_owned()).or_default();
        entry.loading = false;
        match result {
            Ok(value) => {
                entry.value = Some(value);
                entry.error = None;
                entry.at = now;
                if matches!(
                    self.connection,
                    Connection::Offline | Connection::Connecting
                ) {
                    self.connection = Connection::Local;
                }
            }
            Err(error) => {
                if error.contains("Connection refused")
                    || error.contains("No such file") && key == "status"
                {
                    self.connection = self.connection.after(None);
                }
                entry.error = Some(error);
            }
        }
        if key == "status" {
            match self.data.get("status") {
                Some(Loaded {
                    value: Some(value),
                    error: None,
                    ..
                }) => {
                    self.project = value["project"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    self.welcome = None;
                }
                // The backend answered but no Project is open here: welcome, not an exit (§87).
                Some(Loaded {
                    value: None,
                    error: Some(error),
                    ..
                }) if self.can_act() => {
                    self.welcome = Some(error.clone());
                    if self.route != Route::Projects {
                        self.navigate(Route::Projects);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn value(&self, key: &str) -> Option<&Value> {
        self.data.get(key).and_then(|loaded| loaded.value.as_ref())
    }

    pub fn loaded(&self, key: &str) -> Option<&Loaded> {
        self.data.get(key)
    }

    /// Queues everything the current route renders.
    pub fn load_route(&mut self) {
        for (key, action) in route_requests(&self.route) {
            self.request(&key, action);
        }
    }

    /// Reloads the current route (and status) without dropping cached values.
    pub fn refresh(&mut self) {
        let mut keys = route_requests(&self.route);
        if self.drawer {
            keys.push(("events".into(), action(&["activity"])));
        }
        for (key, action) in keys {
            if let Some(entry) = self.data.get_mut(&key) {
                entry.loading = false;
            }
            self.request(&key, action);
        }
        self.request("status", status_action());
    }

    /// Switches every later request to the Project at `root` (§44 Open) and starts over there.
    pub fn switch_project(&mut self, root: String) {
        self.open_project = Some(root);
        self.epoch += 1;
        self.data.clear();
        self.outbox.clear();
        self.collections.clear();
        self.back.clear();
        self.forward.clear();
        self.overlays.clear();
        self.project.clear();
        self.welcome = None;
        self.route = Route::Overview;
        self.after_route_change();
        self.request("status", status_action());
    }

    pub fn navigate(&mut self, route: Route) {
        if route == self.route {
            return;
        }
        let previous = std::mem::replace(&mut self.route, route);
        self.back.push(previous);
        self.forward.clear();
        self.after_route_change();
    }

    pub fn go_back(&mut self) -> bool {
        match self.back.pop() {
            Some(route) => {
                let current = std::mem::replace(&mut self.route, route);
                self.forward.push(current);
                self.after_route_change();
                true
            }
            None => false,
        }
    }

    pub fn go_forward(&mut self) {
        if let Some(route) = self.forward.pop() {
            let current = std::mem::replace(&mut self.route, route);
            self.back.push(current);
            self.after_route_change();
        }
    }

    fn after_route_change(&mut self) {
        self.fullscreen = false;
        self.diff_scroll = 0;
        if let Some(index) = nav_routes().iter().position(|r| *r == self.route.section()) {
            self.nav_index = index;
        }
        if self.focus == Focus::Navigation && self.width() != Width::Wide {
            self.focus = Focus::Workspace;
        }
        self.load_route();
    }

    pub fn tab(&self) -> usize {
        self.tabs.get(&tab_key(&self.route)).copied().unwrap_or(0)
    }

    pub fn tab_name(&self) -> Option<&'static str> {
        self.route.tabs().get(self.tab()).copied()
    }

    pub fn set_tab(&mut self, index: usize) {
        let count = self.route.tabs().len();
        if count > 0 {
            self.tabs.insert(tab_key(&self.route), index % count);
            self.diff_scroll = 0;
        }
    }

    pub fn collection(&mut self, key: &str) -> &mut CollectionState {
        self.collections.entry(key.to_owned()).or_default()
    }

    pub fn notify(&mut self, tone: Tone, text: impl Into<String>) {
        let text = text.into();
        self.activity.push((self.tick, tone, text.clone()));
        if self.activity.len() > 200 {
            self.activity.remove(0);
        }
        self.notifications.push(Notification {
            tone,
            text,
            until: self.tick + 40,
        });
    }

    pub fn advance(&mut self, ticks: u64) {
        self.tick += ticks;
        let tick = self.tick;
        self.notifications.retain(|n| n.until > tick);
    }

    /// Actions change authority-bearing state, so they are disabled while offline (§6.2).
    pub fn can_act(&self) -> bool {
        matches!(self.connection, Connection::Daemon | Connection::Local)
    }
}

pub fn nav_routes() -> Vec<Route> {
    NAV.iter()
        .flat_map(|(_, routes)| routes.iter().cloned())
        .collect()
}

pub fn tab_key(route: &Route) -> String {
    match route {
        Route::ChangePack(_) => "tab:pack".into(),
        Route::Baseline(_) => "tab:baseline".into(),
        Route::Execution(_) => "tab:execution".into(),
        Route::Task(_) => "tab:task".into(),
        other => format!("tab:{}", other.title()),
    }
}

fn status_action() -> Action {
    Action::Status
}

/// Parses CLI-grammar arguments into a typed request (never through a shell).
pub fn parse_action(args: &[String]) -> Result<Action, String> {
    use clap::Parser;
    #[derive(Parser)]
    #[command(name = "calve", no_binary_name = true)]
    struct Line {
        #[command(subcommand)]
        action: Action,
    }
    Line::try_parse_from(args)
        .map(|line| line.action)
        .map_err(|error| {
            error
                .render()
                .to_string()
                .lines()
                .next()
                .unwrap_or("invalid command")
                .to_owned()
        })
}

fn action(args: &[&str]) -> Action {
    parse_action(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>())
        .expect("console read-model requests use valid CLI grammar")
}

/// Read models per route (key, request).
pub fn route_requests(route: &Route) -> Vec<(String, Action)> {
    match route {
        Route::Overview => vec![("overview".into(), action(&["view", "overview"]))],
        Route::Work => vec![
            ("intents".into(), action(&["intent", "list"])),
            ("tasks".into(), action(&["task", "list"])),
            ("overview".into(), action(&["view", "overview"])),
        ],
        Route::Task(id) => vec![
            (format!("task:{id}"), action(&["task", "show", id])),
            ("intents".into(), action(&["intent", "list"])),
        ],
        Route::Execution(id) => vec![(
            format!("execution:{id}"),
            action(&["view", "execution", id]),
        )],
        Route::ChangeGraph => vec![("graph".into(), action(&["view", "change-graph"]))],
        Route::ChangePacks => vec![("packs".into(), action(&["view", "packs"]))],
        Route::ChangePack(id) => vec![(format!("pack:{id}"), action(&["view", "pack", id]))],
        Route::Baselines => vec![
            ("baselines".into(), action(&["baseline", "list"])),
            ("aliases".into(), action(&["baseline", "alias", "list"])),
        ],
        Route::Baseline(id) => vec![
            (format!("baseline:{id}"), action(&["view", "baseline", id])),
            (
                format!("baseline-history:{id}"),
                action(&["activity", "--pack", id]),
            ),
        ],
        Route::Evidence => vec![("evidence".into(), action(&["view", "evidence"]))],
        Route::Events => vec![("events".into(), action(&["activity"]))],
        Route::Projects => vec![("projects".into(), action(&["project", "list"]))],
        Route::Inbox => vec![("inbox".into(), action(&["inbox", "list"]))],
        Route::Doctor => vec![("doctor".into(), action(&["doctor"]))],
        Route::Extensions => vec![
            ("extensions".into(), action(&["extension", "list"])),
            ("extension-health".into(), action(&["extension", "health"])),
            ("extension-catalog".into(), action(&["extension", "search"])),
        ],
    }
}

/// Requests for inspector detail of a selected row in list screens.
pub fn detail_request(route: &Route, id: &str) -> Option<(String, Action)> {
    match route {
        Route::ChangePacks => Some((format!("pack:{id}"), action(&["view", "pack", id]))),
        Route::Baselines => Some((format!("baseline:{id}"), action(&["view", "baseline", id]))),
        Route::Projects => Some((
            format!("project-health:{id}"),
            action(&["project", "health", id]),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::ThemeName;

    #[test]
    fn history_and_requests_follow_navigation() {
        let mut app = App::new(
            Theme::new(ThemeName::Mono),
            Symbols { unicode: true },
            Connection::Local,
            0,
        );
        assert!(app.take_requests().iter().any(|r| r.key == "overview"));
        app.navigate(Route::ChangePacks);
        assert_eq!(app.take_requests()[0].key, "packs");
        app.navigate(Route::ChangePack("cpk_1".into()));
        assert!(app.go_back());
        assert_eq!(app.route, Route::ChangePacks);
        app.go_forward();
        assert_eq!(app.route, Route::ChangePack("cpk_1".into()));
        assert!(parse_action(&["pack".into(), "list".into()]).is_ok());
        assert!(parse_action(&["no-such".into()]).is_err());
    }
}
