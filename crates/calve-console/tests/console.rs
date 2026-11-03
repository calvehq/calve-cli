//! Console snapshot and interaction tests (console-ux §91–92). Read models come from
//! fixtures recorded from a real Project by `tests/fixtures/generate.sh`.

use std::collections::BTreeMap;

use calve_console::input::{handle_key, on_response};
use calve_console::model::{App, Connection, Overlay, Route};
use calve_console::render;
use calve_console::theme::{Symbols, Theme, ThemeName};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use serde_json::{Value, json};

struct Harness {
    app: App,
    data: BTreeMap<String, Value>,
    commands: Vec<String>,
    offline: bool,
}

fn fixtures() -> (i64, BTreeMap<String, Value>) {
    let text = include_str!("fixtures/console.json");
    let value: Value = serde_json::from_str(text).expect("fixture json");
    let data = value["data"]
        .as_object()
        .expect("data")
        .clone()
        .into_iter()
        .collect();
    (value["now"].as_i64().expect("now"), data)
}

impl Harness {
    fn new(width: u16, height: u16) -> Self {
        Self::with_theme(width, height, ThemeName::Mono, true)
    }

    fn with_theme(width: u16, height: u16, theme: ThemeName, unicode: bool) -> Self {
        let (now, data) = fixtures();
        let mut app = App::new(
            Theme::new(theme),
            Symbols { unicode },
            Connection::Daemon,
            now + 60,
        );
        app.size = (width, height);
        app.workspace = "main".into();
        let mut harness = Self {
            app,
            data,
            commands: Vec::new(),
            offline: false,
        };
        harness.pump();
        harness
    }

    /// Serves queued requests until the app stops asking.
    fn pump(&mut self) {
        for _ in 0..20 {
            let requests = self.app.take_requests();
            if requests.is_empty() {
                return;
            }
            for request in requests {
                let result = if self.offline {
                    Err("Connection refused (os error 111)".to_owned())
                } else if request.key.starts_with("cmd:") {
                    self.commands.push(request.key.clone());
                    Ok(json!({"ok": true}))
                } else {
                    self.data
                        .get(&request.key)
                        .cloned()
                        .ok_or_else(|| format!("fixture missing {}", request.key))
                };
                if self.offline {
                    self.app.connection = Connection::Offline;
                }
                on_response(&mut self.app, &request.key, result);
            }
        }
    }

    fn key(&mut self, code: KeyCode) -> &mut Self {
        self.key_with(code, KeyModifiers::NONE)
    }

    fn key_with(&mut self, code: KeyCode, modifiers: KeyModifiers) -> &mut Self {
        handle_key(&mut self.app, KeyEvent::new(code, modifiers));
        self.pump();
        self
    }

    fn keys(&mut self, text: &str) -> &mut Self {
        for ch in text.chars() {
            self.key(KeyCode::Char(ch));
        }
        self
    }

    fn render(&self) -> String {
        let (width, height) = self.app.size;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| render::draw(frame, &self.app))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..height {
            let mut row = String::new();
            let mut x = 0;
            while x < width {
                let symbol = buffer[(x, y)].symbol();
                row.push_str(symbol);
                // A wide character owns the next cell too, as on a terminal.
                x += calve_console::text::width(symbol).max(1) as u16;
            }
            out.push_str(row.trim_end());
            out.push('\n');
        }
        out
    }

    fn pack_id(&self, title: &str) -> String {
        self.data["packs"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["title"] == title)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

fn snapshot(name: &str, text: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.txt"));
    if std::env::var_os("CALVE_UPDATE_SNAPSHOTS").is_some() || !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap();
    assert!(
        expected == text,
        "snapshot {name} changed; rerun with CALVE_UPDATE_SNAPSHOTS=1 to accept\n--- expected\n{expected}\n--- actual\n{text}"
    );
}

/// Scenario A: the overview shows ordered attention, work and activity at every size.
#[test]
fn overview_snapshots_at_all_sizes() {
    for (width, height) in [(160, 45), (120, 35), (100, 30), (80, 24)] {
        let harness = Harness::new(width, height);
        let screen = harness.render();
        assert!(screen.contains("Needs attention") || width < 90, "{screen}");
        assert!(
            !screen.contains("{\""),
            "no raw JSON on the overview:\n{screen}"
        );
        snapshot(&format!("overview_{width}x{height}"), &screen);
    }
    let wide = Harness::new(160, 45).render();
    let failure = wide.find("Execution FAILED").unwrap();
    let blocked = wide.find("is blocked").unwrap();
    let review = wide.find("awaits verification").unwrap();
    assert!(
        failure < blocked && blocked < review,
        "attention order: failures, blocked, review"
    );
    assert!(wide.contains("Active work") && wide.contains("Recent activity"));
}

/// Scenario B: selecting a ChangePack updates the inspector; selection survives refresh.
#[test]
fn changepack_selection_and_detail() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let screen = h.render();
    assert!(screen.contains("All 6"), "{screen}");
    snapshot("changepacks_160x45", &screen);
    h.key(KeyCode::Char('j'));
    let selected = h.app.collections["packs"].selected_id.clone().unwrap();
    let screen = h.render();
    let title = h.data[&format!("pack:{selected}")]["title"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        screen.matches(&title).count() >= 2,
        "inspector shows the selected pack"
    );
    // A refresh with the same data keeps the same selected identity.
    h.key(KeyCode::Char('r'));
    assert_eq!(
        h.app.collections["packs"].selected_id.as_deref(),
        Some(selected.as_str())
    );
    h.key(KeyCode::Enter);
    assert_eq!(h.app.route, Route::ChangePack(selected));
    snapshot("changepack_summary_160x45", &h.render());
}

/// Scenario C: the diff tab shows files, the diff and file details; hunks and fullscreen work.
#[test]
fn changepack_diff_workstation() {
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner.clone()));
    h.pump();
    h.key(KeyCode::Char('2'));
    let screen = h.render();
    assert!(screen.contains("2 files changed"), "{screen}");
    assert!(
        screen.contains("+pub const DEFAULT_TIMEOUT: u64 = 30;"),
        "{screen}"
    );
    assert!(
        screen.contains("-pub const DEFAULT_TIMEOUT: u64 = 10;"),
        "{screen}"
    );
    assert!(
        screen.contains("Modified") || screen.contains("MODIFIED"),
        "{screen}"
    );
    snapshot("changepack_diff_160x45", &screen);
    h.keys("]c");
    h.key(KeyCode::Char('z'));
    assert!(h.app.fullscreen);
    snapshot("changepack_diff_fullscreen", &h.render());
    h.key(KeyCode::Esc);
    assert!(!h.app.fullscreen);
    h.key(KeyCode::Char('j'));
    assert!(h.render().contains("mod http;"));
    h.app.size = (80, 24);
    assert!(
        h.render().contains("mod http;"),
        "diff usable at 80 columns"
    );
}

/// Scenario C, §33.1: the file list stays at 100 columns, `/` searches the open diff, n/N
/// move between matches, Enter opens the file's lines and scrolling stops at the end.
#[test]
fn diff_search_navigation_and_widths() {
    let mut h = Harness::new(100, 30);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner.clone()));
    h.pump();
    h.key(KeyCode::Char('2'));
    let screen = h.render();
    assert!(
        screen.contains("2 files changed") && screen.contains("file 1/2"),
        "{screen}"
    );
    snapshot("changepack_diff_100x30", &screen);
    h.app.size = (80, 24);
    let narrow = h.render();
    assert!(narrow.contains("file 1/2"), "{narrow}");
    snapshot("changepack_diff_80x24", &narrow);
    h.app.size = (160, 45);
    h.key(KeyCode::Char('/'))
        .keys("duration")
        .key(KeyCode::Enter);
    assert!(h.app.diff_lines, "a match opens the lines");
    let first = h.app.diff_scroll;
    let screen = h.render();
    assert!(screen.contains("/duration: 2 matches"), "{screen}");
    h.key(KeyCode::Char('n'));
    assert!(h.app.diff_scroll > first);
    h.key(KeyCode::Char('N'));
    assert_eq!(h.app.diff_scroll, first);
    // Line focus: j scrolls, and never past the last line.
    for _ in 0..200 {
        h.key(KeyCode::Char('j'));
    }
    let end = h.app.diff_scroll;
    h.key(KeyCode::Char('J'));
    assert_eq!(h.app.diff_scroll, end, "scroll is bounded");
    // Esc clears the search, then returns to the file list.
    h.key(KeyCode::Esc).key(KeyCode::Esc);
    assert!(!h.app.diff_lines);
    h.key(KeyCode::Char('j'));
    assert!(h.render().contains("file 2/2"));
    h.key(KeyCode::Char('y'));
    assert_eq!(
        h.app.clipboard.take().as_deref(),
        Some("crates/runner/mod.rs")
    );
}

/// Scenario D: verification results come from OpenAEVC and keep stable order.
#[test]
fn verification_tab() {
    let mut h = Harness::new(120, 35);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.key(KeyCode::Char('3'));
    let screen = h.render();
    assert!(screen.contains("✓ PASS"), "{screen}");
    snapshot("changepack_verify_120x35", &screen);
}

/// Scenario E: promotion is visibly unavailable with a reason, and explain lists conditions.
#[test]
fn disabled_promotion_is_explained() {
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.key(KeyCode::Char('a'));
    let screen = h.render();
    assert!(screen.contains("Promote"), "{screen}");
    assert!(screen.contains("missing: approved review"), "{screen}");
    snapshot("actions_palette", &screen);
    h.key(KeyCode::Esc).key(KeyCode::Char('x'));
    let screen = h.render();
    assert!(
        screen.contains("Satisfied") && screen.contains("Missing"),
        "{screen}"
    );
    assert!(screen.contains("approved review"), "{screen}");
    assert!(screen.contains("snapshot.verify is PASS"), "{screen}");
    snapshot("explain_promotion", &screen);
}

/// §60 Test K: what the backend says is forbidden, the console cannot do. The blocked action's
/// key and its palette entry send nothing.
#[test]
fn test_k_a_forbidden_action_sends_nothing() {
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.key(KeyCode::Char('p'));
    h.key(KeyCode::Enter);
    h.key(KeyCode::Esc);
    h.key(KeyCode::Char('a'));
    h.keys("promote");
    h.key(KeyCode::Enter);
    h.key(KeyCode::Enter);
    assert!(
        !h.commands.iter().any(|c| c.contains("Promote")),
        "{:?}",
        h.commands
    );
}

/// Review runs as a typed request bound to the pack generation; rejections need a reason.
#[test]
fn review_form_submits_typed_request() {
    let mut h = Harness::new(120, 35);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.key(KeyCode::Char('6')).key(KeyCode::Char('r'));
    assert!(matches!(h.app.overlays.last(), Some(Overlay::Review(_))));
    snapshot("review_form", &h.render());
    h.key(KeyCode::Down).key(KeyCode::Tab).key(KeyCode::Enter);
    assert!(h.render().contains("needs a reason"));
    h.keys("needs tests").key(KeyCode::Enter);
    assert!(h.app.overlays.is_empty());
    assert!(
        h.commands.iter().any(|c| c.contains("Review: reject")),
        "{:?}",
        h.commands
    );
}

/// Scenario F: the baseline graph renders with list fallback.
#[test]
fn baseline_graph_and_list() {
    let mut h = Harness::new(120, 35);
    let baseline = h.data["baselines"][0]["id"].as_str().unwrap().to_owned();
    h.app.navigate(Route::Baselines);
    h.pump();
    snapshot("baselines_120x35", &h.render());
    h.app.navigate(Route::Baseline(baseline));
    h.pump();
    let screen = h.render();
    assert!(screen.contains("Update protocol schemas"), "{screen}");
    snapshot("baseline_graph_120x35", &screen);
    h.key(KeyCode::Char('v'));
    assert!(h.render().contains("Head"), "list fallback");
}

/// Scenario G: exact identifiers rank first in the palette.
#[test]
fn palette_ranks_exact_ids_first() {
    let mut h = Harness::new(120, 35);
    let draft = h.pack_id("Refactor verification rules");
    h.key_with(KeyCode::Char('p'), KeyModifiers::CONTROL);
    h.keys(&draft);
    let screen = h.render();
    let first = screen
        .lines()
        .find(|l| l.contains("ChangePack ·") || l.contains("· ChangePack"))
        .unwrap_or("");
    assert!(first.contains(&draft[draft.len() - 6..]), "{screen}");
    snapshot("palette", &screen);
    h.key(KeyCode::Enter);
    assert_eq!(h.app.route, Route::ChangePack(draft));
}

/// Scenario H: at 80 columns one pane is visible; Enter goes inward and Esc outward.
#[test]
fn narrow_terminal_navigation() {
    let mut h = Harness::new(80, 24);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let screen = h.render();
    assert!(!screen.contains("Inspector"), "{screen}");
    snapshot("changepacks_80x24", &screen);
    h.key(KeyCode::Enter);
    assert!(matches!(h.app.route, Route::ChangePack(_)));
    h.key(KeyCode::Esc);
    assert_eq!(h.app.route, Route::ChangePacks);
    h.key(KeyCode::Esc);
    assert!(h.render().contains("Navigation"));
}

/// Scenario I: connection loss marks data stale and disables actions; data stays readable.
#[test]
fn connection_loss_is_safe() {
    let mut h = Harness::new(120, 35);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    h.offline = true;
    h.key(KeyCode::Char('r'));
    let screen = h.render();
    assert!(
        screen.contains("offline") && screen.contains("STALE"),
        "{screen}"
    );
    assert!(
        screen.contains("Update protocol schemas"),
        "cached data stays visible:\n{screen}"
    );
    h.key(KeyCode::Char('a'));
    assert!(h.app.overlays.is_empty(), "actions disabled while offline");
    h.offline = false;
    h.key(KeyCode::Char('r'));
    assert!(!h.render().contains("offline"));
}

/// Scenario I: the selection survives a disconnect and reconnect; a lost daemon says so.
#[test]
fn reconnect_keeps_selection() {
    let mut h = Harness::new(120, 35);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    h.key(KeyCode::Char('j')).key(KeyCode::Char('j'));
    let selected = h.app.collections["packs"].selected_id.clone();
    h.app.connection = h.app.connection.after(None);
    assert_eq!(h.app.connection, Connection::Disconnected);
    h.app.now += 14;
    let screen = h.render();
    assert!(screen.contains("! daemon disconnected"), "{screen}");
    assert!(screen.contains("STALE · last update 14s ago"), "{screen}");
    h.app.connection = Connection::Daemon;
    h.key(KeyCode::Char('r'));
    assert_eq!(h.app.collections["packs"].selected_id, selected);
    assert!(h.render().contains("● healthy"));
}

/// §88: the shell renders before the backend answers.
#[test]
fn startup_shows_connecting() {
    let (now, _) = fixtures();
    let mut app = App::new(
        Theme::new(ThemeName::Mono),
        Symbols { unicode: true },
        Connection::Connecting,
        now,
    );
    app.size = (100, 30);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| render::draw(f, &app)).unwrap();
    let top: String = (0..100)
        .map(|x| terminal.backend().buffer()[(x, 0)].symbol().to_owned())
        .collect();
    assert!(top.contains("○ connecting"), "{top}");
    assert!(!app.can_act(), "no actions before the backend answers");
}

/// §87: without a Project the console welcomes and lists registered Projects.
#[test]
fn first_run_welcomes_instead_of_exiting() {
    let mut h = Harness::new(120, 35);
    let status = h.data.remove("status").unwrap();
    h.app.data.clear();
    h.app.project.clear();
    h.app.refresh();
    h.pump();
    assert_eq!(h.app.route, Route::Projects);
    let screen = h.render();
    assert!(screen.contains("Welcome to Calve"), "{screen}");
    assert!(screen.contains("openaevc"), "{screen}");
    // Enter opens the selected Project: every later request targets its root.
    h.data.insert("status".into(), status);
    h.key(KeyCode::Enter);
    assert_eq!(h.app.open_project.as_deref(), Some("/home/dev/openaevc"));
    assert_eq!(h.app.route, Route::Overview);
}

/// §16, §91.4: event rows keep their identity when events are inserted above, deleted below
/// or reordered, and the inspector follows the same event.
#[test]
fn event_selection_survives_refresh_changes() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::Events);
    h.pump();
    h.key(KeyCode::Char('j')).key(KeyCode::Char('j'));
    let selected = h.app.collections["events"].selected_id.clone().unwrap();
    let events = h.data["events"].as_array().unwrap().clone();
    let mut inserted = events.clone();
    let mut fresh = events[0].clone();
    fresh["id"] = json!("calve:999");
    fresh["kind"] = json!("pack.sealed");
    inserted.insert(0, fresh);
    let mut deleted_below = events.clone();
    deleted_below.truncate(4);
    let mut reordered = events.clone();
    reordered.swap(0, 3);
    for data in [inserted, deleted_below, reordered] {
        h.data.insert("events".into(), Value::Array(data));
        h.key(KeyCode::Char('r'));
        assert_eq!(
            h.app.collections["events"].selected_id.as_deref(),
            Some(selected.as_str())
        );
        assert!(
            h.render().contains(&selected),
            "inspector shows the same event"
        );
    }
    // Deleted: the nearest neighbour is selected, never a silent jump to the top.
    let remaining: Vec<Value> = events
        .iter()
        .filter(|e| e["id"] != selected.as_str())
        .cloned()
        .collect();
    h.data.insert("events".into(), Value::Array(remaining));
    h.key(KeyCode::Char('r'));
    let now = h.app.collections["events"].selected_id.clone().unwrap();
    assert_ne!(now, selected);
    assert_ne!(
        Some(&now),
        events[0]["id"].as_str().map(str::to_owned).as_ref()
    );
}

/// §42.3: `f` follows new events; scrolling away pauses; the footer says which.
#[test]
fn events_live_mode_follows_and_pauses() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::Events);
    h.pump();
    h.key(KeyCode::Char('j'));
    h.key(KeyCode::Char('f'));
    assert!(h.render().contains("● LIVE"));
    let mut events = h.data["events"].as_array().unwrap().clone();
    let mut fresh = events[0].clone();
    fresh["id"] = json!("calve:1000");
    events.insert(0, fresh);
    h.data.insert("events".into(), Value::Array(events));
    h.key(KeyCode::Char('r'));
    assert_eq!(
        h.app.collections["events"].selected_id.as_deref(),
        Some("calve:1000")
    );
    h.key(KeyCode::Char('j'));
    assert!(h.render().contains("paused · f follow"));
}

/// §52: `y` copies the object reference, never an internal row key.
#[test]
fn copy_uses_object_references() {
    let mut h = Harness::new(160, 45);
    h.key(KeyCode::Char('y'));
    let copied = h.app.clipboard.take().unwrap();
    assert!(copied.starts_with("exe_"), "{copied}");
    let id = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(id));
    h.pump();
    h.keys("2").key(KeyCode::Char('y'));
    assert_eq!(
        h.app.clipboard.take().as_deref(),
        Some("crates/runner/http.rs")
    );
    h.app.navigate(Route::Events);
    h.pump();
    h.key(KeyCode::Char('y'));
    let newest = h.data["events"][0]["id"].as_str().map(str::to_owned);
    assert_eq!(h.app.clipboard.take(), newest);
}

/// §25.2: Enter on an attention item opens its native tab.
#[test]
fn overview_items_open_their_context() {
    let mut h = Harness::new(160, 45);
    h.key(KeyCode::Char('j'))
        .key(KeyCode::Char('j'))
        .key(KeyCode::Enter);
    assert!(
        matches!(h.app.route, Route::ChangePack(_)),
        "{:?}",
        h.app.route
    );
    assert_eq!(h.app.tab_name(), Some("Review"));
    h.key(KeyCode::Esc);
    h.key(KeyCode::Char('G')).key(KeyCode::Enter);
    assert!(
        matches!(
            h.app.route,
            Route::ChangePack(_) | Route::Execution(_) | Route::Events
        ),
        "recent activity opens its object: {:?}",
        h.app.route
    );
}

/// §16, §43, §72: marks show a persistent count and drive bulk actions; the drawer shows
/// daemon events; a pasted newline never submits a command.
#[test]
fn marks_drawer_and_paste() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::Inbox);
    h.pump();
    h.key(KeyCode::Char(' '))
        .key(KeyCode::Char('j'))
        .key(KeyCode::Char(' '));
    assert!(h.render().contains("✓ 2 selected"));
    h.key(KeyCode::Char('a'));
    assert!(h.render().contains("Acknowledge 2 selected"));
    h.key(KeyCode::Enter);
    assert!(
        h.commands.iter().any(|c| c.contains("Acknowledge 2 items")),
        "{:?}",
        h.commands
    );
    h.key_with(KeyCode::Char('l'), KeyModifiers::CONTROL);
    let screen = h.render();
    assert!(
        screen.contains("Daemon events") && screen.contains("execution.finished"),
        "{screen}"
    );
    let before = h.commands.len();
    h.key(KeyCode::Char(':'));
    calve_console::input::handle_paste(&mut h.app, "pack list\nproject unregister x");
    h.pump();
    assert!(
        matches!(h.app.overlays.last(), Some(Overlay::Command { input, .. }) if input == "pack list project unregister x")
    );
    assert_eq!(h.commands.len(), before, "paste ran nothing");
}

/// Scenario J: hostile terminal sequences in backend text render as inert text.
#[test]
fn hostile_text_is_sanitized() {
    let mut h = Harness::new(120, 35);
    let mut packs = h.data["packs"].clone();
    packs["items"][0]["title"] = json!("evil\u{1b}]52;c;cm0gLXJmIH4=\u{7}\u{1b}[2Jtitle");
    h.data.insert("packs".into(), packs);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let screen = h.render();
    assert!(screen.contains("eviltitle"), "{screen}");
    assert!(!screen.contains('\u{1b}'));
}

/// Scenario K: without color every state is still distinguishable by symbol and text.
#[test]
fn ascii_and_monochrome_remain_legible() {
    let mut h = Harness::with_theme(120, 35, ThemeName::Mono, false);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let screen = h.render();
    assert!(
        screen.contains("[ok] PROMOTED") && screen.contains("[?] SEALED"),
        "{screen}"
    );
    assert!(screen.is_ascii(), "{screen}");
    snapshot("changepacks_ascii", &screen);
}

/// Every primary destination renders without raw JSON and with its own content.
#[test]
fn every_screen_renders() {
    let mut h = Harness::new(160, 45);
    // Extension ids come from the fixture: domain names live in calve-extensions (INV-022).
    let extension = h.data["extensions"][0]["id"].as_str().unwrap().to_owned();
    let expectations = [
        (Route::Work, "HTTP conformance"),
        (Route::ChangeGraph, "running"),
        (Route::Evidence, "Evidence"),
        (Route::Events, "Event"),
        (Route::Projects, "openaevc"),
        (Route::Inbox, "Execution FAILED"),
        (Route::Doctor, "Product database"),
        (Route::Extensions, extension.as_str()),
    ];
    for (route, needle) in expectations {
        h.app.navigate(route.clone());
        h.pump();
        let screen = h.render();
        assert!(screen.contains(needle), "{route:?}\n{screen}");
        assert!(!screen.contains("\"envelope\""), "{route:?} shows raw JSON");
        snapshot(
            &format!("screen_{}", route.title().to_lowercase().replace(' ', "_")),
            &screen,
        );
    }
    let execution = h
        .data
        .keys()
        .find(|k| k.starts_with("execution:"))
        .unwrap()
        .trim_start_matches("execution:")
        .to_owned();
    h.app.navigate(Route::Execution(execution));
    h.pump();
    h.key(KeyCode::Char('2'));
    let screen = h.render();
    assert!(screen.contains("lint: 2 problems"), "{screen}");
    snapshot("execution_output", &screen);
}

/// Command mode parses CLI grammar into typed requests and confirms destructive ones.
#[test]
fn command_mode_is_structured() {
    let mut h = Harness::new(120, 35);
    let draft = h.pack_id("Refactor verification rules");
    h.key(KeyCode::Char(':'))
        .keys(&format!("pack {draft}"))
        .key(KeyCode::Enter);
    assert_eq!(h.app.route, Route::ChangePack(draft.clone()));
    h.key(KeyCode::Char(':'))
        .keys(&format!("pack abandon {draft} --generation 2"))
        .key(KeyCode::Enter);
    assert!(
        matches!(h.app.overlays.last(), Some(Overlay::Confirm { .. })),
        "destructive commands confirm"
    );
    snapshot("confirm_dialog", &h.render());
    h.key(KeyCode::Enter);
    assert!(h.commands.iter().any(|c| c.contains("pack abandon")));
    h.key(KeyCode::Esc);
    h.key(KeyCode::Char(':'))
        .keys("no-such-command")
        .key(KeyCode::Enter);
    assert!(matches!(
        h.app.overlays.last(),
        Some(Overlay::Command { error: Some(_), .. })
    ));
    h.key(KeyCode::Esc);
    h.key(KeyCode::Char('?'));
    snapshot("help_overlay", &h.render());
}

/// Mouse is additive: clicking navigation and rows mirrors the keyboard (§53).
#[test]
fn mouse_selects_and_opens() {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    let mut h = Harness::new(160, 45);
    let click = |h: &mut Harness, column: u16, row: u16| {
        h.render();
        calve_console::input::handle_mouse(
            &mut h.app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column,
                row,
                modifiers: KeyModifiers::NONE,
            },
        );
        h.pump();
    };
    let screen = h.render();
    let row = screen
        .lines()
        .position(|l| l.contains("  Baselines"))
        .unwrap() as u16;
    click(&mut h, 4, row);
    assert_eq!(h.app.route, Route::Baselines);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let screen = h.render();
    let row = screen
        .lines()
        .position(|l| l.contains("Update protocol schemas"))
        .unwrap() as u16;
    click(&mut h, 40, row);
    let promoted = h.pack_id("Update protocol schemas");
    assert_eq!(
        h.app.collections["packs"].selected_id.as_deref(),
        Some(promoted.as_str())
    );
    click(&mut h, 40, row);
    assert_eq!(h.app.route, Route::ChangePack(promoted));
}

/// `s` sorts single-section tables with a visible marker; Ctrl+R searches command history;
/// `[console.keys]` remaps keys and frees the old default.
#[test]
fn sorting_history_search_and_keymap() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    h.key(KeyCode::Char('s')).key(KeyCode::Char('s'));
    let screen = h.render();
    assert!(screen.contains("ID ▼"), "{screen}");
    h.key(KeyCode::Char('s'));
    assert!(h.render().contains("State ▲"));

    h.key(KeyCode::Char(':')).keys("status").key(KeyCode::Enter);
    h.key(KeyCode::Char(':')).keys("doctor").key(KeyCode::Enter);
    h.key(KeyCode::Char(':'))
        .keys("sta")
        .key_with(KeyCode::Char('r'), KeyModifiers::CONTROL);
    assert!(
        matches!(h.app.overlays.last(), Some(Overlay::Command { input, .. }) if input == "status")
    );
    h.key(KeyCode::Esc);
    h.app.overlays.clear();

    let keys: serde_json::Map<String, Value> =
        serde_json::from_value(json!({"explain":"e"})).unwrap();
    h.app.set_keymap(&keys);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.key(KeyCode::Char('x'));
    assert!(h.app.overlays.is_empty(), "the old default is unbound");
    h.key(KeyCode::Char('e'));
    assert!(matches!(
        h.app.overlays.last(),
        Some(Overlay::Explain { .. })
    ));
    h.key(KeyCode::Esc).key(KeyCode::Char('?'));
    assert!(h.render().contains("CUSTOM KEYS"));
}

/// Scenario D (§34, §34.2, §94.4): running checks show elapsed time, rows keep their order as
/// checks finish, Enter opens the check detail, r reruns and e shows the evidence.
#[test]
fn verification_runs_update_in_place_and_open_details() {
    let mut h = Harness::new(160, 45);
    let id = h.pack_id("Add remote conformance runner");
    let key = format!("pack:{id}");
    let mut pack = h.data[&key].clone();
    let started = h.app.now - 12;
    pack["running"] = json!([{"id":"exe_aaaaaaaaaaaaaaaaaaaaaaaaaa","harness":"example.harness.lint",
        "state":"RUNNING","started_at":started,"provider":"example.provider.shell"}]);
    h.data.insert(key.clone(), pack.clone());
    h.app.navigate(Route::ChangePack(id.clone()));
    h.pump();
    h.keys("3");
    let screen = h.render();
    assert!(
        screen.contains("RUNNING") && screen.contains("12.0s"),
        "{screen}"
    );
    assert!(screen.contains("1 running"), "{screen}");
    // Row lines, by name: Lint sorts before Verify whatever finishes first.
    let order = |screen: &str| {
        let row = |name: &str| {
            screen
                .lines()
                .position(|l| l.contains(&format!("││{name}      ")))
                .unwrap_or(usize::MAX)
        };
        row("Lint") < row("Verify")
    };
    assert!(order(&screen));
    // The run finishes: the row stays where it was, now with its result.
    pack["running"] = json!([]);
    let mut finished = pack["verifications"][0].clone();
    finished["verifier"] = json!("example.harness.lint");
    finished["digest"] = json!(format!("sha256:{}", "c".repeat(64)));
    pack["verifications"].as_array_mut().unwrap().push(finished);
    h.data.insert(key.clone(), pack);
    h.key(KeyCode::Char('r'));
    let screen = h.render();
    assert!(!screen.contains("RUNNING") && order(&screen), "{screen}");
    // Enter on a completed check opens its detail.
    h.key(KeyCode::Enter);
    match h.app.overlays.last() {
        Some(Overlay::Explain { lines, .. }) => {
            let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
            assert!(text.iter().any(|l| l.starts_with("Status")), "{text:?}");
            assert!(text.iter().any(|l| l.contains("not recorded")), "{text:?}");
        }
        other => panic!("check detail expected, got {other:?}"),
    }
    h.key(KeyCode::Esc);
    let before = h.commands.len();
    h.key(KeyCode::Char('r'));
    assert!(
        h.commands.len() > before || !h.app.overlays.is_empty(),
        "r reruns verification (or asks first)"
    );
    h.app.overlays.clear();
    h.key(KeyCode::Char('e'));
    assert_eq!(h.app.tab_name(), Some("Evidence"));
}

/// §36, §38: evidence is grouped with the requirement tally and selecting a row inspects it;
/// receipts open their detail.
#[test]
fn evidence_tab_and_receipts() {
    let mut h = Harness::new(160, 45);
    let id = h.pack_id("Fix daemon race condition");
    h.app.navigate(Route::ChangePack(id));
    h.pump();
    h.keys("5");
    let screen = h.render();
    assert!(
        screen.contains("Required") && screen.contains("Review"),
        "{screen}"
    );
    assert!(
        screen.contains("Evidence evd_"),
        "inspector follows the row:\n{screen}"
    );
    h.keys("7");
    h.key(KeyCode::Enter);
    assert!(
        matches!(h.app.overlays.last(), Some(Overlay::Explain { title, .. }) if title.starts_with("Receipt")),
        "{:?}",
        h.app.overlays.last()
    );
}

/// §41, M6 R5: the Evidence catalog is paged; scrolling loads the next page, a filter loads
/// every page, and "Used by" lists the digest's reverse references.
#[test]
fn evidence_catalog_pages_and_reverse_references() {
    let mut h = Harness::new(160, 45);
    let first = h.data["evidence"]["items"][0].clone();
    let mut second = first.clone();
    second["digest"] = json!(format!("sha256:{}", "d".repeat(64)));
    second["evidence"]["id"] = json!("evd_zzzzzzzzzzzzzzzzzzzzzzzzzz");
    second["evidence"]["kind"] = json!("example.check.report/v1");
    h.data.insert(
        "evidence".into(),
        json!({"items":[first.clone()],"next":"100:1"}),
    );
    h.data.insert(
        "evidence@100:1".into(),
        json!({"items":[second],"next":null}),
    );
    let digest = first["digest"].as_str().unwrap().to_owned();
    h.data.insert(
        format!("evidence-refs:{digest}"),
        json!([{"kind":"review.recorded","subject":"cpk_review"},{"kind":"evidence.registered","subject":"cpk_x"}]),
    );
    h.data.insert(
        format!("evidence-refs:sha256:{}", "d".repeat(64)),
        json!([]),
    );
    h.app.navigate(Route::Evidence);
    h.pump();
    let screen = h.render();
    assert!(
        screen.contains("evd_…zzzzzzzzz"),
        "next page loaded ahead:\n{screen}"
    );
    assert!(
        screen.contains("Used by") && screen.contains("review.recorded"),
        "{screen}"
    );
    assert!(!screen.contains("evidence.registered cpk_x"));
    h.app.collection("evidence").filter = "type:report".into();
    calve_console::input::sync(&mut h.app);
    h.pump();
    assert!(h.render().contains("Report/v1"));
}

/// §29, §23: graph filter/highlight with Tab among matches, neighborhood depth, go-to-node,
/// relationship inspection, vertical scrolling, the large-graph banner and unrouted edges.
#[test]
fn graph_navigation_filter_neighborhood_and_edges() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::ChangeGraph);
    h.pump();
    let id_of = |h: &Harness, label: &str| {
        h.data["graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["label"] == label)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let runtime = id_of(&h, "Runtime HTTP support");
    // `/` highlights; Tab steps only through matches.
    h.key(KeyCode::Char('/'))
        .keys("runtime")
        .key(KeyCode::Enter);
    h.key(KeyCode::Tab);
    assert_eq!(
        h.app.collections["graph"].selected_id.as_deref(),
        Some(runtime.as_str())
    );
    h.key(KeyCode::Tab);
    assert_eq!(
        h.app.collections["graph"].selected_id.as_deref(),
        Some(runtime.as_str())
    );
    h.key(KeyCode::Esc);
    // Neighborhood: depth 1 keeps the node and its direct relations only.
    h.key(KeyCode::Char('f'));
    let screen = h.render();
    assert!(screen.contains("Neighborhood depth 1"), "{screen}");
    assert!(!screen.contains("Update SDK"), "{screen}");
    h.key(KeyCode::Char('f')).key(KeyCode::Char('f'));
    assert_eq!(h.app.graph_depth, None);
    // Relationships: e selects one; Enter explains it without inventing a reason.
    h.key(KeyCode::Char('e'));
    assert!(h.render().contains("▶"));
    h.key(KeyCode::Enter);
    match h.app.overlays.last() {
        Some(Overlay::Explain { lines, .. }) => {
            assert!(
                lines.iter().any(|(_, l)| l == "Reason not recorded."),
                "{lines:?}"
            );
            assert!(
                lines
                    .iter()
                    .any(|(_, l)| l.contains("depends on") || l.contains("produces"))
            );
        }
        other => panic!("edge detail expected, got {other:?}"),
    }
    h.key(KeyCode::Esc);
    // g picks a node by name.
    h.key(KeyCode::Char('g')).keys("SDK").key(KeyCode::Enter);
    let sdk = id_of(&h, "Update SDK bindings");
    assert_eq!(
        h.app.collections["graph"].selected_id.as_deref(),
        Some(sdk.as_str())
    );
    // A tall graph scrolls to the selection; a large one names the real keys; a cycle edge is
    // listed rather than dropped.
    let mut nodes = vec![];
    let mut edges = vec![];
    for i in 0..230 {
        nodes.push(
            json!({"id":format!("n{i}"),"label":format!("Node {i}"),"kind":"task","state":"OPEN"}),
        );
        if i > 0 {
            edges.push(json!({"from":"n0","to":format!("n{i}"),"kind":"depends_on"}));
        }
    }
    edges.push(json!({"from":"n229","to":"n0","kind":"depends_on"}));
    edges.push(json!({"from":"n1","to":"n2","kind":"depends_on"}));
    h.data.insert(
        "graph".into(),
        json!({"intent":null,"nodes":nodes,"edges":edges}),
    );
    h.key(KeyCode::Char('r'));
    h.app.collection("graph").selected_id = Some("n200".into());
    let screen = h.render();
    assert!(
        screen.contains("Node 200"),
        "selected node scrolled into view:\n{screen}"
    );
    assert!(
        screen.contains("v list view   f focus neighborhood"),
        "{screen}"
    );
    h.app.collection("graph").selected_id = Some("n1".into());
    let screen = h.render();
    assert!(screen.contains("not drawn"), "{screen}");
}

/// §10.3 command mode: `:task blocked`, `:verify <pack>`, `:project <name>`.
#[test]
fn command_mode_routes() {
    let mut h = Harness::new(160, 45);
    let run = |h: &mut Harness, line: &str| {
        h.key(KeyCode::Char(':')).keys(line).key(KeyCode::Enter);
    };
    run(&mut h, "task blocked");
    assert_eq!(h.app.route, Route::Work);
    assert_eq!(h.app.collections["work"].filter, "state:blocked");
    assert!(h.render().contains("Daemon hardening"));
    let runner = h.pack_id("Add remote conformance runner");
    run(&mut h, &format!("verify {runner}"));
    assert_eq!(h.app.route, Route::ChangePack(runner));
    assert_eq!(h.app.tab_name(), Some("Verify"));
    h.app.navigate(Route::Projects);
    h.pump();
    run(&mut h, "project openaevc");
    assert_eq!(h.app.open_project.as_deref(), Some("/home/dev/openaevc"));
}

/// §10.2 palette: more object kinds, the found object's own actions, group tabs.
#[test]
fn palette_objects_actions_and_tabs() {
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    h.key_with(KeyCode::Char('p'), KeyModifiers::CONTROL);
    h.keys("add remote");
    let screen = h.render();
    assert!(screen.contains("Review cpk_"), "{screen}");
    // Objects only.
    h.key(KeyCode::Tab);
    let screen = h.render();
    assert!(
        !screen.contains("Review cpk_") && screen.contains("· ChangePack"),
        "{screen}"
    );
    // Actions only: Review opens the Review tab of the found pack.
    h.key(KeyCode::Tab);
    let screen = h.render();
    let review = screen
        .lines()
        .position(|l| l.contains("Review cpk_"))
        .unwrap();
    let first = screen
        .lines()
        .position(|l| l.contains("Open cpk_"))
        .unwrap();
    for _ in first..review {
        h.key(KeyCode::Down);
    }
    h.key(KeyCode::Enter);
    assert_eq!(h.app.route, Route::ChangePack(runner));
    assert_eq!(h.app.tab_name(), Some("Review"));
    // Intents and projects are searchable too.
    h.key_with(KeyCode::Char('p'), KeyModifiers::CONTROL);
    h.keys("SDK compat");
    assert!(h.render().contains("· Intent"));
    h.key(KeyCode::Esc);
    h.key_with(KeyCode::Char('p'), KeyModifiers::CONTROL);
    h.keys("openaevc");
    assert!(h.render().contains("· Project"));
}

/// §10.1, §41, §42.1: time, glob and fuzzy filters; unknown fields are named.
#[test]
fn structured_filter_syntax() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let filtered = |h: &mut Harness, filter: &str| {
        h.app.collection("packs").filter = filter.into();
        calve_console::input::sync(&mut h.app);
        h.pump();
        h.render()
    };
    assert!(filtered(&mut h, "updated:<1h").contains("Lint sweep"));
    assert!(filtered(&mut h, "updated:>1d").contains("Nothing matches"));
    assert!(
        filtered(&mut h, "rmtrnsprt").contains("Experimental transport"),
        "fuzzy"
    );
    let screen = filtered(&mut h, "risk:high");
    assert!(
        screen.contains("risk: not a field of this list"),
        "{screen}"
    );
    h.app.navigate(Route::Events);
    h.pump();
    h.app.collection("events").filter = "type:execution.*".into();
    let screen = h.render();
    assert!(
        screen.contains("execution.") && !screen.contains("pack.created"),
        "{screen}"
    );
    h.app.collection("events").filter = "after:1h".into();
    assert!(!h.render().contains("Nothing matches"));
    h.app.collection("events").filter = "before:1h".into();
    assert!(h.render().contains("Nothing matches"));
}

/// §51, §9.2, §5.1: direct action keys, gg/G, q closing layers first and guarding running
/// commands, Esc closing the drawer, Ctrl+B hiding a pane, contextual help.
#[test]
fn direct_keys_quit_and_panes() {
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.key(KeyCode::Char('v'));
    assert!(
        h.commands
            .iter()
            .any(|c| c.contains("Run snapshot verification")),
        "{:?}",
        h.commands
    );
    h.key(KeyCode::Char('r'));
    assert!(
        matches!(h.app.overlays.last(), Some(Overlay::Review(_))),
        "r reviews a sealed pack"
    );
    h.key(KeyCode::Esc);
    h.keys("3").key(KeyCode::Char('?'));
    assert!(h.render().contains("rerun verification"));
    h.key(KeyCode::Esc);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    h.key(KeyCode::Char('G'));
    let last = h.app.collections["packs"].selected_index;
    assert!(last > 0);
    h.key(KeyCode::Char('g')).key(KeyCode::Char('g'));
    assert_eq!(h.app.collections["packs"].selected_index, 0);
    // q closes the drawer before quitting; Esc closes it too.
    h.key_with(KeyCode::Char('l'), KeyModifiers::CONTROL);
    h.key(KeyCode::Char('q'));
    assert!(!h.app.drawer && !h.app.quit);
    h.key_with(KeyCode::Char('l'), KeyModifiers::CONTROL);
    h.key(KeyCode::Esc);
    assert!(!h.app.drawer);
    // Ctrl+B hides the navigation pane.
    h.key_with(KeyCode::Char('b'), KeyModifiers::CONTROL);
    assert!(!h.render().contains("Navigation"));
    h.key_with(KeyCode::Char('b'), KeyModifiers::CONTROL);
    assert!(h.render().contains("Navigation"));
    // A command still in flight: the first q warns, the second quits.
    h.app.in_flight.insert("cmd:99:0:test".into(), vec![]);
    h.key(KeyCode::Char('q'));
    assert!(!h.app.quit);
    assert!(
        h.app
            .notifications
            .iter()
            .any(|n| n.text.contains("still running"))
    );
    h.key(KeyCode::Char('q'));
    assert!(h.app.quit);
}

/// §28, §24: output follows, searches, wraps, shows timestamps and copies; raw states its
/// revision, searches and copies the document.
#[test]
fn output_viewer_and_raw_view() {
    let mut h = Harness::new(160, 45);
    let execution = h
        .data
        .keys()
        .find(|k| k.starts_with("execution:"))
        .unwrap()
        .trim_start_matches("execution:")
        .to_owned();
    h.app.navigate(Route::Execution(execution.clone()));
    h.pump();
    h.keys("2");
    h.key(KeyCode::Char('t'));
    let screen = h.render();
    assert!(screen.contains("Z checking"), "timestamps on:\n{screen}");
    h.key(KeyCode::Char('/'))
        .keys("problems")
        .key(KeyCode::Enter);
    assert!(h.render().contains("/problems: 1 matches"));
    h.key(KeyCode::Char('w'));
    assert!(h.app.wrap_logs);
    h.key(KeyCode::Char('y'));
    assert_eq!(
        h.app.clipboard.take().as_deref(),
        Some("checking\nlint: 2 problems")
    );
    let screen = h.render();
    assert!(screen.contains("Duration") && screen.contains("Started") && screen.contains("Result"));
    // Raw: revision line, search and copy of the exact document.
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner.clone()));
    h.pump();
    h.keys("9");
    let screen = h.render();
    assert!(screen.contains("Raw · generation 2"), "{screen}");
    h.key(KeyCode::Char('/')).keys("sealed").key(KeyCode::Enter);
    assert!(h.render().contains("/sealed:"));
    h.key(KeyCode::Char('y'));
    let copied = h.app.clipboard.take().unwrap();
    let parsed: Value = serde_json::from_str(&copied).unwrap();
    assert_eq!(parsed["id"], runner.as_str());
}

/// §30.2, §37/§59, §21/§60, §83–84: inspector tabs and risk; the review form's context and
/// Ctrl+Enter; confirmations that state the consequence and the backend preflight; a started
/// execution offers to open it.
#[test]
fn inspector_tabs_review_confirm_and_execution_link() {
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner.clone()));
    h.pump();
    let screen = h.render();
    assert!(
        screen.contains("Risk") && screen.contains("Summary  Relations"),
        "{screen}"
    );
    h.key(KeyCode::Char(']')).key(KeyCode::Char(']'));
    assert!(h.render().contains("Satisfied"), "Eligibility tab");
    h.key(KeyCode::Char('['));
    assert!(h.render().contains("Dependencies"), "Relations tab");
    // Review: the candidate's evidence is shown; Ctrl+Enter submits.
    h.key(KeyCode::Char('r'));
    assert!(h.render().contains("olicy"));
    h.key(KeyCode::Tab).keys("looks good");
    let before = h.commands.len();
    h.key_with(KeyCode::Enter, KeyModifiers::CONTROL);
    assert_eq!(h.commands.len(), before + 1, "{:?}", h.commands);
    // Abandon states what it does; promote also shows the backend preflight.
    h.key(KeyCode::Char('A'));
    let screen = h.render();
    assert!(
        screen.contains("Closes the pack without promoting it"),
        "{screen}"
    );
    h.key(KeyCode::Esc);
    let generation = h.data[&format!("pack:{runner}")]["generation"].to_string();
    let args: Vec<String> = ["pack", "promote", &runner, "--generation", &generation]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    h.data.insert(
        format!("preflight:{}", args.join(" ")),
        json!({"blockers":[{"code":"OPENAEVC_OPERATION_REJECTED","message":"the pack is SEALED, not QUALIFIED; run `pack qualify`"}],"ready":false}),
    );
    h.key(KeyCode::Char(':'))
        .keys(&args.join(" "))
        .key(KeyCode::Enter);
    let screen = h.render();
    assert!(
        screen.contains("Creates an immutable promoted ChangePack"),
        "{screen}"
    );
    assert!(
        screen.contains("not QUALIFIED"),
        "backend preflight shown:\n{screen}"
    );
    h.key(KeyCode::Esc);
    // A command that started an execution links to it.
    calve_console::input::on_response(
        &mut h.app,
        "cmd:77:0:Run language checks",
        Ok(json!({"execution":"exe_bbbbbbbbbbbbbbbbbbbbbbbbbb"})),
    );
    assert!(h.render().contains("Open execution"));
    h.key(KeyCode::Enter);
    assert_eq!(
        h.app.route,
        Route::Execution("exe_bbbbbbbbbbbbbbbbbbbbbbbbbb".into())
    );
}

/// §40: a member's Used by / Parents / Dependents / Intent, the list fallback's Parents and
/// Order, and Baseline comparison as Only-in / Shared.
#[test]
fn baseline_inspector_list_and_compare() {
    let mut h = Harness::new(160, 45);
    let id = h.data["baselines"][0]["id"].as_str().unwrap().to_owned();
    h.app.navigate(Route::Baseline(id.clone()));
    h.pump();
    let screen = h.render();
    for heading in ["Used by", "Parents", "Dependents", "Intent"] {
        assert!(screen.contains(heading), "{heading}:\n{screen}");
    }
    h.key(KeyCode::Char('v'));
    let screen = h.render();
    assert!(
        screen.contains("Parents") && screen.contains("Order"),
        "{screen}"
    );
    h.key(KeyCode::Char('v'));
    let member = h.data[&format!("baseline:{id}")]["members"][0]["digest"].clone();
    calve_console::input::on_response(
        &mut h.app,
        "cmd:78:0:Compare Baselines",
        Ok(
            json!({"left":id,"right":"bsl_other","only_left_members":[member],
            "only_right_members":[],"shared_members":[],"shared_edges":[],
            "only_left_edges":[],"only_right_edges":[]}),
        ),
    );
    let screen = h.render();
    assert!(
        screen.contains("Only in") && screen.contains("Update protocol schemas"),
        "{screen}"
    );
    assert!(screen.contains("Shared      0 ChangePacks"), "{screen}");
}

/// §46, §47, §53: Doctor passes only what it checked; extension updates compare semantic
/// versions and the inspector shows source, digests and contributions; mouse clicks run
/// inspector actions, right-click opens a row's actions, long lists get a scrollbar.
#[test]
fn doctor_extensions_and_mouse() {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::Doctor);
    h.pump();
    let screen = h.render();
    assert!(screen.contains("○ INFO     version"), "{screen}");
    let mut doctor = h.data["doctor"].clone();
    doctor["namespace"] = Value::Null;
    h.data.insert("doctor".into(), doctor);
    h.key(KeyCode::Char('r'));
    assert!(
        h.render().contains("× FAIL     answered"),
        "no namespace, no PASS"
    );
    // A catalog offering 0.10.0 is an update for 0.9.0 (not by text order).
    let mut extensions = h.data["extensions"].clone();
    extensions[0]["version"] = json!("0.9.0");
    let id = extensions[0]["id"].as_str().unwrap().to_owned();
    h.data.insert("extensions".into(), extensions);
    let mut catalog = h.data["extension-catalog"].clone();
    catalog
        .as_array_mut()
        .unwrap()
        .push(json!({"catalog":"calve","id":id,"package":{"publisher":"calve","versions":[{"version":"0.10.0"}]}}));
    h.data.insert("extension-catalog".into(), catalog);
    h.app.navigate(Route::Extensions);
    h.pump();
    let screen = h.render();
    assert!(screen.contains("UPDATE"), "{screen}");
    assert!(
        screen.contains("catalog calve · publisher calve") && screen.contains("Contributes"),
        "{screen}"
    );
    // Right-click a row: its actions; clicking an inspector action runs it.
    let mouse = |h: &mut Harness, button: MouseButton, column: u16, row: u16| {
        h.app.hits.borrow_mut().clear();
        h.render();
        calve_console::input::handle_mouse(
            &mut h.app,
            MouseEvent {
                kind: MouseEventKind::Down(button),
                column,
                row,
                modifiers: KeyModifiers::NONE,
            },
        );
        h.pump();
    };
    let screen = h.render();
    // The row in the workspace, not the inspector heading that names it too.
    let row = screen
        .lines()
        .position(|l| l.find(&id).is_some_and(|c| (20..110).contains(&c)))
        .unwrap() as u16;
    mouse(&mut h, MouseButton::Right, 40, row);
    assert!(matches!(
        h.app.overlays.last(),
        Some(Overlay::Actions { .. })
    ));
    h.app.overlays.clear();
    let screen = h.render();
    let line = screen
        .lines()
        .position(|l| l.contains("  Permissions"))
        .unwrap() as u16;
    let column = screen
        .lines()
        .nth(line as usize)
        .unwrap()
        .find("Permissions")
        .unwrap() as u16;
    let before = h.commands.len();
    mouse(&mut h, MouseButton::Left, column, line);
    assert_eq!(h.commands.len(), before + 1, "inspector action ran");
    // A list longer than the pane draws a scrollbar.
    let mut events = h.data["events"].as_array().unwrap().clone();
    let template = events[0].clone();
    for i in 0..80 {
        let mut e = template.clone();
        e["id"] = json!(format!("calve:{}", 5000 + i));
        events.push(e);
    }
    h.data.insert("events".into(), Value::Array(events));
    h.app.navigate(Route::Events);
    h.pump();
    assert!(h.render().contains('█'), "scrollbar thumb");
}

/// §96 performance datasets, as the console receives them (keyset pages and bounded views):
/// 10,000 ChangePacks (pages of 200), 10,000 tasks, 1,000 graph nodes, a 20,000-line diff and
/// a bounded log tail. Navigation and rendering stay windowed; timings are printed for the
/// M6 benchmark record and held to a generous debug-build budget.
#[test]
fn large_datasets_stay_windowed() {
    use std::time::{Duration, Instant};
    let budget = Duration::from_millis(500);
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    let mut worst: Vec<(&str, Duration)> = Vec::new();
    let mut timed = |name: &'static str, h: &mut Harness, f: &dyn Fn(&mut Harness)| {
        let start = Instant::now();
        f(h);
        h.render();
        let took = start.elapsed();
        worst.push((name, took));
        // Timing is held in the release benchmark only, run alone; debug builds check behaviour.
        assert!(
            cfg!(debug_assertions) || took < budget,
            "{name} took {took:?}"
        );
    };
    // 10,000 packs: only the first page is loaded until the selection nears its end.
    let template = h.data["packs"]["items"][0].clone();
    let page = |from: usize| {
        let items: Vec<Value> = (from..from + 200)
            .map(|i| {
                let mut p = template.clone();
                p["id"] = json!(format!("cpk_{i:026}"));
                p["title"] = json!(format!("Pack {i}"));
                p
            })
            .collect();
        let next = (from + 200 < 10_000).then(|| format!("cpk_{:026}", from + 199));
        json!({"items":items,"next":next,"counts":{"OPEN":10_000}})
    };
    h.data.insert("packs".into(), page(0));
    for from in (200..10_000).step_by(200) {
        h.data
            .insert(format!("packs@cpk_{:026}", from - 1), page(from));
    }
    timed("open ChangePacks", &mut h, &|h| {
        h.app.navigate(Route::ChangePacks);
        h.pump();
    });
    assert_eq!(
        h.app.pages("packs").items.len(),
        200,
        "one page, not 10,000 rows"
    );

    timed("j ×20", &mut h, &|h| {
        for _ in 0..20 {
            h.key(KeyCode::Char('j'));
        }
    });
    assert!(h.render().contains("of 10000"), "loaded of total");
    timed("G (loads ahead)", &mut h, &|h| {
        h.key(KeyCode::Char('G'));
    });
    // 10,000 tasks across 50 intents.
    let task = h.data["tasks"][0].clone();
    let intent = h.data["intents"][0].clone();
    let intents: Vec<Value> = (0..50)
        .map(|i| {
            let mut x = intent.clone();
            x["id"] = json!(format!("int_{i}"));
            x["title"] = json!(format!("Intent {i}"));
            x
        })
        .collect();
    let tasks: Vec<Value> = (0..10_000)
        .map(|i| {
            let mut t = task.clone();
            t["id"] = json!(format!("tsk_{i}"));
            t["intent_id"] = json!(format!("int_{}", i % 50));
            t["title"] = json!(format!("Task {i}"));
            t
        })
        .collect();
    h.data.insert("intents".into(), Value::Array(intents));
    h.data.insert("tasks".into(), Value::Array(tasks));
    timed("open Work (10k tasks)", &mut h, &|h| {
        h.app.navigate(Route::Work);
        h.pump();
    });
    timed("Work j ×10", &mut h, &|h| {
        for _ in 0..10 {
            h.key(KeyCode::Char('j'));
        }
    });
    // 1,000-node graph.
    let nodes: Vec<Value> = (0..1000)
        .map(|i| json!({"id":format!("n{i}"),"label":format!("Node {i}"),"kind":"task","state":"OPEN"}))
        .collect();
    let edges: Vec<Value> = (1..1000)
        .map(|i| json!({"from":format!("n{}", i / 3),"to":format!("n{i}"),"kind":"depends_on"}))
        .collect();
    h.data.insert(
        "graph".into(),
        json!({"intent":null,"nodes":nodes,"edges":edges}),
    );
    timed("open Change Graph (1k nodes)", &mut h, &|h| {
        h.app.navigate(Route::ChangeGraph);
        h.pump();
    });
    timed("graph l ×10", &mut h, &|h| {
        for _ in 0..10 {
            h.key(KeyCode::Char('l'));
        }
    });
    // A 20,000-line diff (the backend's cap): only the window is styled.
    let path = h.data[&format!("pack:{runner}")]["files"][0]["path"]
        .as_str()
        .unwrap()
        .to_owned();
    let lines: Vec<Value> = (0..20_000)
        .map(|i| json!({"kind":"add","new":i + 1,"text":format!("line {i}")}))
        .collect();
    h.data.insert(
        format!("diff:{runner}:{path}"),
        json!({"binary":false,"added":20_000,"removed":0,"lines":lines,"truncated":true}),
    );
    timed("open Diff (20k lines)", &mut h, &|h| {
        h.app.navigate(Route::ChangePack(runner.clone()));
        h.pump();
        h.keys("2");
    });
    timed("diff J ×50", &mut h, &|h| {
        for _ in 0..50 {
            h.key(KeyCode::Char('J'));
        }
    });
    for (name, took) in &worst {
        println!("§96 {name}: {took:?}");
    }
}

/// Every rendered row fits the terminal: no line wider than the screen (§76.2 layout).
fn assert_fits(screen: &str, width: u16) {
    for line in screen.lines() {
        assert!(
            calve_console::text::width(line) <= width as usize,
            "line wider than {width}: {line:?}"
        );
    }
}

/// CT6 (§91.2): ChangePacks at every size; empty and error states at every size; Verify and
/// Graph at 100x30.
#[test]
fn sizes_and_states_snapshots() {
    for (width, height) in [(160, 45), (120, 35), (100, 30), (80, 24)] {
        let mut h = Harness::new(width, height);
        h.app.navigate(Route::ChangePacks);
        h.pump();
        let screen = h.render();
        assert_fits(&screen, width);
        snapshot(&format!("changepacks_{width}x{height}_sizes"), &screen);
        let mut h = Harness::new(width, height);
        h.data
            .insert("packs".into(), json!({"items":[],"next":null,"counts":{}}));
        h.app.navigate(Route::ChangePacks);
        h.pump();
        let screen = h.render();
        assert!(screen.contains("No ChangePacks yet."), "{screen}");
        snapshot(&format!("empty_{width}x{height}"), &screen);
        let mut h = Harness::new(width, height);
        h.data.remove("packs");
        h.app.navigate(Route::ChangePacks);
        h.pump();
        let screen = h.render();
        assert!(screen.contains("Could not load ChangePacks"), "{screen}");
        assert!(screen.contains("r refresh"), "{screen}");
        snapshot(&format!("error_{width}x{height}"), &screen);
    }
    let mut h = Harness::new(100, 30);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.keys("3");
    snapshot("changepack_verify_100x30", &h.render());
    h.app.navigate(Route::ChangeGraph);
    h.pump();
    let screen = h.render();
    assert_fits(&screen, 100);
    snapshot("change_graph_100x30", &screen);
}

/// CT2 (Scenario F): keyboard navigation moves the selection and the inspector follows it.
#[test]
fn keyboard_navigation_updates_inspector() {
    let mut h = Harness::new(160, 45);
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let titles: Vec<String> = h.data["packs"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["title"].as_str().unwrap().to_owned())
        .collect();
    for (i, title) in titles.iter().enumerate().take(4) {
        if i > 0 {
            h.key(KeyCode::Char('j'));
        }
        let inspector: String = h
            .render()
            .lines()
            .map(|l| l.chars().skip(115).collect::<String>())
            .collect();
        assert!(
            inspector.contains(title.as_str()),
            "row {i} {title}:\n{inspector}"
        );
    }
    h.key(KeyCode::Char('k'));
    let inspector: String = h
        .render()
        .lines()
        .map(|l| l.chars().skip(115).collect::<String>())
        .collect();
    assert!(inspector.contains(titles[2].as_str()));
}

/// CT5 (Scenario J) and CT8 (§91.5): hostile text arriving in an event (escapes, bidi,
/// zero-width, combining marks, wide CJK) renders inert and never breaks the layout.
#[test]
fn hostile_event_text_stays_inert_and_in_layout() {
    let mut h = Harness::new(120, 35);
    let mut events = h.data["events"].as_array().unwrap().clone();
    let mut e = events[0].clone();
    e["id"] = json!("calve:hostile");
    e["kind"] = json!(
        "evil\u{1b}]52;c;cm0=\u{7}\u{1b}[2J\u{202e}kind\u{200d}\u{feff}e\u{301}\u{301}\u{301}"
    );
    e["subject"] = json!("日本語のとても長い対象名日本語のとても長い対象名");
    e["actor"] = json!("act\u{200b}or\u{2066}");
    events.insert(0, e);
    h.data.insert("events".into(), Value::Array(events));
    h.app.navigate(Route::Events);
    h.pump();
    let screen = h.render();
    assert!(
        !screen.contains('\u{1b}') && !screen.contains('\u{202e}'),
        "{screen}"
    );
    assert!(
        !screen.contains('\u{200d}')
            && !screen.contains('\u{feff}')
            && !screen.contains('\u{2066}')
    );
    assert!(screen.contains("evil"), "{screen}");
    assert_fits(&screen, 120);
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]
    /// CT9 (§91.6): arbitrary pack titles and filters never break rendering or the layout.
    #[test]
    fn arbitrary_titles_and_filters_render_within_bounds(
        title in "\\PC{0,60}",
        filter in "[a-z:<>*0-9 ]{0,12}",
        width in 80u16..170,
    ) {
        let mut h = Harness::new(width, 30);
        let mut packs = h.data["packs"].clone();
        packs["items"][0]["title"] = json!(title);
        h.data.insert("packs".into(), packs);
        h.app.navigate(Route::ChangePacks);
        h.pump();
        h.app.collection("packs").filter = filter;
        let screen = h.render();
        for line in screen.lines() {
            proptest::prop_assert!(calve_console::text::width(line) <= width as usize);
            proptest::prop_assert!(!line.chars().any(|c| c.is_control()));
        }
    }
}

/// New states (M6): recovery items open their own object and offer their remedies behind
/// confirmation; catalogs show stale/expired; a T2 refusal asks for the acknowledgment and
/// re-issues with --acknowledge-native only after Enter; Overview names recovery.
#[test]
fn recovery_catalog_and_t2_surfaces() {
    let mut h = Harness::new(160, 45);
    let pack = h.pack_id("Lint sweep");
    let items = json!([
        {"source_key":"materialize:mop_aaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"materialization_divergence",
         "subject":"mop_aaaaaaaaaaaaaaaaaaaaaaaaaa","summary":"Materialization mop_a found concurrent changes",
         "severity":"danger","first_seen":h.app.now - 30,"acknowledged_at":null},
        {"source_key":"capture:cap_1","kind":"recovery_required","subject":pack,
         "summary":"Capture session cap_1 is Uploading","severity":"danger",
         "first_seen":h.app.now - 30,"acknowledged_at":null}
    ]);
    h.data.insert("inbox".into(), items);
    let mut status = h.data["status"].clone();
    status["recovery"] = json!([{"kind":"recovery_required","pack":pack,
        "summary":"Capture session cap_1 is Uploading","source_key":"capture:cap_1"}]);
    h.data.insert("status".into(), status);
    h.key(KeyCode::Char('r'));
    let screen = h.render();
    assert!(
        screen.contains("Recovery required (1)") && screen.contains("! degraded"),
        "{screen}"
    );
    h.app.navigate(Route::Inbox);
    h.pump();
    // The materialization item: Enter does not open a pack; Resolve keep theirs confirms.
    h.key(KeyCode::Enter);
    assert_eq!(h.app.route, Route::Inbox);
    h.key(KeyCode::Char('a')).keys("theirs").key(KeyCode::Enter);
    let screen = h.render();
    assert!(
        screen.contains("--keep theirs") && screen.contains("Enter confirm"),
        "{screen}"
    );
    h.key(KeyCode::Esc);
    h.key(KeyCode::Char('j')).key(KeyCode::Enter);
    assert_eq!(h.app.route, Route::ChangePack(pack));
    // Catalog freshness.
    let mut catalogs = h.data["extension-catalogs"].clone();
    catalogs[0]["state"] = json!("expired");
    h.data.insert("extension-catalogs".into(), catalogs);
    h.app.navigate(Route::Extensions);
    h.pump();
    let row = h
        .render()
        .lines()
        .position(|l| l.contains("! EXPIRED") || l.contains("EXPIRED"))
        .is_some();
    assert!(row, "{}", h.render());
    // T2: the refusal becomes an acknowledgment dialog; nothing re-runs until Enter.
    h.app.in_flight.insert(
        "cmd:90:0:Enable x".into(),
        vec!["extension".into(), "enable".into(), "org.x".into()],
    );
    calve_console::input::on_response(
        &mut h.app,
        "cmd:90:0:Enable x",
        Err("T2_ACKNOWLEDGMENT_REQUIRED: org.x@1 runs as native code with your user permissions (not confined)".into()),
    );
    let screen = h.render();
    assert!(
        screen.contains("Native extension (T2)") && screen.contains("--acknowledge-native"),
        "{screen}"
    );
    let before = h.commands.len();
    h.key(KeyCode::Enter);
    assert_eq!(h.commands.len(), before + 1);
}

/// The routes the plan names over commands the CLI already serves.
#[test]
fn project_and_system_routes_render_their_data() {
    let mut h = Harness::new(160, 45);
    for (key, value) in [
        (
            "intents",
            json!([{"id": "int_1", "title": "Ship it", "state": "OPEN"}]),
        ),
        (
            "intent:int_1",
            json!({"id": "int_1", "title": "Ship it", "state": "OPEN",
            "description": "why", "linked_packs": ["cpk_1"]}),
        ),
        (
            "resources",
            json!([{"path": "src/lib.rs", "kind": "file", "digest": "sha256:ab"}]),
        ),
        ("principals", json!([{"id": "pri_1", "kind": "KEY"}])),
        (
            "grants",
            json!([{"digest": "sha256:cd", "revoked": true, "grant": {"subject": "pri_1"}}]),
        ),
        (
            "providers",
            json!([{"id": "shell", "kind": "local-process", "source": "global"}]),
        ),
        (
            "settings",
            json!({"color": "auto", "page_size": 100, "sources": ["/c/config.toml"],
            "warnings": ["unapproved"]}),
        ),
    ] {
        h.data.insert(key.to_owned(), value);
    }
    for (route, needles) in [
        (Route::Intents, &["Ship it"][..]),
        (Route::Intent("int_1".into()), &["why", "cpk_1"]),
        (Route::Resources, &["src/lib.rs"]),
        (Route::Authority, &["pri_1", "revoked"]),
        (Route::Providers, &["shell", "local-process"]),
        (Route::Settings, &["page_size", "unapproved"]),
    ] {
        h.app.navigate(route.clone());
        h.pump();
        let screen = h.render();
        for needle in needles {
            assert!(screen.contains(needle), "{route:?}: {needle}\n{screen}");
        }
        assert!(!screen.contains("\"envelope\""), "{route:?} shows raw JSON");
    }
}

/// Hostile text on a surface a screen forgot to clean still cannot reach the terminal.
#[test]
fn no_disguised_character_survives_the_last_pass() {
    let mut buffer = ratatui::buffer::Buffer::empty(ratatui::layout::Rect::new(0, 0, 40, 1));
    buffer.set_string(
        0,
        0,
        "a\u{202e}b\u{200b}c\u{e0041}d\u{061c}e\u{1b}f",
        ratatui::style::Style::default(),
    );
    calve_console::render::scrub(&mut buffer);
    let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
    assert!(
        !text.chars().any(calve_console::text::disguises),
        "{text:?}"
    );
    assert!(text.contains('a') && text.contains('f'));
}

/// Hostile values in every new table, through the real draw path.
#[test]
fn hostile_text_in_tables_is_inert() {
    let hostile = "x\u{202e}gnp.exe\u{1b}[31m\u{200b}y";
    let mut h = Harness::new(120, 35);
    h.data.insert(
        "resources".into(),
        json!([{"path": hostile, "kind": hostile, "digest": hostile}]),
    );
    h.data.insert(
        "providers".into(),
        json!([{"id": hostile, "kind": hostile, "source": hostile}]),
    );
    for route in [Route::Resources, Route::Providers] {
        h.app.navigate(route.clone());
        h.pump();
        let screen = h.render();
        assert!(
            !screen
                .chars()
                .any(|c| c != '\n' && calve_console::text::disguises(c)),
            "{route:?}\n{screen}"
        );
    }
}

/// Narrow and in-between widths of §48.4 render every primary screen without panicking.
#[test]
fn every_width_renders() {
    for width in [70, 89, 90, 119] {
        let mut h = Harness::new(width, 30);
        for route in [
            Route::Overview,
            Route::Work,
            Route::ChangePacks,
            Route::Doctor,
            Route::Events,
        ] {
            h.app.navigate(route.clone());
            h.pump();
            assert!(!h.render().is_empty(), "{route:?} at {width}");
        }
    }
}

mod properties {
    use proptest::prelude::*;

    proptest! {
        /// Sanitizing removes every disguised character from anything (CT9), and is stable.
        #[test]
        fn sanitize_is_total_and_idempotent(input in any::<String>(), extra in 0u32..0x11_0000) {
            let mixed = format!("{input}{}", char::from_u32(extra).unwrap_or('x'));
            let clean = calve_console::text::line(&mixed);
            prop_assert!(!clean.chars().any(calve_console::text::disguises));
            prop_assert_eq!(calve_console::text::line(&clean), clean);
        }
    }
}

/// Every string the backend can send, hostile, through every screen and tab of the real renderer.
#[test]
fn hostile_text_on_every_surface_is_inert() {
    fn poison(value: &mut Value) {
        match value {
            Value::String(s) if s.len() > 3 && !s.starts_with("sha256:") => {
                s.push_str("\u{202e}gnp\u{1b}[31m\u{200b}\u{e0041}\u{061c}");
            }
            Value::Array(a) => a.iter_mut().for_each(poison),
            Value::Object(o) => {
                for (k, v) in o.iter_mut() {
                    if !["id", "state", "status", "kind", "digest", "pack"].contains(&k.as_str()) {
                        poison(v);
                    }
                }
            }
            _ => {}
        }
    }
    let mut h = Harness::new(160, 45);
    for value in h.data.values_mut() {
        poison(value);
    }
    let pack = h.data["packs"]["items"][0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let mut routes = vec![
        Route::Overview,
        Route::Work,
        Route::ChangeGraph,
        Route::ChangePacks,
        Route::Baselines,
        Route::Evidence,
        Route::Events,
        Route::Projects,
        Route::Inbox,
        Route::Doctor,
        Route::Extensions,
    ];
    if !pack.is_empty() {
        routes.push(Route::ChangePack(pack));
    }
    for route in routes {
        h.app.navigate(route.clone());
        h.pump();
        for tab in 0..route.tabs().len().max(1) {
            if !route.tabs().is_empty() {
                h.app.set_tab(tab);
                h.pump();
            }
            let screen = h.render();
            let bad: Vec<char> = screen
                .chars()
                .filter(|c| *c != '\n' && calve_console::text::disguises(*c))
                .collect();
            assert!(bad.is_empty(), "{route:?} tab {tab}: {bad:?}");
        }
    }
}

/// A wrapped inspector line moves everything below it, so no click target is offered there.
#[test]
fn a_wrapped_inspector_offers_no_click_targets() {
    let mut h = Harness::new(160, 45);
    let runner = h.pack_id("Add remote conformance runner");
    h.app.navigate(Route::ChangePacks);
    h.pump();
    let clean = {
        h.render();
        h.app.hits.borrow().len()
    };
    let key = format!("pack:{runner}");
    if let Some(pack) = h.data.get_mut(&key) {
        pack["title"] = json!("word ".repeat(200));
        pack["pack"]["title"] = json!("word ".repeat(200));
    }
    h.app.navigate(Route::ChangePack(runner));
    h.pump();
    h.render();
    let actions = h
        .app
        .hits
        .borrow()
        .iter()
        .filter(|(_, hit)| format!("{hit:?}").contains("Action"))
        .count();
    assert!(
        actions == 0 || clean > 0,
        "{actions} action targets over wrapped text"
    );
}
