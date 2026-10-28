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
            for x in 0..width {
                row.push_str(buffer[(x, y)].symbol());
            }
            out.push_str(row.trim_end());
            out.push('\n');
        }
        out
    }

    fn pack_id(&self, title: &str) -> String {
        self.data["packs"]
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
    assert_eq!(h.app.clipboard.take().as_deref(), Some("calve:37"));
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
    packs[0]["title"] = json!("evil\u{1b}]52;c;cm0gLXJmIH4=\u{7}\u{1b}[2Jtitle");
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
    let expectations = [
        (Route::Work, "HTTP conformance"),
        (Route::ChangeGraph, "running"),
        (Route::Evidence, "Evidence"),
        (Route::Events, "Event"),
        (Route::Projects, "openaevc"),
        (Route::Inbox, "Execution FAILED"),
        (Route::Doctor, "Product database"),
        (Route::Extensions, "org.examples.files"),
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
