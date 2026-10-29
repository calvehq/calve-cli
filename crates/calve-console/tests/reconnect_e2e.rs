//! §57 Scenario O (console reconnect) end to end: the console engine (state, input, rendering)
//! against a real calved serving a Project with the first-party catalog's extensions on
//! OpenAEVC v0.1.0. Ignored by default; the driver prepares a Project (a trusted catalog, an
//! enabled file extension, at least three OPEN packs), isolates XDG_DATA_HOME/XDG_CONFIG_HOME/
//! XDG_RUNTIME_DIR, sets CALVE_E2E_PROJECT and CALVE_BIN (a `calve` with `calved` beside it),
//! and runs `cargo test -p calve-console --test reconnect_e2e -- --ignored`.

use std::path::PathBuf;
use std::process::Command;

use calve_api::{Outcome, Request, RequestScope};
use calve_client::{Backend, Client, Options};
use calve_console::input::{handle_key, on_response, sync};
use calve_console::model::{App, Connection, Route};
use calve_console::render;
use calve_console::theme::{Symbols, Theme, ThemeName};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

/// Serves the console's queued requests through the real client, as the runtime loop does.
fn pump(rt: &tokio::runtime::Runtime, client: &Client, scope: &RequestScope, app: &mut App) {
    for _ in 0..30 {
        let requests = app.take_requests();
        if requests.is_empty() {
            return;
        }
        for r in requests {
            let (result, backend) = rt.block_on(async {
                match client.send(Request::local(scope.clone(), r.action)).await {
                    Ok((response, backend)) => (
                        match response.outcome {
                            Outcome::Ok { value } => Ok(value),
                            Outcome::Error { error } => {
                                Err(format!("{}: {}", error.code, error.message))
                            }
                        },
                        Some(backend),
                    ),
                    Err(e) => (Err(e.to_string()), None),
                }
            });
            app.connection = app.connection.after(backend.map(|b| match b {
                Backend::Daemon => Connection::Daemon,
                Backend::Embedded => Connection::Local,
            }));
            on_response(app, &r.key, result);
        }
    }
}

fn render(app: &App) -> String {
    let mut t = Terminal::new(TestBackend::new(app.size.0, app.size.1)).unwrap();
    t.draw(|f| render::draw(f, app)).unwrap();
    let b = t.backend().buffer().clone();
    (0..app.size.1)
        .map(|y| {
            (0..app.size.0)
                .map(|x| b[(x, y)].symbol())
                .collect::<String>()
                + "\n"
        })
        .collect()
}

fn daemon(verb: &str) {
    let status = Command::new(std::env::var("CALVE_BIN").unwrap())
        .args(["daemon", verb])
        .status()
        .unwrap();
    assert!(status.success(), "calve daemon {verb}");
}

fn key(app: &mut App, c: char) {
    handle_key(app, KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
}

#[test]
#[ignore = "end to end: run by m6-scenario-o.sh against a real calved"]
fn scenario_o_console_reconnect() {
    let project = PathBuf::from(std::env::var("CALVE_E2E_PROJECT").unwrap());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = Client::new(Options {
        direct: false,
        endpoint: Some(calve_client::default_endpoint().unwrap()),
        no_daemon_start: true,
    });
    let scope = RequestScope {
        project: Some(project),
        workspace: None,
        config_file: None,
        actor: None,
    };
    daemon("start");
    // 1. Open the console.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut app = App::new(
        Theme::new(ThemeName::Mono),
        Symbols { unicode: true },
        Connection::Connecting,
        now,
    );
    app.size = (160, 45);
    pump(&rt, &client, &scope, &mut app);
    assert_eq!(app.connection, Connection::Daemon, "served by calved");
    app.navigate(Route::ChangePacks);
    pump(&rt, &client, &scope, &mut app);
    sync(&mut app);
    key(&mut app, 'j');
    pump(&rt, &client, &scope, &mut app);
    let selected = app.collections["packs"].selected_id.clone().unwrap();
    println!("selected before restart: {selected}");
    // 2–3. Restart the daemon: the console detects the disconnect and keeps its data readable.
    daemon("stop");
    app.now += 3;
    key(&mut app, 'r');
    pump(&rt, &client, &scope, &mut app);
    let screen = render(&app);
    assert_eq!(app.connection, Connection::Disconnected, "{screen}");
    assert!(
        screen.contains("! daemon disconnected") && screen.contains("STALE"),
        "{screen}"
    );
    assert!(
        !app.can_act(),
        "authority-bearing actions disabled while disconnected"
    );
    // 4–5. The compatible daemon returns: reconnect, selection preserved.
    daemon("start");
    key(&mut app, 'r');
    pump(&rt, &client, &scope, &mut app);
    let screen = render(&app);
    assert_eq!(app.connection, Connection::Daemon, "{screen}");
    assert!(
        screen.contains("● healthy") && !screen.contains("STALE"),
        "{screen}"
    );
    assert_eq!(
        app.collections["packs"].selected_id.as_deref(),
        Some(selected.as_str())
    );
    // 6. The selected object leaves the view: selection falls back to the same position.
    app.collection("packs").filter = "state:open".into();
    sync(&mut app);
    let index = app.collections["packs"].selected_index;
    let id = app.collections["packs"].selected_id.clone().unwrap();
    let generation = rt
        .block_on(
            client.call(
                scope.clone(),
                calve_console::model::parse_action(&["pack".into(), "show".into(), id.clone()])
                    .unwrap(),
            ),
        )
        .unwrap()["generation"]
        .to_string();
    rt.block_on(
        client.call(
            scope.clone(),
            calve_console::model::parse_action(&[
                "pack".into(),
                "seal".into(),
                id.clone(),
                "--generation".into(),
                generation,
            ])
            .unwrap(),
        ),
    )
    .unwrap();
    key(&mut app, 'r');
    pump(&rt, &client, &scope, &mut app);
    sync(&mut app);
    let after = app.collections["packs"].selected_id.clone();
    assert_ne!(
        after.as_deref(),
        Some(id.as_str()),
        "the sealed pack left the open view"
    );
    let open: Vec<String> = app
        .pages("packs")
        .items
        .iter()
        .filter(|p| p["state"] == "OPEN")
        .map(|p| p["id"].as_str().unwrap().to_owned())
        .collect();
    let expected = open.get(index.min(open.len().saturating_sub(1))).cloned();
    assert_eq!(
        after, expected,
        "deterministic fallback: the row now at the same position"
    );
    println!("scenario O: PASS (fallback {index} -> {after:?})");
    daemon("stop");
}
