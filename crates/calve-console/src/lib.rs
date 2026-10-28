//! Calve Console: the terminal control surface for understanding, reviewing and accepting
//! Project changes. It reads everything through the Calve API client (never the product
//! store or OpenAEVC directly) and renders read models the backend produces.
#![forbid(unsafe_code)]

pub mod graph;
pub mod highlight;
pub mod input;
pub mod model;
pub mod render;
pub mod screens;
pub mod text;
pub mod theme;

use std::cell::RefCell;
use std::io::{self, IsTerminal, Write};
use std::rc::Rc;
use std::time::Duration;

use calve_api::{Action, DaemonCommand, Outcome, Request, RequestScope};
use calve_client::{Backend, Client, Result};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use serde_json::Value;

use model::{App, Connection};
use theme::{Symbols, Theme, ThemeName};

/// Restores the terminal on every exit path, including panics (§72, §90).
struct TerminalGuard {
    mouse: bool,
}

impl TerminalGuard {
    fn enter(mouse: bool) -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        // Bracketed paste: pasted newlines never submit a command (§72).
        execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
        if mouse {
            execute!(stdout, EnableMouseCapture)?;
        }
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore(true);
            previous(info);
        }));
        Ok(Self { mouse })
    }
}

fn restore(mouse: bool) {
    let mut stdout = io::stdout();
    if mouse {
        let _ = execute!(stdout, DisableMouseCapture);
    }
    let _ = execute!(
        stdout,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
    let _ = disable_raw_mode();
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore(self.mouse);
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// OSC 52 clipboard write; terminals that forbid it ignore the sequence.
fn osc52(text: &str) {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let mut stdout = io::stdout();
    let _ = write!(stdout, "\u{1b}]52;c;{encoded}\u{7}");
    let _ = stdout.flush();
}

/// The system clipboard through the platform's copy tool; `false` when none took the text.
fn system_clipboard(text: &str) -> bool {
    let tools: &[&[&str]] = if cfg!(windows) {
        &[&["clip"]]
    } else if cfg!(target_os = "macos") {
        &[&["pbcopy"]]
    } else {
        &[
            &["wl-copy"],
            &["xclip", "-selection", "clipboard"],
            &["xsel", "--clipboard", "--input"],
            &["clip.exe"],
        ]
    };
    tools.iter().any(|tool| {
        let Ok(mut child) = std::process::Command::new(tool[0])
            .args(&tool[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return false;
        };
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
        // A copy tool that hangs must not freeze the console.
        for _ in 0..20 {
            if let Ok(Some(status)) = child.try_wait() {
                return wrote && status.success();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        false
    })
}

/// Never fails silently (§52): the system clipboard, else OSC 52 plus a dialog to copy from.
fn copy_out(app: &mut App, text: String) {
    let what = std::mem::take(&mut app.clipboard_label);
    if system_clipboard(&text) {
        app.notify(theme::Tone::Success, format!("Copied {what}"));
    } else {
        osc52(&text);
        app.notify(
            theme::Tone::Warning,
            "No system clipboard; sent to the terminal (OSC 52), which may ignore it",
        );
        app.overlays.push(model::Overlay::Result {
            title: format!("Copy {what} (select the text)"),
            value: Value::String(text),
        });
    }
}

type Reply = (String, std::result::Result<Value, String>, Option<Backend>);

async fn call(
    client: &Client,
    scope: &RequestScope,
    action: Action,
) -> (std::result::Result<Value, String>, Option<Backend>) {
    match client.send(Request::local(scope.clone(), action)).await {
        Ok((response, backend)) => (
            match response.outcome {
                Outcome::Ok { value } => Ok(value),
                Outcome::Error { error } => Err(format!("{}: {}", error.code, error.message)),
            },
            Some(backend),
        ),
        Err(error) => (Err(error.to_string()), None),
    }
}

fn preferences(config: &Value, no_color: bool) -> (Theme, Symbols, bool) {
    let colorless = no_color
        || std::env::var_os("NO_COLOR").is_some()
        || config["color"] == "never"
        || (config["color"] == "auto" && !io::stdout().is_terminal());
    let theme = if colorless {
        ThemeName::Mono
    } else {
        config["console"]["theme"]
            .as_str()
            .and_then(ThemeName::parse)
            .unwrap_or(ThemeName::Dark)
    };
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        .unwrap_or_default()
        .to_uppercase();
    let unicode = config["console"]["unicode"]
        .as_bool()
        .unwrap_or(locale.contains("UTF-8") || locale.contains("UTF8") || locale.is_empty());
    let mouse = config["console"]["mouse"].as_bool().unwrap_or(true);
    (Theme::new(theme), Symbols { unicode }, mouse)
}

/// Starts or connects to calved, then runs the console until the user quits.
pub async fn run(client: Client, scope: RequestScope, no_color: bool) -> Result<()> {
    let config = client
        .call(
            scope.clone(),
            Action::Config {
                command: calve_api::ConfigCommand::List,
            },
        )
        .await
        .unwrap_or(Value::Null);
    let (theme, symbols, mouse) = preferences(&config, no_color);
    // The shell renders at once and says it is connecting (§88); status arrives as a reply.
    let mut app = App::new(theme, symbols, Connection::Connecting, now());
    let console = &config["console"];
    if let Some(keys) = console["keys"].as_object() {
        app.set_keymap(keys);
    }
    app.time = match console["time"].as_str() {
        Some("absolute") => model::TimeStyle::Absolute,
        Some("both") => model::TimeStyle::Both,
        _ => model::TimeStyle::Relative,
    };
    app.show_footer = console["show_footer"].as_bool().unwrap_or(true);
    app.wrap_logs = console["wrap_logs"].as_bool().unwrap_or(false);
    app.diff_context = console["diff_context"].as_u64().map(|n| n as u32);
    app.workspace = scope.workspace.clone().unwrap_or_default();
    let client = Rc::new(client);
    let local = tokio::task::LocalSet::new();
    local.run_until(event_loop(app, client, scope, mouse)).await
}

fn connection(backend: Option<Backend>) -> Option<Connection> {
    backend.map(|b| match b {
        Backend::Daemon => Connection::Daemon,
        Backend::Embedded => Connection::Local,
    })
}

async fn event_loop(
    mut app: App,
    client: Rc<Client>,
    scope: RequestScope,
    mouse: bool,
) -> Result<()> {
    // Concurrent embedded requests must share one runtime per Project.
    calve_client::share_embedded_projects();
    let _guard = TerminalGuard::enter(mouse)?;
    let scope = Rc::new(RefCell::new(scope));
    // The console uses daemon mode; until the daemon has started (or failed to), requests wait.
    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel::<()>();
    let mut ready = client.options().direct || client.options().no_daemon_start;
    if !ready {
        let client = client.clone();
        tokio::task::spawn_local(async move {
            let _ = client.daemon(DaemonCommand::Start).await;
            let _ = ready_tx.send(());
        });
    }
    // Change feed: one long-poll at a time; a change triggers a refresh of the visible route.
    // Bounded queues (R16). Changes coalesce: one pending refresh is enough.
    let (change_tx, mut changes) = tokio::sync::mpsc::channel::<()>(1);
    {
        let client = client.clone();
        let scope = scope.clone();
        tokio::task::spawn_local(async move {
            let mut cursor: Option<(u64, i64)> = None;
            let mut watching = scope.borrow().project.clone();
            loop {
                let current = scope.borrow().clone();
                if current.project != watching {
                    // Another Project's cursor means nothing here.
                    watching = current.project.clone();
                    cursor = None;
                }
                let (protocol, product) = cursor.unwrap_or((0, 0));
                let action = Action::View {
                    view: calve_api::ViewQuery::Changes {
                        protocol,
                        product,
                        wait_ms: 25_000,
                    },
                };
                match call(&client, &current, action).await.0 {
                    Ok(value) => {
                        let next = (
                            value["protocol"].as_u64().unwrap_or(protocol),
                            value["product"].as_i64().unwrap_or(product),
                        );
                        if cursor.is_some()
                            && value["changed"] == true
                            && let Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) =
                                change_tx.try_send(())
                        {
                            break;
                        }
                        cursor = Some(next);
                    }
                    Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
                }
            }
        });
    }
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let (keys_tx, mut keys) = tokio::sync::mpsc::channel::<Event>(256);
    std::thread::spawn(move || {
        while let Ok(event) = event::read() {
            if keys_tx.blocking_send(event).is_err() {
                break;
            }
        }
    });
    let (reply_tx, mut replies) = tokio::sync::mpsc::channel::<(u64, Reply)>(64);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let size = terminal.size()?;
    app.size = (size.width, size.height);
    input::sync(&mut app);
    loop {
        if let Some(root) = app.open_project.take() {
            scope.borrow_mut().project = Some(root.into());
        }
        if ready {
            for request in app.take_requests() {
                let client = client.clone();
                let scope = scope.borrow().clone();
                let reply = reply_tx.clone();
                let epoch = app.epoch;
                tokio::task::spawn_local(async move {
                    let (result, backend) = call(&client, &scope, request.action).await;
                    let _ = reply.send((epoch, (request.key, result, backend))).await;
                });
            }
        }
        if let Some(text) = app.clipboard.take() {
            copy_out(&mut app, text);
        }
        app.hits.borrow_mut().clear();
        terminal.draw(|frame| render::draw(frame, &app))?;
        if app.quit {
            break;
        }
        tokio::select! {
            Ok(()) = &mut ready_rx, if !ready => ready = true,
            Some(event) = keys.recv() => match event {
                Event::Key(key) if key.kind == event::KeyEventKind::Press => input::handle_key(&mut app, key),
                Event::Mouse(mouse) => input::handle_mouse(&mut app, mouse),
                Event::Paste(text) => input::handle_paste(&mut app, &text),
                Event::Resize(width, height) => {
                    app.size = (width, height);
                    input::sync(&mut app);
                }
                _ => {}
            },
            Some(()) = changes.recv() => app.refresh(),
            Some((epoch, (key, result, backend))) = replies.recv() => {
                // A reply for the Project the console left behind is not this Project's data.
                if epoch == app.epoch {
                    app.connection = app.connection.after(connection(backend));
                    input::on_response(&mut app, &key, result);
                } else if key.starts_with("cmd:") {
                    input::on_response(&mut app, &key, result);
                }
            }
            _ = tick.tick() => {
                app.now = now();
                app.advance(1);
                // The change feed drives refreshes; this slow fallback catches working-tree edits.
                if app.tick.is_multiple_of(240) && app.overlays.is_empty() {
                    app.refresh();
                }
            }
        }
    }
    Ok(())
}
