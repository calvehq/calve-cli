#![forbid(unsafe_code)]

mod render;

use std::io::IsTerminal as _;
use std::path::PathBuf;

use calve_api::errors::{exit, exit_code};
use calve_api::{
    Action, CatalogCommand, ExtensionCommand, Fault, Outcome, ProjectCommand, Request, RequestScope,
};
use calve_client::{Backend, Client, Options};
use clap::{CommandFactory as _, FromArgMatches as _, Parser};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "calve",
    version,
    about = "See the whole change. Decide what becomes real."
)]
struct Cli {
    /// Project path or registered Project ID (default: the enclosing Project directory).
    #[arg(long = "project", global = true)]
    project_path: Option<PathBuf>,
    /// Workspace name or ID (default: the selected Workspace).
    #[arg(long, global = true)]
    workspace: Option<String>,
    /// Extra configuration file applied after the scope files.
    #[arg(long = "config", global = true)]
    config_file: Option<PathBuf>,
    /// JSON output in the versioned envelope, for commands that declare a JSON schema
    /// (docs/reference/json/v1); other commands refuse it.
    #[arg(long, global = true)]
    json: bool,
    /// Run in this process even when calved is available.
    #[arg(long, global = true)]
    direct: bool,
    /// Daemon socket to use; failing to reach it is an error.
    #[arg(long, global = true)]
    endpoint: Option<PathBuf>,
    /// Suppress success output; errors still go to stderr.
    #[arg(long, global = true, conflicts_with = "verbose")]
    quiet: bool,
    /// Report the backend and request ID on stderr.
    #[arg(long, global = true)]
    verbose: bool,
    /// Disable color in the console. Plain CLI output is never colored.
    #[arg(long, global = true)]
    no_color: bool,
    /// Never start calved implicitly.
    #[arg(long, global = true)]
    no_daemon_start: bool,
    /// Act as a local identity (see `calve authority identities`).
    #[arg(long = "as", global = true)]
    actor: Option<String>,
    #[command(subcommand)]
    command: Action,
}

/// `pack list`, `extension catalog add`, …: the subcommand path the user typed.
fn command_key(matches: &clap::ArgMatches) -> String {
    let mut parts = vec![];
    let mut m = matches;
    while let Some((name, sub)) = m.subcommand() {
        parts.push(name.to_owned());
        m = sub;
    }
    parts.join(" ")
}

/// Test hook: `CALVE_JSON_RECORD=<dir>` writes every JSON result to its own file
/// `<dir>/<command>@<pid>-<n>.json` (parallel runs never interleave), the input of
/// `xtask json-schemas`.
fn record(key: &str, data: &Value) {
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(dir) = std::env::var_os("CALVE_JSON_RECORD") else {
        return;
    };
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = PathBuf::from(dir).join(format!(
        "{}@{}-{n}.json",
        key.replace(' ', "."),
        std::process::id()
    ));
    let _ = std::fs::write(path, data.to_string());
}

struct Run {
    key: String,
    json: bool,
    quiet: bool,
}

impl Run {
    fn success(&self, data: Value) {
        if self.json {
            record(&self.key, &data);
            let envelope = json!({"api_version": calve_api::API_VERSION.to_string(), "command": self.key, "data": data});
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope).unwrap_or_default()
            );
        } else if !self.quiet {
            print!("{}", render::human(&self.key, &data));
        }
    }

    /// Prints the error to stderr and returns the exit status for its code.
    fn failure(&self, fault: Fault) -> i32 {
        let status = exit_code(&fault.code);
        if self.json {
            let envelope = json!({"api_version": calve_api::API_VERSION.to_string(), "command": self.key,
                "error": {"code": fault.code, "message": fault.message, "retryable": fault.retryable,
                    "detail": fault.detail, "exit_code": status}});
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&envelope).unwrap_or_default()
            );
        } else {
            eprint!("{}", render::error(&fault));
        }
        status
    }
}

async fn run(cli: Cli, out: &Run) -> i32 {
    let client = Client::new(Options {
        direct: cli.direct,
        endpoint: cli.endpoint.clone(),
        no_daemon_start: cli.no_daemon_start,
    });
    let fail = |e: calve_client::Error| out.failure(calve_app::app::fault(e));
    // The daemon has its own working directory, so every path is made absolute here.
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => return fail(e.into()),
    };
    let absolute = |path: PathBuf| {
        if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        }
    };
    let scope = RequestScope {
        project: match cli.project_path {
            Some(path) if path.exists() => Some(absolute(path)),
            Some(id) => Some(id),
            None => calve_app::Project::discover(&cwd).ok(),
        },
        workspace: cli.workspace,
        config_file: cli.config_file.map(absolute),
        actor: cli.actor,
    };
    let mut command = cli.command;
    match &mut command {
        Action::Console => {
            return match calve_console::run(client, scope, cli.no_color).await {
                Ok(()) => exit::OK,
                Err(e) => fail(e),
            };
        }
        Action::Daemon { command } => {
            return match client.daemon(command.clone()).await {
                Ok(value) => {
                    out.success(value);
                    exit::OK
                }
                Err(e) => fail(e),
            };
        }
        Action::Init { path, .. } => {
            *path = Some(absolute(path.take().unwrap_or_else(|| cwd.clone())));
        }
        Action::Doctor {
            bundle: Some(path), ..
        }
        | Action::Project {
            command:
                ProjectCommand::Register { path }
                | ProjectCommand::Relocate { path, .. }
                | ProjectCommand::AdoptCopy { path, .. },
        }
        | Action::Extension {
            command:
                ExtensionCommand::Catalog {
                    command:
                        CatalogCommand::Add { root: path, .. }
                        | CatalogCommand::Reset { root: path, .. },
                },
        } => *path = absolute(std::mem::take(path)),
        _ => {}
    }
    if let Action::Extension {
        command:
            ExtensionCommand::Catalog {
                command: CatalogCommand::Add { url, .. },
            },
    } = &mut command
        && !url.contains("://")
    {
        *url = absolute(PathBuf::from(url.as_str())).display().to_string();
    }
    let mut request = Request::local(scope, command);
    // Callers correlate several requests (scripts, retries) with CALVE_CORRELATION_ID.
    request.correlation_id = std::env::var("CALVE_CORRELATION_ID")
        .ok()
        .and_then(|v| v.parse().ok());
    loop {
        let request_id = request.request_id;
        let (response, backend) = match client.send(request.clone()).await {
            Ok(r) => r,
            Err(e) => return fail(e),
        };
        if cli.verbose {
            let backend = match backend {
                Backend::Daemon => "daemon",
                Backend::Embedded => "embedded",
            };
            eprintln!("calve: backend={backend} request={request_id}");
        }
        match response.outcome {
            Outcome::Ok { value } => {
                out.success(value);
                return exit::OK;
            }
            // A destructive command asked for confirmation: ask on a terminal, then resend the
            // same request acknowledged (non-interactive callers pass --yes).
            Outcome::Error { error }
                if error.code == "CONFIRMATION_REQUIRED"
                    && !out.json
                    && std::io::stdin().is_terminal()
                    && std::io::stderr().is_terminal() =>
            {
                eprintln!("{}", render::sanitize(&error.message, false));
                eprint!("Proceed? [y/N] ");
                let mut answer = String::new();
                let _ = std::io::stdin().read_line(&mut answer);
                if !matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
                    return out.failure(Fault {
                        code: "USER_CANCELLED".into(),
                        message: "cancelled; nothing was changed".into(),
                        retryable: false,
                        detail: None,
                    });
                }
                request.action.acknowledge();
                // The confirmed resend is a new request correlated with the first.
                request.correlation_id.get_or_insert(request.request_id);
                request.request_id = calve_api::new_request_id();
            }
            Outcome::Error { error } => return out.failure(error),
        }
    }
}

fn main() {
    // Hidden helper modes run before any runtime thread exists (Landlock is per thread).
    if let Some(code) = calve_app::sandbox::hidden_mode() {
        std::process::exit(code);
    }
    std::process::exit(real_main());
}

#[tokio::main]
async fn real_main() -> i32 {
    // Usage errors exit 2 (clap); --help/--version exit 0.
    let matches = Cli::command().get_matches();
    let key = command_key(&matches);
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    let out = Run {
        key,
        json: cli.json,
        quiet: cli.quiet,
    };
    if cli.json
        && !calve_api::json::declares(&out.key)
        && !(cfg!(debug_assertions) && std::env::var_os("CALVE_JSON_RECORD").is_some())
    {
        eprintln!(
            "error: --json is not supported by `calve {}` (it declares no JSON schema)",
            out.key
        );
        return exit::USAGE;
    }
    run(cli, &out).await
}
