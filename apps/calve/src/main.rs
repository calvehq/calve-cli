#![forbid(unsafe_code)]

use std::path::PathBuf;

use calve_api::{Action, Outcome, Request, RequestScope};
use calve_client::{Backend, Client, Error, Options, Result};
use clap::Parser;
use serde_json::Value;

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
    /// Structured JSON output.
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

fn print_value(value: Value, machine: bool) {
    if machine {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    } else {
        match value {
            Value::String(text) => println!("{text}"),
            Value::Array(values) => {
                if values.is_empty() {
                    println!("No items.");
                }
                for value in values {
                    print_one(&value);
                }
            }
            value => print_one(&value),
        }
    }
}

fn print_one(value: &Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let rendered = match value {
                    Value::String(s) => s.clone(),
                    _ => value.to_string(),
                };
                println!("{key}: {rendered}");
            }
            println!();
        }
        _ => println!("{value}"),
    }
}

async fn run(cli: Cli) -> Result<()> {
    let client = Client::new(Options {
        direct: cli.direct,
        endpoint: cli.endpoint.clone(),
        no_daemon_start: cli.no_daemon_start,
    });
    // The daemon has its own working directory, so every path is made absolute here.
    let cwd = std::env::current_dir()?;
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
        Action::Console => return calve_console::run(client, scope, cli.no_color).await,
        Action::Daemon { command } => {
            let value = client.daemon(command.clone()).await?;
            if !cli.quiet {
                print_value(value, cli.json);
            }
            return Ok(());
        }
        Action::Init { path, .. } => {
            *path = Some(absolute(path.take().unwrap_or_else(|| cwd.clone())));
        }
        _ => {}
    }
    let request = Request::local(scope, command);
    let request_id = request.request_id;
    let (response, backend) = client.send(request).await?;
    if cli.verbose {
        let backend = match backend {
            Backend::Daemon => "daemon",
            Backend::Embedded => "embedded",
        };
        eprintln!("calve: backend={backend} request={request_id}");
    }
    match response.outcome {
        Outcome::Ok { value } => {
            if !cli.quiet {
                print_value(value, cli.json);
            }
            Ok(())
        }
        Outcome::Error { error } => {
            Err(Error::Message(format!("{}: {}", error.code, error.message)))
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("calve: {error}");
        std::process::exit(1);
    }
}
