#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "calved", version, about = "Calve local service")]
struct Cli {
    #[arg(long)]
    endpoint: Option<PathBuf>,
}

fn main() {
    // Hidden helper modes run before any runtime thread exists (Landlock is per thread).
    if let Some(code) = calve_app::sandbox::hidden_mode() {
        std::process::exit(code);
    }
    calve_app::with_main_stack(real_main);
}

#[tokio::main]
async fn real_main() {
    let cli = Cli::parse();
    let result = async {
        let endpoint = match cli.endpoint {
            Some(path) => path,
            None => calve_client::default_endpoint()?,
        };
        calve_client::serve(&endpoint).await
    }
    .await;
    if let Err(error) = result {
        eprintln!("calved: {error}");
        std::process::exit(1);
    }
}
