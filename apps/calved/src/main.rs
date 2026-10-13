#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "calved", version, about = "Calve local service")]
struct Cli {
    #[arg(long)]
    endpoint: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
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
