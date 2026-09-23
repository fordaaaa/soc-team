//! `socteam` control CLI — Phase 0 skeleton.

use clap::{Parser, Subcommand};

/// socteam control CLI.
#[derive(Debug, Parser)]
#[command(name = "socteam", version, about = "socteam control CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Print the workspace version.
    Version,
    /// Print sensor status (placeholder until Phase 1).
    Status,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => println!("socteam {}", env!("CARGO_PKG_VERSION")),
        Command::Status => println!("sensor status: not implemented (phase 1)"),
    }
}
