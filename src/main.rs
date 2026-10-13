use clap::Parser;

mod cli;

fn main() -> anyhow::Result<()> {
    cli::Cli::parse().run()
}
