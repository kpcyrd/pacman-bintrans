use std::path::PathBuf;
use structopt::clap::AppSettings;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp])]
pub struct Args {
    /// Verbose output
    #[structopt(short = "v", global = true, parse(from_occurrences))]
    pub verbose: u8,
    #[structopt(short = "O", long)]
    pub output: PathBuf,
    pub url: String,
}
