use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http::Proxy;
use std::path::PathBuf;
use structopt::StructOpt;
use structopt::clap::AppSettings;

#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp])]
pub struct Args {
    /// Verbose output
    #[structopt(short = "v", global = true, parse(from_occurrences))]
    pub verbose: u8,
    #[structopt(short = "O", long)]
    pub output: PathBuf,
    #[structopt(long)]
    pub transparency_url: Option<String>,
    #[structopt(long)]
    pub pubkey: String,
    /// Example: socks5://127.0.0.1:9050
    #[structopt(long, parse(try_from_str = parse_proxy))]
    pub proxy: Option<Proxy>,
    pub url: String,
}

fn parse_proxy(proxy: &str) -> Result<Proxy> {
    Proxy::all(proxy)
        .map_err(Error::from)
}
