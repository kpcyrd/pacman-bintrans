use clap::ArgAction;
use pacman_bintrans_common::http::Proxy;
use std::path::PathBuf;
use url::Url;

#[derive(Debug, clap::Parser)]
pub struct Args {
    /// Verbose output
    #[arg(short = 'v', global = true, action(ArgAction::Count))]
    pub verbose: u8,
    #[arg(short = 'O', long)]
    pub output: PathBuf,
    #[arg(long)]
    pub transparency_url: Option<Url>,
    #[arg(long)]
    pub pubkey: String,
    /// Example: socks5://127.0.0.1:9050
    #[arg(long)]
    pub proxy: Option<Proxy>,
    /// Only use the proxy for transparency signatures, not the pkg
    #[arg(long)]
    pub bypass_proxy_for_pkgs: bool,
    #[arg(long = "rebuilder")]
    pub rebuilders: Vec<Url>,
    #[arg(long, default_value = "0")]
    pub required_rebuild_confirms: usize,
    pub url: Url,
}
