use env_logger::Env;
use pacman_bintrans::args::Args;
use pacman_bintrans::errors::*;
use pacman_bintrans::http;
use pacman_bintrans::proof;
use std::fs;
use structopt::StructOpt;

const DB_SIZE_LIMIT: usize = 1024 * 1024 * 128; // 128M

fn needs_transparency_proof(url: &str) -> bool {
    url.ends_with(".db")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::from_args();

    let log = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "info,pacman_bintrans=debug",
        _ => "debug",
    };

    env_logger::init_from_env(Env::default().default_filter_or(log));

    if needs_transparency_proof(&args.url) {
        info!(
            "Transparency proof is required for {:?}, downloading into memory",
            args.url
        );
        let db = http::download_to_mem(&args.url, DB_SIZE_LIMIT).await?;
        debug!("Downloaded {} bytes", db.len());

        // security critical code happens here
        proof::fetch_and_verify(&args.url, &db).await?;

        info!("Writing database to {:?}", args.output);
        fs::write(args.output, &db).context("Failed to write database file after verification")?;
        debug!("Wrote {} bytes", db.len());
    } else {
        info!("Downloading {:?} to {:?}", args.url, args.output);
        let n = http::download_to_file(&args.url, &args.output).await?;
        debug!("Downloaded {} bytes", n);
    }

    Ok(())
}
