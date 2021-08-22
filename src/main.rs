use env_logger::Env;
use minisign::PublicKey;
use pacman_bintrans::args::Args;
use pacman_bintrans::proof;
use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http;
use std::fs;
use std::path::Path;
use structopt::StructOpt;
use url::Url;

const DB_SIZE_LIMIT: usize = 1024 * 1024 * 128; // 128M

fn needs_transparency_proof(url: &str) -> bool {
    let parts = url.split(".").collect::<Vec<_>>();

    let mut iter = parts.iter().rev();

    // strip .tar.zstd
    if let Some(x) = iter.next() {
        // if the extension is .tar there is possibly no compression
        if *x != "tar" {
            if iter.next() != Some(&"tar") {
                return false;
            }
        }
    }

    iter.next() == Some(&"pkg")
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

    let pubkey = PublicKey::from_file(args.pubkey_file)
        .context("Failed to load transparency public key")?
        .to_box()?;

    if needs_transparency_proof(&args.url) {
        info!(
            "Transparency proof is required for {:?}, downloading into memory",
            args.url
        );
        let pkg = http::download_to_mem(&args.url, Some(DB_SIZE_LIMIT)).await?;
        debug!("Downloaded {} bytes", pkg.len());

        let url = if let Some(url) = args.transparency_url {
            let p = Path::new(&args.url);
            let file_name = p.file_name()
                .ok_or_else(|| anyhow!("Missing filename for url"))?
                .to_str()
                .ok_or_else(|| anyhow!("Invalid filename"))?;
            let url = url.parse::<Url>()?;
            let url = url.join(file_name)?;
            url.as_str().to_string()
        } else {
            args.url
        };

        // security critical code happens here
        proof::fetch_and_verify(&pubkey, &url, &pkg).await?;

        info!("Writing pkg to {:?}", args.output);
        fs::write(args.output, &pkg).context("Failed to write database file after verification")?;
        debug!("Wrote {} bytes", pkg.len());
    } else {
        info!("Downloading {:?} to {:?}", args.url, args.output);
        let n = http::download_to_file(&args.url, &args.output).await?;
        debug!("Downloaded {} bytes", n);
    }

    Ok(())
}
