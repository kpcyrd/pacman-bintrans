use crate::http::Client;
use clap::Parser;
use env_logger::Env;
use minisign::PublicKey;
use pacman_bintrans::args::Args;
use pacman_bintrans::proof;
use pacman_bintrans::reproducible;
use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http;
use std::env;
use std::fs;
use std::rc::Rc;
use url::Url;

fn needs_transparency_proof(url: &str) -> bool {
    let parts = url.split('.').collect::<Vec<_>>();

    let mut iter = parts.iter().rev();

    // strip .tar.zstd
    if let Some(x) = iter.next() {
        // if the extension is .tar there is possibly no compression
        if *x != "tar" && iter.next() != Some(&"tar") {
            return false;
        }
    }

    iter.next() == Some(&"pkg")
}

fn filename_from_url(url: &Url) -> Option<String> {
    let segments = url.path_segments()?;
    let filename = segments.last()?;
    Some(filename.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log = match (args.verbose, env::var("RUST_LOG")) {
        (0, Err(_)) => None,
        (_, Ok(_)) => Some("warn"),
        (1, _) => Some("info"),
        (2, _) => Some("info,pacman_bintrans=debug"),
        _ => Some("debug"),
    };

    if let Some(log) = log {
        env_logger::init_from_env(Env::default().default_filter_or(log));
    }

    let pubkey = PublicKey::from_base64(&args.pubkey)
        .context("Failed to load transparency public key")?
        .to_box()?;

    if args.url.scheme() == "file" {
        let path = args
            .url
            .to_file_path()
            .map_err(|_| anyhow!("Failed to convert file:// url to path"))?;
        info!("Copying from file {:?} to {:?}", path, args.output);
        let n = fs::copy(path, &args.output).context("Failed to copy from file://")?;
        debug!("Copied {} bytes", n);
        return Ok(());
    }

    let client = Rc::new(Client::new(args.proxy.clone())?);
    let pkg_client = if args.bypass_proxy_for_pkgs {
        Rc::new(Client::new(None)?)
    } else {
        client.clone()
    };

    if needs_transparency_proof(args.url.as_str()) {
        info!(
            "Transparency proof is required for {:?}, downloading into memory",
            args.url.as_str()
        );
        let pkg = if args.output.exists() {
            info!("Target path already exists, reading from disk instead of downloading");
            fs::read(&args.output).context("Failed to read existing file")?
        } else {
            let pkg = pkg_client.download_to_mem(args.url.as_str(), None).await?;
            debug!("Downloaded {} bytes", pkg.len());
            pkg
        };

        if log.is_none() {
            println!(
                "\x1b[1m[\x1b[32m+\x1b[0;1m]\x1b[0m Downloaded {:?}",
                args.url.as_str()
            );
        }

        let url = if let Some(transparency_url) = &args.transparency_url {
            let file_name = filename_from_url(&args.url).ok_or_else(|| {
                anyhow!("Couldn't detect filename for url: {:?}", args.url.as_str())
            })?;
            let mut url = transparency_url.clone();
            url.path_segments_mut()
                .map_err(|_| anyhow!("Failed to get path segments for url"))?
                .pop_if_empty()
                .push(&file_name);
            url
        } else {
            args.url
        };

        if log.is_none() {
            println!("\x1b[2K\r\x1b[1m[\x1b[34m%\x1b[0;1m]\x1b[0m Checking transparency log...");
        }

        // security critical code happens here
        proof::fetch_and_verify(&client, &pubkey, &url, &pkg, &args.proxy)
            .await
            .context("Failed to check transparency log")?;

        if log.is_none() {
            println!("\x1b[1A\x1b[2K\r\x1b[1m[\x1b[32m+\x1b[0;1m]\x1b[0m Package is present in transparency log");
        }

        if !args.rebuilders.is_empty() || args.required_rebuild_confirms > 0 {
            let rebuild_confirms =
                reproducible::check_rebuilds(&client, &pkg, &args.rebuilders, &log)
                    .await
                    .context("Failed to check rebuilds")?;

            if rebuild_confirms < args.required_rebuild_confirms {
                bail!(
                    "Not enough rebuild confirms: got {}, expected {}",
                    rebuild_confirms,
                    args.required_rebuild_confirms
                );
            }
        }

        info!("Writing pkg to {:?}", args.output);
        fs::write(args.output, &pkg).context("Failed to write database file after verification")?;
        debug!("Wrote {} bytes", pkg.len());
    } else {
        info!("Downloading {:?} to {:?}", args.url.as_str(), args.output);
        let n = client
            .download_to_file(args.url.as_str(), &args.output)
            .await?;
        debug!("Downloaded {} bytes", n);

        if log.is_none() {
            println!(
                "\x1b[1m[\x1b[32m+\x1b[0;1m]\x1b[0m Downloaded {:?}",
                args.url.as_str()
            );
        }
    }

    Ok(())
}
