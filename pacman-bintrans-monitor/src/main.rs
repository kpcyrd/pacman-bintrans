use clap::Parser;
use env_logger::Env;
use pacman_bintrans_common::errors::*;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Debug, Parser)]
struct Args {
    /// Verbose logging
    #[arg(short)]
    verbose: bool,
    /// Minisign public key used to sign packages
    #[arg(long)]
    pubkey: String,
}

async fn fetch_signatures(pubkey: &str) -> Result<Vec<String>> {
    info!("Searching for {:?}", pubkey);
    let mut child = Command::new("rekor-cli")
        .args([
            "search",
            "--pki-format=minisign",
            "--public-key",
            "/dev/stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn")?;

    let mut stdin = child
        .stdin
        .take()
        .context("child did not have a handle to stdin")?;

    stdin.write_all(pubkey.as_bytes()).await?;
    drop(stdin);

    let stdout = child
        .stdout
        .take()
        .context("child did not have a handle to stdout")?;

    let mut reader = BufReader::new(stdout).lines();

    // Ensure the child process is spawned in the runtime so it can
    // make progress on its own while we await for any output.
    tokio::spawn(async move {
        // TODO: proper error handling, logging
        let status = child
            .wait()
            .await
            .expect("child process encountered an error");

        if !status.success() {
            error!("child status was: {}", status);
        }
    });

    // skip first line: https://github.com/sigstore/rekor/issues/420
    reader.next_line().await?;

    let mut uuids = Vec::new();
    while let Some(line) = reader.next_line().await? {
        uuids.push(line);
    }

    Ok(uuids)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let logging = if args.verbose { "debug" } else { "info" };

    env_logger::init_from_env(Env::default().default_filter_or(logging));

    let sigs = fetch_signatures(&args.pubkey).await?;

    eprintln!("Found {} signatures", sigs.len());
    for sig in sigs {
        println!("{}", sig);
    }

    Ok(())
}
