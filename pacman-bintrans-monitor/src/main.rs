use pacman_bintrans_common::errors::*;
use std::fs;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::io::{BufReader, AsyncBufReadExt};
use tokio::process::Command;

async fn fetch_signatures(pubkey: &str) -> Result<Vec<String>> {
    info!("Searching for {:?}", pubkey);
    let mut child = Command::new("rekor-cli")
        .args(&["search", "--pki-format=minisign", "--public-key", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn")?;

    let mut stdin = child.stdin.take()
        .context("child did not have a handle to stdin")?;

    stdin.write_all(pubkey.as_bytes())
        .await?;
    drop(stdin);

    let stdout = child.stdout.take()
        .context("child did not have a handle to stdout")?;

    let mut reader = BufReader::new(stdout).lines();

    // Ensure the child process is spawned in the runtime so it can
    // make progress on its own while we await for any output.
    tokio::spawn(async move {
        // TODO: proper error handling, logging
        let status = child.wait().await
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
    env_logger::init();

    let pubkey = fs::read_to_string("../pacman-bintrans-sign/minisign.pub")?;
    let sigs = fetch_signatures(&pubkey).await?;

    eprintln!("Found {} signatures", sigs.len());
    for sig in sigs {
        println!("{}", sig);
    }

    Ok(())
}
