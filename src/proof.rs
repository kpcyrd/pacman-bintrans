use minisign::{PublicKeyBox, SignatureBox};
use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http::{Client, Proxy};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::process::Stdio;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use url::Url;

const REKOR_BIN: &str = "rekor-cli";
const PROOF_SIZE_LIMIT: usize = 1024; // 1K

async fn rekor_verify(
    pubkey: &PublicKeyBox,
    artifact: &[u8],
    signature: &[u8],
    proxy: &Option<Proxy>,
) -> Result<()> {
    rekor_exec(pubkey, artifact, signature, proxy, "upload", &[
        "--format",
        "json",
    ]).await
}

async fn rekor_upload(
    pubkey: &PublicKeyBox,
    artifact: &[u8],
    signature: &[u8],
    proxy: &Option<Proxy>,
) -> Result<()> {
    rekor_exec(pubkey, artifact, signature, proxy, "upload", &[]).await
}

async fn rekor_exec(
    pubkey: &PublicKeyBox,
    artifact: &[u8],
    signature: &[u8],
    proxy: &Option<Proxy>,
    action: &str,
    extra_args: &[&str],
) -> Result<()> {
    let pubkey_file = NamedTempFile::new()?;
    let sig_file = NamedTempFile::new()?;

    let pubkey = pubkey.to_string();
    debug!(
        "Writing to pubkey temp file {:?}: {:?}",
        pubkey_file.path(),
        pubkey
    );
    fs::write(pubkey_file.path(), pubkey)?;
    debug!(
        "Writing to signature temp file {:?}: {:?}",
        sig_file.path(),
        signature
    );
    fs::write(sig_file.path(), signature)?;

    let mut cmd = Command::new(REKOR_BIN);
    cmd.arg(action)
        .arg("--pki-format=minisign")
        .arg("--public-key")
        .arg(pubkey_file.path())
        .arg("--artifact")
        .arg("/dev/stdin")
        .arg("--signature")
        .arg(sig_file.path());

    for arg in extra_args {
        cmd.arg(arg);
    }

    cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    if let Some(proxy) = proxy {
        let proxy = proxy.as_text();
        debug!("Setting proxy for rekor-cli child process: {:?}", proxy);
        cmd.env("http_proxy", &proxy);
        cmd.env("https_proxy", &proxy);
    }

    debug!(
        "Executing {:?} {:?}",
        REKOR_BIN,
        cmd.as_std().get_args().collect::<Vec<_>>()
    );
    let mut child = cmd.spawn().context("failed to spawn")?;

    let mut stdin = child
        .stdin
        .take()
        .context("child did not have a handle to stdin")?;

    debug!("Sending to child stdin: {:?}", artifact);
    stdin.write_all(artifact).await?;
    stdin.flush().await?;
    drop(stdin);

    let exit = child.wait_with_output().await?;

    debug!(
        "Child wrote to stdout: {:?}",
        String::from_utf8_lossy(&exit.stdout)
    );
    debug!("Child exited with {:?}", exit.status);

    if exit.status.success() {
        Ok(())
    } else {
        bail!("Sigstore verify failed");
    }
}

pub async fn verify(
    pubkey: &PublicKeyBox,
    artifact: &[u8],
    sig: &[u8],
    proxy: &Option<Proxy>,
) -> Result<()> {
    info!("Calculating sha256sum for {} bytes", artifact.len());
    let mut hasher = Sha256::new();
    hasher.update(artifact);
    let sha256 = hex::encode(&hasher.finalize());

    info!("Verifying transparency signature");
    let data_reader = Cursor::new(&sha256);
    let sig_box = SignatureBox::from_string(&String::from_utf8_lossy(sig))?;
    let pk = pubkey.clone().into_public_key()?;
    minisign::verify(&pk, &sig_box, data_reader, true, false, true)?;

    info!("Verifying signature is in transparency log");
    if let Err(err) = rekor_verify(pubkey, sha256.as_bytes(), sig, proxy).await {
        warn!("Verification failed, uploading signature to log next: {:#}", err);
        rekor_upload(pubkey, sha256.as_bytes(), sig, proxy).await
            .context("Failed to upload signature")?;
        rekor_verify(pubkey, sha256.as_bytes(), sig, proxy).await
            .context("Repeated lookup in transparency log failed")?;
    }

    info!("Success: package verified");
    Ok(())
}

pub async fn fetch_and_verify(
    client: &Client,
    pubkey: &PublicKeyBox,
    url: &Url,
    pkg: &[u8],
    proxy: &Option<Proxy>,
) -> Result<()> {
    let url = format!("{}.t", url.as_str());
    info!("Trying to download transparency proof from {:?}", url);
    let url = url.parse::<Url>()?;

    let proof = client
        .download_to_mem(url.as_str(), Some(PROOF_SIZE_LIMIT))
        .await?;
    debug!("Downloaded {} bytes", proof.len());

    verify(pubkey, pkg, &proof, proxy).await
}
