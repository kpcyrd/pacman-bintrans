use minisign::{PublicKeyBox, SignatureBox};
use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http::Client;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::process::Stdio;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use url::Url;

const PROOF_SIZE_LIMIT: usize = 1024; // 1K

async fn rekor_verify(pubkey: &PublicKeyBox, artifact: &[u8], signature: &[u8]) -> Result<()> {
    let pubkey_file = NamedTempFile::new()?;
    let sig_file = NamedTempFile::new()?;

    fs::write(pubkey_file.path(), pubkey.to_string())?;
    fs::write(sig_file.path(), signature)?;

    let mut child = Command::new("rekor-cli")
        .arg("verify")
        .arg("--pki-format=minisign")
        .arg("--public-key")
        .arg(pubkey_file.path())
        .arg("--artifact")
        .arg("/dev/stdin")
        .arg("--signature")
        .arg(sig_file.path())
        .arg("--format")
        .arg("json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn")?;

    let mut stdin = child
        .stdin
        .take()
        .context("child did not have a handle to stdin")?;

    stdin.write_all(artifact).await?;
    stdin.flush().await?;
    drop(stdin);

    let exit = child.wait_with_output().await?;
    if exit.status.success() {
        Ok(())
    } else {
        bail!("Sigstore verify failed");
    }
}

pub async fn verify(pubkey: &PublicKeyBox, artifact: &[u8], sig: &[u8]) -> Result<()> {
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
    rekor_verify(pubkey, sha256.as_bytes(), sig).await?;

    info!("Success: package verified");
    Ok(())
}

pub async fn fetch_and_verify(
    client: &Client,
    pubkey: &PublicKeyBox,
    url: &Url,
    pkg: &[u8],
) -> Result<()> {
    let url = format!("{}.t", url.as_str());
    info!("Trying to download transparency proof from {:?}", url);
    let url = url.parse::<Url>()?;

    let proof = client
        .download_to_mem(url.as_str(), Some(PROOF_SIZE_LIMIT))
        .await?;
    debug!("Downloaded {} bytes", proof.len());

    verify(pubkey, pkg, &proof).await
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_foo() {}
}
