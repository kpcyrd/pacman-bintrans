use crate::errors::*;
use futures_util::StreamExt;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

async fn http_request(url: &str) -> Result<reqwest::Response> {
    let resp = reqwest::get(url)
        .await
        .context("Failed to send request")?
        .error_for_status()
        .context("Server returned http error")?;
    Ok(resp)
}

pub async fn download_to_mem(url: &str, limit: usize) -> Result<Vec<u8>> {
    let mut stream = http_request(url).await?.bytes_stream();

    let mut out = Vec::new();

    while let Some(item) = stream.next().await {
        let bytes = item.context("Failed to read from stream")?;
        if bytes.len() + out.len() > limit {
            bail!("Exceeded size limit for .db");
        }
        out.extend(&bytes);
    }

    Ok(out)
}

pub async fn download_to_file(url: &str, output: &Path) -> Result<usize> {
    let mut stream = http_request(url).await?.bytes_stream();

    let mut out = File::create(output).context("Failed to create output file")?;

    let mut n = 0;
    while let Some(item) = stream.next().await {
        let bytes = item.context("Failed to read from stream")?;
        out.write_all(&bytes)
            .context("Failed to write to output file")?;
        n += bytes.len();
    }

    // TODO: we should add a .part extension and remove it here

    Ok(n)
}
