use crate::errors::*;
use futures_util::StreamExt;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

pub struct Client {
    client: reqwest::Client,
}

impl Client {
    pub fn new() -> Client {
        Client {
            client: reqwest::Client::new(),
        }
    }

    pub async fn http_request(&self, url: &str) -> Result<reqwest::Response> {
        let resp = self.client.get(url)
            .send()
            .await
            .context("Failed to send request")?
            .error_for_status()
            .context("Server returned http error")?;
        Ok(resp)
    }

    pub async fn download_to_mem(&self, url: &str, limit: Option<usize>) -> Result<Vec<u8>> {
        let mut stream = self.http_request(url).await?.bytes_stream();

        let mut out = Vec::new();

        while let Some(item) = stream.next().await {
            let bytes = item.context("Failed to read from stream")?;
            if let Some(limit) = &limit {
                if bytes.len() + out.len() > *limit {
                    bail!("Exceeded size limit for .db");
                }
            }
            out.extend(&bytes);
        }

        Ok(out)
    }

    pub async fn download_to_file(&self, url: &str, output: &Path) -> Result<usize> {
        let mut stream = self.http_request(url).await?.bytes_stream();

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
}

pub async fn http_request(url: &str) -> Result<reqwest::Response> {
    Client::new().http_request(url).await
}

pub async fn download_to_mem(url: &str, limit: Option<usize>) -> Result<Vec<u8>> {
    Client::new().download_to_mem(url, limit).await
}

pub async fn download_to_file(url: &str, output: &Path) -> Result<usize> {
    Client::new().download_to_file(url, output).await
}
