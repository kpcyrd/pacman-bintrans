use crate::errors::*;
use futures_util::StreamExt;
pub use reqwest::Proxy;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

pub struct Client {
    client: reqwest::Client,
}

impl Client {
    pub fn new(proxy: Option<Proxy>) -> Result<Client> {
        let mut b = reqwest::ClientBuilder::new();
        if let Some(proxy) = proxy {
            b = b.proxy(proxy);
        }
        Ok(Client { client: b.build()? })
    }

    pub async fn http_request(&self, url: &str) -> Result<reqwest::Response> {
        let resp = self
            .client
            .get(url)
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
