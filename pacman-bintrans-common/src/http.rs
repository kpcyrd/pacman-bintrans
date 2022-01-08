use crate::errors::*;
use futures_util::StreamExt;
use reqwest::IntoUrl;
use reqwest::Response;
use reqwest::Url;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Proxy {
    text: String,
    inner: reqwest::Proxy,
}

impl Proxy {
    pub fn all(s: &str) -> Result<Proxy> {
        let mut url = Url::parse(s)
            .context("Failed to parse proxy as url")?;

        // normalize for Go http.Client
        if url.scheme() == "socks5h" {
            url.set_scheme("socks5").unwrap();
        }

        let text = url.to_string();

        let inner = reqwest::Proxy::all(s)?;
        Ok(Proxy { text, inner })
    }

    pub fn to_proxy(&self) -> reqwest::Proxy {
        self.inner.clone()
    }

    pub fn as_text(&self) -> &str {
        &self.text
    }
}

pub struct Client {
    client: reqwest::Client,
}

impl Client {
    pub fn new(proxy: Option<Proxy>) -> Result<Client> {
        let mut b = reqwest::ClientBuilder::new();
        if let Some(proxy) = proxy {
            b = b.proxy(proxy.to_proxy());
        }
        Ok(Client { client: b.build()? })
    }

    pub async fn http_request(&self, url: Url) -> Result<reqwest::Response> {
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

    async fn fetch_loop<W: Write>(
        &self,
        resp: Response,
        file_name: &str,
        out: &mut W,
        limit: Option<usize>,
    ) -> Result<usize> {
        let total_size = resp
            .content_length()
            .ok_or_else(|| anyhow!("Failed to get content length from request"))?;

        let mut stream = resp.bytes_stream();

        use indicatif::{ProgressBar, ProgressStyle};

        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
                )
                .progress_chars("#>-"),
        );
        pb.set_message(file_name.to_string());

        let mut n = 0;
        while let Some(item) = stream.next().await {
            let bytes = item.context("Failed to read from stream")?;

            if let Some(limit) = limit {
                if bytes.len() + n > limit {
                    bail!("Exceeded size limit for download");
                }
            }

            out.write_all(&bytes)
                .context("Failed to write to output file")?;
            n += bytes.len();

            pb.set_position(n as u64);
        }

        Ok(n)
    }

    pub async fn download_to_mem<U: IntoUrl>(
        &self,
        url: U,
        limit: Option<usize>,
    ) -> Result<Vec<u8>> {
        let url = url.into_url()?;
        let file_name = get_filename(&url)?;
        let resp = self.http_request(url).await?;

        let mut out = Vec::new();
        self.fetch_loop(resp, &file_name, &mut out, limit).await?;
        Ok(out)
    }

    pub async fn download_to_file<U: IntoUrl>(&self, url: U, output: &Path) -> Result<usize> {
        let url = url.into_url()?;
        let file_name = get_filename(&url)?;
        let resp = self.http_request(url).await?;

        let mut out = File::create(output).context("Failed to create output file")?;
        let n = self.fetch_loop(resp, &file_name, &mut out, None).await?;

        Ok(n)
    }
}

fn get_filename(url: &Url) -> Result<String> {
    let segments = url
        .path_segments()
        .ok_or_else(|| anyhow!("Url can not be base: {:?}", url.as_str()))?;
    let last = segments
        .last()
        .ok_or_else(|| anyhow!("Url has no path segments"))?;

    if last.is_empty() {
        bail!("Url filename can't be empty");
    }

    Ok(last.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_to_env() {
        let proxy = Proxy::all("socks5://192.168.1.1:1080").unwrap();
        assert_eq!(proxy.as_text(), "socks5://192.168.1.1:1080");
    }

    #[test]
    fn test_proxy_socks5h_to_socks5_text() {
        let proxy = Proxy::all("socks5h://192.168.1.1:1080").unwrap();
        assert_eq!(proxy.as_text(), "socks5://192.168.1.1:1080");
    }
}
