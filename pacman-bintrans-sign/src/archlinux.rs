use crate::decompress;
use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http::Client;
use std::convert::TryInto;
use std::fs;
use std::io::Read;
use tar::{Archive, EntryType};
use url::Url;

pub struct ArchRepo {
    url: String,
    name: String,
    arch: String,
}

impl ArchRepo {
    pub fn new(url: String, name: String, arch: String) -> ArchRepo {
        ArchRepo { url, name, arch }
    }

    pub fn db_url(&self) -> String {
        let url = &self.url;
        let url = url.replace("$repo", &self.name);
        let url = url.replace("$arch", &self.arch);
        format!("{}/{}.db", url, self.name)
    }

    pub fn pkg_url(&self, pkg: &Pkg) -> String {
        let url = &self.url;
        let url = url.replace("$repo", &self.name);
        let url = url.replace("$arch", &self.arch);
        format!("{}/{}", url, pkg.filename)
    }
}

pub async fn load_db(client: &Client, path: &str) -> Result<Vec<u8>> {
    if path.starts_with("http:") || path.starts_with("https:") {
        let url = path
            .parse::<Url>()
            .with_context(|| anyhow!("Failed to parse url: {:?}", path))?;
        info!("Fetching database: {:?}", url);
        let body = client
            .http_request(url)
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        info!("Downloadeded {} bytes", body.len());
        Ok(body.to_vec())
    } else {
        let file = fs::read(path)?;
        info!("Loaded {} bytes from disk", file.len());
        Ok(file)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Pkg {
    pub name: String,
    pub base: String,
    pub filename: String,
    pub version: String,
    pub sha256sum: String,
    pub architecture: String,
    pub packager: String,
}

#[derive(Debug, Default)]
pub struct NewPkg {
    name: Vec<String>,
    base: Vec<String>,
    filename: Vec<String>,
    version: Vec<String>,
    sha256sum: Vec<String>,
    architecture: Vec<String>,
    packager: Vec<String>,
}

impl TryInto<Pkg> for NewPkg {
    type Error = Error;

    fn try_into(self: NewPkg) -> Result<Pkg> {
        Ok(Pkg {
            name: self
                .name
                .first()
                .ok_or_else(|| anyhow!("Missing pkg name field"))?
                .to_string(),
            base: self
                .base
                .first()
                .ok_or_else(|| anyhow!("Missing pkg base field"))?
                .to_string(),
            filename: self
                .filename
                .first()
                .ok_or_else(|| anyhow!("Missing filename field"))?
                .to_string(),
            version: self
                .version
                .first()
                .ok_or_else(|| anyhow!("Missing version field"))?
                .to_string(),
            sha256sum: self
                .sha256sum
                .first()
                .ok_or_else(|| anyhow!("Missing sha256sum field"))?
                .to_string(),
            architecture: self
                .architecture
                .first()
                .ok_or_else(|| anyhow!("Missing architecture field"))?
                .to_string(),
            packager: self
                .packager
                .first()
                .ok_or_else(|| anyhow!("Missing packager field"))?
                .to_string(),
        })
    }
}

pub fn db_parse_pkgs(bytes: &[u8]) -> Result<Vec<Pkg>> {
    let comp = decompress::detect_compression(bytes);
    let tar = decompress::stream(comp, bytes)?;
    let mut archive = Archive::new(tar);

    let mut pkgs = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() == EntryType::Regular {
            let mut pkg = NewPkg::default();

            let mut content = String::new();
            entry.read_to_string(&mut content)?;

            let mut iter = content.split('\n');
            while let Some(key) = iter.next() {
                let mut values = Vec::new();
                for value in &mut iter {
                    if !value.is_empty() {
                        values.push(value.to_string());
                    } else {
                        break;
                    }
                }

                match key {
                    "%FILENAME%" => pkg.filename = values,
                    "%NAME%" => pkg.name = values,
                    "%BASE%" => pkg.base = values,
                    "%VERSION%" => pkg.version = values,
                    "%SHA256SUM%" => pkg.sha256sum = values,
                    "%ARCH%" => pkg.architecture = values,
                    "%PACKAGER%" => pkg.packager = values,
                    _ => (),
                }
            }

            pkgs.push(pkg.try_into()?);
        }
    }

    Ok(pkgs)
}
