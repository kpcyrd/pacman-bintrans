use pacman_bintrans_common::decompress;
use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http::Client;
use rebuilderd_common::{PkgRelease, Status};
use std::io::{self, Read, Write};
use std::path::Path;
use tar::{Archive, EntryType};
use url::Url;

fn build_query_url(rebuilder: &Url, name: &str) -> Result<Url> {
    let mut url = rebuilder.clone();

    url.path_segments_mut()
        .map_err(|_| anyhow!("Failed to get path segments for url"))?
        .pop_if_empty()
        .extend(&["api", "v0", "pkgs", "list"]);

    url.query_pairs_mut()
        .append_pair("distro", "archlinux")
        .append_pair("name", name);

    Ok(url)
}

/// Returns true for sucecssful rebuilds,  false for everything else
async fn query_rebuilder(
    client: &Client,
    rebuilder: &Url,
    name: &str,
    version: &str,
) -> Result<bool> {
    let url = build_query_url(rebuilder, name)?;

    info!("Querying rebuilder: {:?}", url.as_str());

    // TODO: ensure there's a timeout
    let json = client.download_to_mem(url.as_str(), None).await?;
    let pkgs = serde_json::from_slice::<Vec<PkgRelease>>(&json)
        .context("Failed to deserialize response")?;

    for pkg in pkgs {
        if pkg.name != name {
            continue;
        }

        if pkg.version != version {
            continue;
        }

        if pkg.status != Status::Good {
            continue;
        }

        return Ok(true);
    }

    Ok(false)
}

#[derive(Debug, PartialEq)]
struct PkgInfo {
    name: String,
    version: String,
}

fn extract_dot_pkginfo_from_archive(bytes: &[u8]) -> Result<String> {
    let compression = decompress::detect_compression(bytes);
    let tar =
        decompress::stream(compression, bytes).context("Failed to open compressed package")?;

    let mut archive = Archive::new(tar);

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != EntryType::Regular {
            continue;
        }

        match entry.header().path() {
            Ok(p) if p == Path::new(".PKGINFO") => (),
            _ => continue,
        }

        let mut file = String::new();
        entry
            .read_to_string(&mut file)
            .context("Failed to read .PKGINFO from archive")?;

        return Ok(file);
    }

    bail!("Package does not contain .PKGINFO")
}

fn parse_pkg_info(pkg: &[u8]) -> Result<PkgInfo> {
    let mut pkgname = None;
    let mut pkgver = None;

    let content = extract_dot_pkginfo_from_archive(pkg)?;
    for line in content.split('\n') {
        if let Some(value) = line.strip_prefix("pkgname = ") {
            pkgname = Some(value.to_string());
        }
        if let Some(value) = line.strip_prefix("pkgver = ") {
            pkgver = Some(value.to_string());
        }
    }

    Ok(PkgInfo {
        name: pkgname.context("Missing pkgname field in .PKGINFO")?,
        version: pkgver.context("Missing pkgver field in .PKGINFO")?,
    })
}

pub async fn check_rebuilds(client: &Client, pkg: &[u8], rebuilders: &[Url]) -> Result<usize> {
    println!("\x1b[1m[\x1b[34m%\x1b[0;1m]\x1b[0m Inspecting .PKGINFO in package...");
    let pkginfo = parse_pkg_info(pkg).context("Failed to parse infos from package")?;
    print!("\x1b[1A\x1b[2K");

    let mut confirms = 0;
    for rebuilder in rebuilders {
        println!(
            "\x1b[2K\r\x1b[1m[\x1b[34m%\x1b[0;1m]\x1b[0m Checking rebuilder {:?}...",
            rebuilder.as_str()
        );
        match query_rebuilder(client, rebuilder, &pkginfo.name, &pkginfo.version).await {
            Ok(true) => {
                let msg = format!(
                    "Package was reproduced by rebuilder: {:?}",
                    rebuilder.as_str()
                );

                println!("\x1b[1A\x1b[2K\r\x1b[1m[\x1b[32m+\x1b[0;1m]\x1b[0m {:95} \x1b[32mREPRODUCIBLE\x1b[0m", msg);
                confirms += 1;
                continue;
            }
            Ok(false) => (),
            Err(err) => {
                // TODO: log warning
                warn!("Failed to query rebuilder: {:?}", err);
            }
        }
        print!("\x1b[1A\x1b[2K");
    }
    io::stdout().flush().ok();

    Ok(confirms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url_trailing_slash() {
        let rebuilder = "https://reproducible.archlinux.org/".parse().unwrap();
        let url = build_query_url(&rebuilder, "rebuilderd").unwrap();
        assert_eq!(
            url.as_str(),
            "https://reproducible.archlinux.org/api/v0/pkgs/list?distro=archlinux&name=rebuilderd"
        );
    }

    #[test]
    fn test_build_url_no_trailing_slash() {
        let rebuilder = "https://reproducible.archlinux.org".parse().unwrap();
        let url = build_query_url(&rebuilder, "rebuilderd").unwrap();
        assert_eq!(
            url.as_str(),
            "https://reproducible.archlinux.org/api/v0/pkgs/list?distro=archlinux&name=rebuilderd"
        );
    }

    #[test]
    fn test_build_url_subdir_trailing_slash() {
        let rebuilder = "https://wolfpit.net/rebuild/".parse().unwrap();
        let url = build_query_url(&rebuilder, "rebuilderd").unwrap();
        assert_eq!(
            url.as_str(),
            "https://wolfpit.net/rebuild/api/v0/pkgs/list?distro=archlinux&name=rebuilderd"
        );
    }

    #[test]
    fn test_build_url_subdir_no_trailing_slash() {
        let rebuilder = "https://wolfpit.net/rebuild".parse().unwrap();
        let url = build_query_url(&rebuilder, "rebuilderd").unwrap();
        assert_eq!(
            url.as_str(),
            "https://wolfpit.net/rebuild/api/v0/pkgs/list?distro=archlinux&name=rebuilderd"
        );
    }

    #[test]
    fn test_parse_pkg_get_name_version() {
        let bytes = include_bytes!("../test_data/rebuilderd-0.18.1-1-x86_64.pkg.tar.zst");
        let pkginfo = parse_pkg_info(bytes).unwrap();
        assert_eq!(
            pkginfo,
            PkgInfo {
                name: "rebuilderd".to_string(),
                version: "0.18.1-1".to_string(),
            }
        );
    }
}
