#[macro_use] extern crate diesel;
#[macro_use] extern crate diesel_migrations;

pub mod archlinux;
pub mod migrations;
pub mod db;
pub mod decompress;
pub mod schema;

use crate::archlinux::ArchRepo;
use crate::db::Database;
use env_logger::Env;
use minisign::{SecretKey, PublicKey, PublicKeyBox};
use pacman_bintrans_common::errors::*;
use pacman_bintrans_common::http::Client;
use std::env;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::process::Stdio;
use structopt::StructOpt;
use structopt::clap::AppSettings;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp])]
struct Args {
    /// Verbose logging
    #[structopt(short)]
    verbose: bool,
    /// Configuration file path
    #[structopt(short, long)]
    config: Option<PathBuf>,
    #[structopt(long)]
    repo_url: String,
    #[structopt(long)]
    repo_name: String,
    #[structopt(long)]
    architecture: String,
    /// Url or path to pacman database file
    #[structopt(long)]
    repo_db: Option<String>,
    #[structopt(long)]
    signature_dir: Option<PathBuf>,
    /// Minisign public key used to sign packages
    #[structopt(long)]
    pubkey_path: PathBuf,
    /// Minisign secret key used to sign packages
    #[structopt(long)]
    seckey_path: PathBuf,
    /// Generate signatures but don't upload them
    #[structopt(long)]
    skip_upload: bool,
    #[structopt(long)]
    dry_run: bool,
}

async fn rekor_upload(pubkey: &PublicKeyBox, artifact: &[u8], signature: &str) -> Result<()> {
    let pubkey_file = NamedTempFile::new()?;
    let sig_file = NamedTempFile::new()?;

    fs::write(pubkey_file.path(), pubkey.to_string())?;
    fs::write(sig_file.path(), signature)?;

    let mut child = Command::new("rekor-cli")
        .arg("upload")
        .arg("--pki-format=minisign")
        .arg("--public-key")
        .arg(pubkey_file.path())
        .arg("--artifact")
        .arg("/dev/stdin")
        .arg("--signature")
        .arg(sig_file.path())
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to spawn")?;

    let mut stdin = child.stdin.take()
        .context("child did not have a handle to stdin")?;

    stdin.write_all(artifact)
        .await?;
    stdin.flush()
        .await?;
    drop(stdin);

    let status = child.wait().await?;
    if !status.success() {
        error!("Sigstore upload failed");
    }

    Ok(())
}

fn write_sig_to_dir(dir: &PathBuf, filename: &str, signature: &str) -> Result<()> {
    if filename.is_empty() {
        bail!("Filename can't be empty");
    }
    if filename.contains('/') {
        bail!("Filename contains invalid characters: {:?}", filename);
    }
    if filename.starts_with('.') {
        bail!("Filename is not allowed to start with `.`");
    }
    let path = dir.join(&format!("{}.t", filename));
    info!("Writing signature to folder: {:?}", path);
    fs::write(path, signature)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::from_args();

    let logging = if args.verbose {
        "debug"
    } else {
        "info"
    };

    env_logger::init_from_env(Env::default()
        .default_filter_or(logging));

    info!("Loading seckey");
    let password = env::var("PACMAN_BINTRANS_PASSWORD").ok();
    let sk = SecretKey::from_file(args.seckey_path, password)?;
    let pk = PublicKey::from_file(args.pubkey_path)?
        .to_box()?;
    info!("Key loaded");

    let client = Client::new(None)?;
    let repo = ArchRepo::new(args.repo_url, args.repo_name, args.architecture);

    let db = if let Some(path) = args.repo_db {
        path
    } else {
        repo.db_url()
    };
    let db = archlinux::load_db(&client, &db).await?;
    let pkgs = archlinux::db_parse_pkgs(&db)?;

    let db = Database::open("foo.db")?;

    for pkg in pkgs {
        if db.already_signed(&pkg)? {
            debug!("Package already known: {:?} => {:?}", pkg.sha256sum, pkg.filename);
            continue;
        }

        if args.dry_run {
            info!("Dry-run: would sign package: {:?} => {:?}", pkg.sha256sum, pkg.filename);
            continue;
        }

        info!("Signing package");
        let data_reader = Cursor::new(&pkg.sha256sum);
        let sig = minisign::sign(None, &sk, data_reader, false, Some(&pkg.filename), None)?;
        let sig = sig.to_string();

        info!("Adding to database");
        db.insert_sig(&pkg, sig.to_string(), None)?;

        if let Some(sig_dir) = &args.signature_dir {
            if let Err(err) = write_sig_to_dir(&sig_dir, &pkg.filename, &sig) {
                warn!("Failed to publish signature ({:?}): {:#}", pkg.filename, err);
            }
        }

        if args.skip_upload {
            info!("Uploading to sigstore");
            match rekor_upload(&pk, pkg.sha256sum.as_bytes(), &sig).await {
                Ok(_) => {
                    debug!("Record uuid (todo)");
                    db.insert_sig(&pkg, sig.to_string(), Some("dummy".into()))?;
                },
                Err(err) => {
                    error!("Error(rekor): {:?}", err);
                }
            }
        }
    }

    Ok(())
}
