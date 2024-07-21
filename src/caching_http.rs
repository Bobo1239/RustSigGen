use std::{fs, path::PathBuf};

use anyhow::Result;
use log::*;
use regex::Regex;
use reqwest::IntoUrl;
use sha2::{Digest, Sha256};

use crate::cache_dir;

pub async fn get_string<T: IntoUrl>(url: T) -> Result<String> {
    let url = url.into_url()?;

    // We cache URLs which are either dated or are a full version number (so x.y.z).
    let re =
        Regex::new(r"^((/dist/\d{4}-\d{2}-\d{2}/)|(/dist/channel-rust-\d+.\d+.\d+.toml))").unwrap();
    let should_cache = url.domain().unwrap() == "static.rust-lang.org" && re.is_match(url.path());

    if should_cache {
        let path = download_file(url, None).await?;
        Ok(fs::read_to_string(path)?)
    } else {
        Ok(reqwest::get(url).await?.text().await?)
    }
}

// This always does caching for now since we actually want a file in the end so we store it in the
// cache dir.
pub async fn download_file<T: IntoUrl>(
    url: T,
    expected_sha256: Option<[u8; 32]>,
) -> Result<PathBuf> {
    let url = url.into_url()?;
    let out_path = cache_dir()
        .join(url.domain().unwrap())
        .join(url.path().trim_matches('/'));

    if out_path.exists() {
        if let Some(expected_sha256) = expected_sha256 {
            let bytes = fs::read(&out_path)?;
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            if hasher.finalize() == expected_sha256.into() {
                debug!("cache hit");
                return Ok(out_path);
            } else {
                fs::remove_file(&out_path)?;
                // Continue with normal download process
            }
        } else {
            debug!("cache hit");
            return Ok(out_path);
        }
    }

    let bytes = reqwest::get(url).await?.bytes().await?;

    fs::create_dir_all(out_path.parent().unwrap())?;
    fs::write(&out_path, bytes)?;

    Ok(out_path)
}
