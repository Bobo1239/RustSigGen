pub mod caching_http;
pub mod ida;

pub mod crate_sigs;
pub mod std_sigs;

use std::path::PathBuf;

use chrono::NaiveDate;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use toml::Table;

pub fn cache_dir() -> PathBuf {
    dirs::cache_dir().unwrap().join(env!("CARGO_PKG_NAME"))
}

pub struct ReleaseWithManifest {
    release: Release,
    commit_hash: String,
    /// The rustup manifest.
    manifest: Table,
}

impl ReleaseWithManifest {
    pub fn release(&self) -> &Release {
        &self.release
    }

    fn rust_std_url(&self, component: Component, target: Target) -> Url {
        self.manifest["pkg"][component.key()]["target"][target.name()]["xz_url"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    fn rust_std_sha256(&self, component: Component, target: Target) -> [u8; 32] {
        let hash_hex = self.manifest["pkg"][component.key()]["target"][target.name()]["xz_hash"]
            .as_str()
            .unwrap();
        let mut ret = [0; 32];
        hex::decode_to_slice(hash_hex, &mut ret).unwrap();
        ret
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Release {
    Stable(String),
    Beta(NaiveDate),
    Nightly(NaiveDate),
}

impl Release {
    pub fn name(&self) -> String {
        match self {
            Release::Stable(rel) => rel.clone(),
            Release::Beta(date) => format!("beta-{}", date.format("%Y-%m-%d")),
            Release::Nightly(date) => format!("nightly-{}", date.format("%Y-%m-%d")),
        }
    }

    pub fn std_signature_base_file_name(&self) -> String {
        format!("rust-std-{}", self.name().replace('.', "-"))
    }

    pub fn is_nightly(&self) -> bool {
        matches!(self, Release::Nightly(..))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Component {
    RustStd,
}

impl Component {
    fn key(&self) -> &'static str {
        match self {
            Component::RustStd => "rust-std",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Target {
    X8664LinuxGnu,
    X8664LinuxMusl,
    X8664WindowsMsvc,
    X8664WindowsGnu,
    I686WindowsMsvc,
    I686WindowsGnu,
}

impl Target {
    pub fn name(&self) -> &'static str {
        match self {
            Target::X8664LinuxGnu => "x86_64-unknown-linux-gnu",
            Target::X8664LinuxMusl => "x86_64-unknown-linux-musl",
            Target::X8664WindowsMsvc => "x86_64-pc-windows-msvc",
            Target::X8664WindowsGnu => "x86_64-pc-windows-gnu",
            Target::I686WindowsMsvc => "i686-pc-windows-msvc",
            Target::I686WindowsGnu => "i686-pc-windows-gnu",
        }
    }
}
