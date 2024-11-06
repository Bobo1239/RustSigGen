pub mod caching_http;
pub mod ida;

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{BufReader, Read},
    path::PathBuf,
    str,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{Days, NaiveDate};
use log::*;
use object::{Architecture, BinaryFormat, Object};
use regex::bytes::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use tempfile::TempDir;
use toml::Table;
use xz2::bufread::XzDecoder;

// (Potentially) useful references/links:
// - https://github.com/rust-lang/cargo-bisect-rustc
// - https://github.com/kennytm/rustup-toolchain-install-master
// - https://github.com/rust-lang/rustup/issues/977
// - https://internals.rust-lang.org/t/future-updates-to-the-rustup-distribution-format/4196#the-v2-manifest-format
// - https://github.com/rust-lang/promote-release
// - https://github.com/rust-lang/generate-manifest-list
// - https://static.rust-lang.org/manifests.txt

pub fn cache_dir() -> PathBuf {
    dirs::cache_dir().unwrap().join(env!("CARGO_PKG_NAME"))
}

pub fn extract_object_files_to_tmp_dir(
    std_lib: &PathBuf,
    release_manifest: &ReleaseWithManifest,
) -> Result<TempDir> {
    info!("Extracting rust-std...");

    let file = BufReader::new(File::open(std_lib)?);
    let mut archive = Archive::new(XzDecoder::new(file));

    let tmp_dir = tempfile::tempdir()?;

    for file in archive.entries().unwrap() {
        let mut file = file?;
        match file.path()? {
            p if p.file_name() == Some(OsStr::new("git-commit-hash")) => {
                let mut commit_hash = String::new();
                file.read_to_string(&mut commit_hash)?;
                assert_eq!(commit_hash, release_manifest.commit_hash);
            }
            p if p.extension() == Some(OsStr::new("rlib")) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;

                let file = object::read::archive::ArchiveFile::parse(&*buf)?;
                for member in file.members() {
                    let member = member?;
                    let name = str::from_utf8(member.name())?;

                    if name.ends_with(".o") {
                        let data = member.data(&*buf)?;
                        fs::write(tmp_dir.path().join(name.replace('/', "\\")), data)?;
                        // let object_file = object::File::parse(data)?;
                    }
                }
            }
            p if p.extension() == Some(OsStr::new("rlib"))
                || p.extension() == Some(OsStr::new("a")) =>
            {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;

                let file = object::read::archive::ArchiveFile::parse(&*buf)?;
                for member in file.members() {
                    let member = member?;
                    let name = str::from_utf8(member.name())?;

                    // `.lo` files appear in `libc.a` for musl target
                    if name.ends_with(".o") || name.ends_with(".lo") {
                        let data = member.data(&*buf)?;
                        fs::write(tmp_dir.path().join(name.replace('/', "\\")), data)?;
                    }
                }
            }
            p if p.extension() == Some(OsStr::new("o")) => {
                let mut f = File::create(tmp_dir.path().join(p.file_name().unwrap()))?;
                std::io::copy(&mut file, &mut f)?;
            }
            p if p.extension() == Some(OsStr::new("lo")) => {
                // Just a sanity check for now
                unreachable!();
            }
            _ => {}
        }
    }

    Ok(tmp_dir)
}

pub async fn download_std_lib(release: &ReleaseWithManifest, target: Target) -> Result<PathBuf> {
    // TODO: Cache eviction...
    let url = release.rust_std_url(Component::RustStd, target);

    info!("Downloading rust-std for that release... ({})", url);
    let sha256 = release.rust_std_sha256(Component::RustStd, target);
    let path = caching_http::download_file(url, Some(sha256)).await?;
    let bytes = std::fs::read(&path)?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    if hasher.finalize() != release.rust_std_sha256(Component::RustStd, target).into() {
        bail!("downloaded std lib doesn't match expected SHA256 hash");
    }

    Ok(path)
}

pub async fn detect_rustc_release(bin: &[u8]) -> Result<(ReleaseWithManifest, Target)> {
    // Windows binaries use `\` except at the root for some reason
    let re = Regex::new(r"/rustc[/\\]([[:xdigit:]]{40})[/\\]")?;
    let mut m = re
        .captures_iter(bin)
        .map(|m| str::from_utf8(m.get(1).unwrap().as_bytes()).unwrap());

    let commit_hash = m
        .next()
        .ok_or(anyhow!("failed to detect a rustc commit hash"))?;
    if !m.all(|m| m == commit_hash) {
        bail!("detected multiple rustc commit hashes")
    }
    info!("Detected rustc commit hash: {}", commit_hash);

    let rel_with_manifest = determine_release_from_commit(commit_hash).await?;
    info!("Detected rustc release: {:?}", rel_with_manifest.release);

    let file = object::File::parse(bin)?;
    // TODO: This is very naive atm...
    let target = match file.format() {
        BinaryFormat::Elf => {
            let statically_linked = file.imports()?.is_empty();
            match (file.architecture(), statically_linked) {
                (Architecture::X86_64, false) => Target::X8664LinuxGnu,
                // NOTE: Currently we assume that a completely statically linked binary means musl
                //       libc. This doesn't have to be true but is definitely the common case.
                //       Statically linking glibc is not well supported and fully statically linked
                //       binaries is one of the main reasons for using musl. Rust even defaults to
                //       full static linking when using the musl target target though this may
                //       change in the future: https://github.com/rust-lang/compiler-team/issues/422
                // NOTE: musl libc is bundled together with rustc so we don't have to make any
                //       special considerations for multiple musl versions. Bundled version can be
                //       seen in:
                //       https://github.com/rust-lang/rust/blob/master/src/ci/docker/scripts/musl-toolchain.sh
                (Architecture::X86_64, true) => Target::X8664LinuxMusl,
                (a, s) => unimplemented!(
                    "unsupported ELF architecture: {:?} (statically linked: {})",
                    a,
                    s
                ),
            }
        }
        BinaryFormat::Pe => {
            // TODO: Apparently this isn't sufficient?
            //       (https://nofix.re/posts/2024-23-05-rust-mingw/) Investigate whether mingw is
            //       provided by the compiler runtime environment or shipped with rustc.
            //       Apparently it depends... https://github.com/rust-lang/rust/pull/67429
            //       The rust-mingw rustup component contains the bundled MinGW libraries so we
            //       could generate signatures for that at least.
            // TODO: There's also a new x86_64-pc-windows-gnullvm target...
            let is_mingw = Regex::new("Mingw-w64 runtime failure:")
                .unwrap()
                .is_match(bin);
            match (file.is_64(), is_mingw) {
                (true, true) => Target::X8664WindowsGnu,
                (true, false) => Target::X8664WindowsMsvc,
                (false, true) => Target::I686WindowsGnu,
                (false, false) => Target::I686WindowsMsvc,
            }
        }
        f => unimplemented!("unsupported binary format: {f:?}"),
    };

    info!("Detected binary platform: {}", target.name());

    Ok((rel_with_manifest, target))
}

pub async fn get_manifest_and_hash(
    date: Option<&NaiveDate>,
    channel: &str,
) -> Result<Option<(Table, String, String)>> {
    let manifest_url = if let Some(date) = date {
        format!(
            "https://static.rust-lang.org/dist/{}/channel-rust-{channel}.toml",
            date.format("%Y-%m-%d")
        )
    } else {
        format!("https://static.rust-lang.org/dist/channel-rust-{channel}.toml",)
    };
    let manifest = caching_http::get_string(&manifest_url).await?;

    // NOTE: I've observed these errors already but not sure why both can occur...
    if manifest.contains("<Error><Code>NoSuchKey</Code>")
        || manifest.contains("<title>Not Found</title>")
    {
        Ok(None)
    } else {
        let table = manifest.parse::<Table>().unwrap();
        let commit_hash = table["pkg"]["rustc"]["git_commit_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        Ok(Some((table, commit_hash, manifest_url)))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResolvedCommit {
    manifest_url: String,
    release: Release,
}

pub async fn determine_release_from_commit(commit_hash: &str) -> Result<ReleaseWithManifest> {
    // We're caching these results since they never change and we don't want to run into GitHub's
    // rate limit of 60 req/h (without API token)
    let cache_path = cache_dir().join("resolved_commits.json");
    let mut cached = if let Ok(json) = fs::read_to_string(&cache_path) {
        serde_json::from_str::<HashMap<String, ResolvedCommit>>(&json)?
    } else {
        HashMap::new()
    };

    if let Some(resolved) = cached.get(commit_hash) {
        trace!("cache hit: commit hash");
        let manifest = caching_http::get_string(&resolved.manifest_url).await?;
        let manifest = manifest.parse::<Table>().unwrap();
        assert_eq!(
            commit_hash,
            manifest["pkg"]["rustc"]["git_commit_hash"]
                .as_str()
                .unwrap()
        );
        return Ok(ReleaseWithManifest {
            release: resolved.release.clone(),
            commit_hash: commit_hash.to_owned(),
            manifest,
        });
    }

    // First check tagged releases
    let octocrab = octocrab::instance();
    let tags_first_page = octocrab
        .repos("rust-lang", "rust")
        .list_tags()
        .per_page(100)
        .send()
        .await?;
    let tags = octocrab.all_pages(tags_first_page).await?;

    let (release, manifest, manifest_url) = match tags
        .into_iter()
        .find(|t| t.commit.sha == commit_hash)
    {
        Some(tag) => {
            // Found a matching tag so we're dealing with a stable release
            // These manifests are used by rustup so we should be able to rely on them.
            // NOTE: We can see the URLs used by rustup using `rustup -v toolchain install 1.78`.
            let (manifest, hash, url) = get_manifest_and_hash(None, &tag.name).await?.unwrap();
            ensure!(
                commit_hash == hash,
                "rustc commit hash doesn't match manifest; bug"
            );
            (Release::Stable(tag.name), manifest, url)
        }
        None => {
            // If no tagged release matches we assume a beta or nightly release
            let commit = octocrab
                .commits("rust-lang", "rust")
                .get(commit_hash)
                .await
                .context("couldn't find rustc commit hash in the Rust git repository; binary may be using a custom rustc build")?;
            let date = commit
                .commit
                .author
                .ok_or(anyhow!("commit has no author"))?
                .date
                .ok_or(anyhow!("commit has no date"))?;

            // Rust releases are built at 0:00 UTC so the first release to contain our
            // commit must be from the next day.
            let date = date.checked_add_days(Days::new(1)).unwrap().date_naive();

            // First try beta
            let manifest_hash = get_manifest_and_hash(Some(&date), "beta").await?;
            if let Some((manifest, _, url)) =
                manifest_hash.filter(|(_, hash, _)| hash == commit_hash)
            {
                (Release::Beta(date), manifest, url)
            } else {
                // Then try nightly
                let manifest_hash = get_manifest_and_hash(Some(&date), "nightly").await?;
                if let Some((manifest, _, url)) =
                    manifest_hash.filter(|(_, hash, _)| hash == commit_hash)
                {
                    (Release::Nightly(date), manifest, url)
                } else {
                    bail!("failed to find a release with the rustc commit hash; but found the commit in the Rust git repository; either bug or custom rustc build")
                }
            }
        }
    };

    cached.insert(
        commit_hash.to_owned(),
        ResolvedCommit {
            manifest_url,
            release: release.clone(),
        },
    );

    let cached_json = serde_json::to_string(&cached)?;
    fs::create_dir_all(cache_path.parent().unwrap())?;
    fs::write(cache_path, cached_json)?;

    Ok(ReleaseWithManifest {
        release,
        commit_hash: commit_hash.to_owned(),
        manifest,
    })
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

    pub fn signature_base_file_name(&self) -> String {
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
