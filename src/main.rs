use std::fmt::{self, Debug};

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Days, Utc};
use object::{File, Object};
use regex::bytes::Regex;
use reqwest::Url;
use toml::Table;

// (Potentially) useful references/links:
// - https://github.com/rust-lang/cargo-bisect-rustc
// - https://github.com/kennytm/rustup-toolchain-install-master
// - https://github.com/rust-lang/rustup/issues/977
// - https://internals.rust-lang.org/t/future-updates-to-the-rustup-distribution-format/4196#the-v2-manifest-format
// - https://github.com/rust-lang/promote-release
// - https://github.com/rust-lang/generate-manifest-list
// - https://static.rust-lang.org/manifests.txt

// TODO: Adapt detection logic for non-Linux binaries
// TODO: Support for linux-musl target?
// TODO: Detect used crates (only those with panic info)

// TODO: Use `dirs`` to get cache directory and cache downloads
const TMP_FILE: &str = "download.tar.xz";

fn main() -> Result<()> {
    let path = std::env::args().nth(1).expect("missing arg: <path>");
    let bin = std::fs::read(path)?;

    let re = Regex::new("/rustc/([[:xdigit:]]{40})/").unwrap();
    let mut m = re
        .captures_iter(&bin)
        .map(|m| std::str::from_utf8(m.get(1).unwrap().as_bytes()).unwrap());

    let commit_hash = m
        .next()
        .ok_or(anyhow!("failed to detect a rustc commit hash"))?;
    assert!(
        m.all(|m| m == commit_hash),
        "detected multiple rustc commit hash"
    );
    println!("Detected rustc commit hash: {}", commit_hash);

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let release = determine_release(commit_hash).await?;
            println!("Detected rustc version: {:?}", release);

            let url = release.rust_std_download_url();
            println!("Downloading rust-std for that release... ({})", url);
            let bytes = reqwest::get(url).await?.bytes().await?;
            std::fs::write(TMP_FILE, bytes)?;

            Ok::<_, anyhow::Error>(())
        })?;

    // let tmpdir = tempfile::tempdir()?;

    // let data = fs::read("libstd-d2ef02247056996e.rlib")?;
    // let file = object::read::archive::ArchiveFile::parse(&*data)?;
    // for member in file.members() {
    //     let member = member?;
    //     println!("{}", String::from_utf8_lossy(member.name()));
    //     let data = member.data(&data[..])?;
    //     dbg!(data.len());
    //     let object_file = File::parse(data)?;
    //     dbg!(object_file.architecture());
    //     dbg!(object_file.symbols().count());
    //     // for sym in sym
    //     // dbg!(object_file.symbol_table());
    // }
    Ok(())
}

async fn determine_release(commit_hash: &str) -> Result<Release> {
    // TODO: Allow using an API token; otherwise limited to 60 req/h
    let octocrab = octocrab::instance();
    let tags_first_page = octocrab
        .repos("rust-lang", "rust")
        .list_tags()
        .per_page(100)
        .send()
        .await?;
    let tags = octocrab.all_pages(tags_first_page).await?;

    let release = match tags.into_iter().find(|t| t.commit.sha == commit_hash) {
        Some(tag) => {
            // These manifests are used by rustup so we should be able to rely on them.
            // NOTE: We can see the URLs used by rustup using `rustup -v toolchain install 1.78`.
            let manifest_url = format!(
                "https://static.rust-lang.org/dist/channel-rust-{}.toml",
                tag.name
            );
            let manifest = reqwest::get(manifest_url).await?.text().await?;
            let manifest = manifest.parse::<Table>().unwrap();
            Release::Stable(tag.name, manifest)
        }
        None => {
            let commit = octocrab
                .commits("rust-lang", "rust")
                .get(commit_hash)
                .await?;
            let date = commit
                .commit
                .author
                .ok_or(anyhow!("commit has no author"))?
                .date
                .ok_or(anyhow!("commit has no date"))?;

            // Rust nightlies are built at 0:00 UTC so the first nightly to contain our
            // commit must be from the next day.
            let date = date.checked_add_days(Days::new(1)).unwrap();
            let manifest_url = format!(
                "https://static.rust-lang.org/dist/{}/channel-rust-nightly.toml",
                date.format("%Y-%m-%d")
            );
            let manifest = reqwest::get(manifest_url).await?.text().await?;
            let manifest = manifest.parse::<Table>().unwrap();

            let manifest_commit_hash = &manifest["pkg"]["rustc"]["git_commit_hash"];
            if commit_hash == manifest_commit_hash.as_str().unwrap() {
                Release::Nightly(date)
            } else {
                bail!("rustc commit hash matched neither stable nor nightly release")
            }
        }
    };

    Ok(release)
}

enum Release {
    Stable(String, Table), // The rustup manifest
    // Don't think these are very relevant for our use-case and not even sure if they are archived
    // TODO: Check if they're archived; if yes we can handle them like stable releases probably
    // Beta(String),
    Nightly(DateTime<Utc>),
}

impl Debug for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable(version, _) => write!(f, "Stable({version})"),
            Self::Nightly(date) => write!(f, "Nightly({})", date.format("%Y-%m-%d")),
        }
    }
}

impl Release {
    fn rust_std_download_url(&self) -> Url {
        let target = "x86_64-unknown-linux-gnu"; // TODO: Make this a parameter
        let component = "rust-std";
        match self {
            Release::Stable(_, manifest) => manifest["pkg"][component]["target"][target]["url"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            Release::Nightly(date) => format!(
                "https://static.rust-lang.org/dist/{}/{component}-nightly-{target}.tar.xz",
                date.format("%Y-%m-%d")
            )
            .parse()
            .unwrap(),
        }
    }
}
