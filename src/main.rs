use std::{
    env,
    ffi::OsStr,
    fmt::Debug,
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str,
};

use anyhow::{anyhow, bail, ensure, Result};
use chrono::{Days, NaiveDate};
use clap::{arg, Parser};
use regex::bytes::Regex;
use reqwest::Url;
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

// TODO: Additional target support (see https://doc.rust-lang.org/stable/rustc/platform-support.html)
// TODO: Detect used crates (only those with panic info)

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the FLIRT directory. Needed to get access to `sigmake` and co. If not set signature
    /// generation for IDA will be skipped.
    #[arg(short, long)]
    flair_path: Option<PathBuf>,
    /// Path of binary to generate signatures for
    bin_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let bin = fs::read(args.bin_path)?;
    let release_manifest = detect_rustc_release(&bin).await?;
    let std_lib = download_std_lib(&release_manifest).await?;
    let tmp_dir = extract_object_files_to_tmp_dir(&std_lib, &release_manifest)?;

    if let Some(flair_path) = args.flair_path {
        println!("Generating IDA F.L.I.R.T. signatures...");
        generate_ida_signatures(&tmp_dir, &flair_path, &release_manifest)?;
    }

    Ok(())
}

fn generate_ida_signatures(
    tmp_dir: &TempDir,
    flair_path: &Path,
    release_manifest: &ReleaseWithManifest,
) -> Result<()> {
    // TODO: Fix signature library name (atm IDA outputs `Using FLIRT signature: Unnamed sample library`)
    let bin_path = flair_path.join("bin/linux");
    if !bin_path.exists() {
        bail!("FLAIR directory doesn't seem correct; failed to find `bin/linux`")
    }

    let status = Command::new(bin_path.join("pelf"))
        .arg(tmp_dir.path().join("*.o"))
        .arg(tmp_dir.path().join("std.pat"))
        .stderr(Stdio::null())
        .status()?;
    ensure!(status.success(), "pelf failed; non-zero exit code");

    // Not checking for exit code here since it will be non-zero on collisions (which we expect)
    let output = Command::new(bin_path.join("sigmake"))
        .arg(tmp_dir.path().join("std.pat"))
        .arg(tmp_dir.path().join("std.sig"))
        .output()?;
    println!(
        "sigmake output: {}",
        str::from_utf8(&output.stderr)?.lines().next().unwrap()
    );

    let exc_path = tmp_dir.path().join("std.exc");
    let exc = std::fs::read_to_string(&exc_path)?;
    // Skipping the first four lines indicates to `sigmake` that we just want to skip the
    // collisions.
    // TODO: We can handle some of the collisions to get better signatures
    let new_exc = exc.lines().skip(4).collect::<Vec<_>>().join("\n");
    std::fs::write(&exc_path, new_exc)?;

    let status = Command::new(bin_path.join("sigmake"))
        .arg(tmp_dir.path().join("std.pat"))
        .arg(tmp_dir.path().join("std.sig"))
        .status()?;
    ensure!(status.success(), "sigmake failed; non-zero exit code");

    let out_path = format!("{}.sig", release_manifest.release.path_name());
    std::fs::copy(tmp_dir.path().join("std.sig"), &out_path)?;
    println!("Generated {}", out_path);

    Ok(())
}

fn extract_object_files_to_tmp_dir(
    std_lib: &PathBuf,
    release_manifest: &ReleaseWithManifest,
) -> Result<TempDir> {
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
                        fs::write(tmp_dir.path().join(name), data)?;
                        // let object_file = object::File::parse(data)?;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(tmp_dir)
}

async fn download_std_lib(release: &ReleaseWithManifest) -> Result<PathBuf> {
    // TODO: Cache eviction...
    let cache_dir = dirs::cache_dir().unwrap().join(env!("CARGO_PKG_NAME"));

    let url = release.rust_std_url();
    let target_path = cache_dir
        .join(url.domain().unwrap())
        .join(url.path().trim_matches('/'));

    if target_path.exists() {
        let bytes = fs::read(&target_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        if hasher.finalize() == release.rust_std_sha256().into() {
            println!("Found cached rust-std for that release...");
            return Ok(target_path);
        } else {
            println!("Cached rust-std is corrupt!");
            fs::remove_file(&target_path)?;
        }
    }

    // TODO: Progress bar (https://gist.github.com/Tapanhaz/096e299bf060607b572d700e89a62529)
    println!("Downloading rust-std for that release... ({})", url);

    let bytes = reqwest::get(url).await?.bytes().await?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    if hasher.finalize() != release.rust_std_sha256().into() {
        bail!("downloaded std lib doesn't match expected SHA256 hash");
    }

    fs::create_dir_all(target_path.parent().unwrap())?;
    fs::write(&target_path, bytes)?;
    Ok(target_path)
}

async fn detect_rustc_release(bin: &[u8]) -> Result<ReleaseWithManifest> {
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
    println!("Detected rustc commit hash: {}", commit_hash);

    let rel_with_manifest = determine_release_from_commit(commit_hash).await?;
    println!("Detected rustc release: {:?}", rel_with_manifest.release);

    Ok(rel_with_manifest)
}

async fn determine_release_from_commit(commit_hash: &str) -> Result<ReleaseWithManifest> {
    // First check tagged releases
    // TODO: Allow using an API token; otherwise limited to 60 req/h
    let octocrab = octocrab::instance();
    let tags_first_page = octocrab
        .repos("rust-lang", "rust")
        .list_tags()
        .per_page(100)
        .send()
        .await?;
    let tags = octocrab.all_pages(tags_first_page).await?;

    let (release, manifest_url) = match tags.into_iter().find(|t| t.commit.sha == commit_hash) {
        Some(tag) => {
            // Found a matching tag so we're dealing with a stable release
            // These manifests are used by rustup so we should be able to rely on them.
            // NOTE: We can see the URLs used by rustup using `rustup -v toolchain install 1.78`.
            let manifest_url = format!(
                "https://static.rust-lang.org/dist/channel-rust-{}.toml",
                tag.name
            );
            (Release::Stable(tag.name), manifest_url)
        }
        None => {
            // If no tagged release matches we assume a nightly release
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
            let date = date.checked_add_days(Days::new(1)).unwrap().date_naive();
            let manifest_url = format!(
                "https://static.rust-lang.org/dist/{}/channel-rust-nightly.toml",
                date.format("%Y-%m-%d")
            );
            (Release::Nightly(date), manifest_url)
        }
    };

    let manifest = reqwest::get(manifest_url).await?.text().await?;
    let manifest = manifest.parse::<Table>().unwrap();

    if let Release::Nightly { .. } = release {
        let manifest_commit_hash = &manifest["pkg"]["rustc"]["git_commit_hash"];
        if commit_hash != manifest_commit_hash.as_str().unwrap() {
            bail!("rustc commit hash doesn't match nightly release manifest; either bug or custom rustc build")
        }
    }

    Ok(ReleaseWithManifest {
        release,
        commit_hash: commit_hash.to_owned(),
        manifest,
    })
}

struct ReleaseWithManifest {
    release: Release,
    commit_hash: String,
    /// The rustup manifest.
    manifest: Table,
}

impl ReleaseWithManifest {
    fn rust_std_url(&self) -> Url {
        let target = "x86_64-unknown-linux-gnu"; // TODO: Make this a parameter
        let component = "rust-std";
        self.manifest["pkg"][component]["target"][target]["xz_url"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    fn rust_std_sha256(&self) -> [u8; 32] {
        let target = "x86_64-unknown-linux-gnu"; // TODO: Make this a parameter
        let component = "rust-std";
        let hash_hex = self.manifest["pkg"][component]["target"][target]["xz_hash"]
            .as_str()
            .unwrap();
        let mut ret = [0; 32];
        hex::decode_to_slice(hash_hex, &mut ret).unwrap();
        ret
    }
}

#[derive(Debug)]
enum Release {
    Stable(String),
    // Don't think these are very relevant for our use-case and not even sure if they are archived
    // TODO: Check if they're archived; if yes we can handle them like stable releases probably
    // Beta(String),
    Nightly(NaiveDate),
}

impl Release {
    fn path_name(&self) -> String {
        match self {
            Release::Stable(ver) => format!("rust-std-{}", ver.replace('.', "-")),
            Release::Nightly(date) => format!("rust-std-nightly-{}", date.format("%Y-%m-%d")),
        }
    }
}
