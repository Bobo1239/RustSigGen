use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str,
    time::Duration,
};

use anyhow::{ensure, Result};
use chrono::{DateTime, TimeDelta, Utc};
use crates_index::{IndexConfig, SparseIndex, Version};
use crates_io_api::AsyncClient;
use flate2::read::GzDecoder;
use guppy::{
    graph::{
        cargo::{CargoOptions, CargoSet},
        feature::StandardFeatures,
        DependencyDirection,
    },
    platform::{Platform, PlatformSpec, TargetFeatures, Triple},
    MetadataCommand,
};
use indoc::formatdoc;
use log::*;
use regex::bytes::Regex;
use reqwest::ClientBuilder;
use serde::Deserialize;
use tar::Archive;
use tempfile::TempDir;
use toml::Table;

use crate::{caching_http, ida, CompilerOptions, Profile, Release, Target};

// NOTE:
// - In general crates.io doesn't remove any code even when a version is yanked so generally this should work.
// - Cargo registry index docs: https://doc.rust-lang.org/nightly/cargo/reference/registry-index.html
// - Unofficial crates.io API reference: https://github.com/hcpl/crates.io-http-api-reference (unofficial client lib: crates_io_api)
//     - There's no official documentation atm: https://github.com/rust-lang/crates.io/issues/741

// Ideas for improving signatures:
// - Can find more usage examples (=> generic instantiations) by looking at reverse dependencies of
//   the dependencies (e.g. using `crates_io_api`)

// Caveats:
// - Compilation flags need to match for best results (LTO, codegen-units, ...)
// -

// TODO: Also generate signatures for all the `.rlib`s of the sub-dependencies; Idea: Generic functions (for which we don't generate signatures) may still call non-generic functions of sub-dependencies; we can detect those
// TODO: Probably want some kind of safeguarding/sandboxing since compiling crates can run arbitrary code...

static CRATES_IO_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CARGO_PKG_AUTHORS"),
    ")"
);

// Dummy crate name used during dependecy graph creation/expansion
const DUMMY_CRATE_NAME: &str = "rust_sig_gen_dummy_package";

pub struct Context<'a> {
    pub rust_release: &'a Release,
    pub target: &'a Target,
    pub out_path: &'a Path,
    pub ida_flair_path: &'a Path,
    pub compiler_options: &'a CompilerOptions,
}

// Our assumption is that the upload date of the last detected crate version is the date when `cargo
// update` was performed last.
async fn determine_last_cargo_update_date(
    crates: &HashSet<DetectedCrate>,
) -> Result<Option<DateTime<Utc>>> {
    // TODO: We need to split up this json file. The size grows quickly (>10MB) which kills
    //       performance.
    let cache_path = crate::cache_dir().join("crate_versions.json");
    let mut cached = if let Ok(json) = fs::read_to_string(&cache_path) {
        serde_json::from_str::<HashMap<String, Vec<crates_io_api::Version>>>(&json)?
    } else {
        HashMap::new()
    };

    info!("Querying crates.io API for crate version metadata...");
    // Rate limit as requested on https://crates.io/data-access#api
    let client = AsyncClient::new(CRATES_IO_USER_AGENT, Duration::from_millis(1000))?;
    let mut max_date: Option<(DateTime<Utc>, &DetectedCrate)> = None;
    for cratee in crates {
        match &cratee.version {
            DetectedVersion::Release(ver) => {
                if let Some(version) =
                    get_crates_io_version(&mut cached, &client, &cratee.name, ver).await?
                {
                    if max_date
                        .map(|max| version.created_at > max.0)
                        .unwrap_or(true)
                    {
                        max_date = Some((version.created_at, cratee))
                    }
                }
            }
            DetectedVersion::Git(_) => {} // TODO
        }
    }

    if let Some((max_date, cratee)) = max_date {
        info!(
            "Determined date of last `cargo update`: {} ({} {})",
            max_date, cratee.name, cratee.version
        );
    } else {
        warn!("Couldn't determine date of last `cargo update`.");
    }

    let cached_json = serde_json::to_string(&cached)?;
    fs::create_dir_all(cache_path.parent().unwrap())?;
    fs::write(cache_path, cached_json)?;

    Ok(max_date.map(|t| t.0))
}

fn checkout_old_registry_index(date: DateTime<Utc>) -> Result<PathBuf> {
    // TODO: Use gix for everything once it's mature enough:
    //     - https://github.com/Byron/gitoxide/issues/301 (non-exclusive checkout; could probably
    //       already do an exclusive checkout? (into an empty directory; see
    //       gix-worktree-state/tests/state/checkout.rs))
    //     - ...

    let index_current = crate::cache_dir().join("crates.io-index");
    if !index_current.exists() {
        info!("Cloning crates.io-index git repository. This will take a while...");
        let url = gix::url::parse("https://github.com/rust-lang/crates.io-index.git".into())?;
        let mut prepare_clone = gix::prepare_clone(url, &index_current)?;
        let (mut prepare_checkout, _) = prepare_clone
            .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;
        prepare_checkout.main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;
    }

    let index_archive = crate::cache_dir().join("crates.io-index-archive");
    if !index_archive.exists() {
        info!("Cloning crates.io-index-archive git repository. This will take a while...");
        let url =
            gix::url::parse("https://github.com/rust-lang/crates.io-index-archive.git".into())?;
        let mut prepare_clone = gix::prepare_clone(url, &index_archive)?;
        let (mut prepare_checkout, _) = prepare_clone
            .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;
        prepare_checkout.main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;
    }

    // Update repos
    info!("Updating crates.io indices...");
    exec_cmd(Command::new("git").current_dir(&index_current).arg("fetch"))?;
    exec_cmd(Command::new("git").current_dir(&index_archive).arg("fetch"))?;

    // Determine which repository/branch we need to look at
    let branches = Command::new("git")
        .current_dir(&index_archive)
        .arg("branch")
        .arg("--remote")
        .output()?;
    let branches = String::from_utf8(branches.stdout)?;
    let snapshot_branches: Vec<_> = branches
        .lines()
        .map(|s| s.trim())
        .filter(|s| s.starts_with("origin/snapshot-"))
        .collect();

    let mut snapshots = Vec::new();
    for branch in &snapshot_branches {
        let output = Command::new("git")
            .current_dir(&index_archive)
            .arg("log")
            .arg("-1")
            .arg("--format=%cI")
            .arg(branch)
            .output()?;
        let last_commit_date = String::from_utf8(output.stdout)?;
        let last_commit_date =
            DateTime::parse_from_rfc3339(last_commit_date.trim())?.with_timezone(&Utc);
        snapshots.push((last_commit_date, branch));
    }
    snapshots.sort_unstable(); // Probably not needed...

    let snapshot_idx = match snapshots.binary_search_by_key(&date, |snap| snap.0) {
        Ok(idx) => Some(idx),
        Err(idx) => {
            if idx == snapshots.len() {
                // Binary search found that the date is newer than the last snapshot
                // => we need to look at the current index and not a snapshot
                None
            } else {
                Some(idx)
            }
        }
    };

    let (index, branch) = match snapshot_idx {
        Some(idx) => (index_archive, *snapshots[idx].1),
        None => (index_current, "origin/master"),
    };

    // Find last commit before our cutoff time
    let output = Command::new("git")
        .current_dir(&index)
        .arg("log")
        .arg("-1")
        .arg("--format=%cI %H")
        .arg(format!("--until={}", date))
        .arg(branch)
        .output()?;
    let date_and_commit = String::from_utf8(output.stdout)?;
    let (commit_date, commit) = date_and_commit.trim().split_once(" ").unwrap();
    let commit_date = DateTime::parse_from_rfc3339(commit_date)?.with_timezone(&Utc);

    // Sanity check that the commit date is plausible
    assert!(date - commit_date < TimeDelta::hours(1));

    info!(
        "Checking out {} to commit {commit} ({commit_date})",
        index.file_name().unwrap().to_str().unwrap()
    );
    exec_cmd(
        Command::new("git")
            .current_dir(&index)
            .args(["-c", "advice.detachedHead=false"])
            .arg("reset")
            .arg("--hard")
            .arg(commit),
    )?;

    Ok(index)
}

fn generate_cargo_toml_content(crates: &HashSet<DetectedCrate>) -> String {
    // TODO: Select edition based on rustc release
    let mut ret = formatdoc! {r#"
        [package]
        name = "{DUMMY_CRATE_NAME}"
        version = "0.1.0"
        # edition = "2021"

        [dependencies]"#
    };
    ret.push('\n');

    let mut counter = 0;
    let mut added_crates = Vec::new();
    for c in crates {
        match &c.version {
            DetectedVersion::Release(ver) => {
                // Discard compatible versions of a specific crate since they can't appear in the same
                // package graph. This should only occur with crates which are shipped as part of std and
                // are thus not resolved by Cargo. Compatibility is defined at
                // https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility as the case
                // where the left-most non-zero version component is equal.
                // TODO: This could be improve by keeping the version which is not part of std instead of
                //       the first version we encounter.
                if added_crates.iter().any(|added: &&DetectedCrate| {
                    added.name == c.name && {
                        let DetectedVersion::Release(added_version) = &added.version else {
                            return false;
                        };
                        let DetectedVersion::Release(c_version) = &c.version else {
                            return false;
                        };
                        let ver0 = guppy::Version::parse(added_version).unwrap();
                        let ver1 = guppy::Version::parse(c_version).unwrap();
                        if ver0.major != 0 {
                            ver0.major == ver1.major
                        } else if ver0.minor != 0 {
                            ver0.minor == ver1.minor
                        } else if ver0.patch != 0 {
                            ver0.patch == ver1.patch
                        } else {
                            true
                        }
                    }
                }) {
                    info!("Skipping {} {} since there's already a semver-compatible version in the package graph", c.name, c.version);
                    continue;
                }

                // NOTE: Strictly speaking we need `default-features = false` here...
                ret += &format!(
                    r#"crate{} = {{ package = "{}", version = "={}", features = [{}] }}"#,
                    counter,
                    c.name,
                    ver,
                    match &c.features {
                        None => "".to_owned(),
                        Some(feats) =>
                            if feats.is_empty() {
                                "".to_owned()
                            } else {
                                format!("\"{}\"", feats.join("\",\""))
                            },
                    }
                );
                counter += 1;
                ret += "\n";
                added_crates.push(c);
            }
            DetectedVersion::Git(_) => { // TODO
            }
        }
    }

    ret
}

fn determine_transitive_dependencies_and_max_features_inner(
    ctx: &Context,
    cwd: &Path,
    crates: HashSet<DetectedCrate>,
) -> Result<(HashSet<DetectedCrate>, bool)> {
    let cargo_toml_path = cwd.join("Cargo.toml");

    info!("Checking if crates can be compiled (may take a long time on first run)");
    let cargo_toml_content = generate_cargo_toml_content(&crates);
    fs::write(&cargo_toml_path, &cargo_toml_content)?;
    debug!("{}", &cargo_toml_content);

    // for v in std::env::vars() {
    //     println!("{:?}", v);
    // }

    let mut cmd = Command::new("cargo");
    // FIXME: Deduplicate common flags/envs
    cmd
        // When running the signature generator using `cargo run`/`just run` the `CARGO` env var
        // will be set and somehow that can propagate to the inner invocation which then fails with
        // weird errors like: "error: the `-Z unstable-options` flag must also be passed to enable
        // the flag `check-cfg`"
        .env_remove("CARGO")
        // NOTE: This is currently a hack which enables crate source code to use nightly features
        //       even when the compiler isn't actually a nightly release. This is required for these
        //       reasons:
        //       - We accidentally enable create features which are only intended for nightly
        //         compilers
        //       - Some projects use nightly features for development targets (e.g. benches)
        //       Using this env var is actually strongly discouraged by the compiler developers
        //       since it breaks the stability guarantees of Rust but for what we're doing all hope
        //       is lost anyways...
        .env("RUSTC_BOOTSTRAP", "1")
        // Use the git CLI instead of libgit2 which has performance problems:
        // https://github.com/rust-lang/cargo/issues/11014
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
        .env("XWIN_ARCH", "x86,x86_64")
        // This is sometimes required for successful compilation. Dunno why exactly...
        // (https://github.com/rust-cross/cargo-xwin/pull/123)
        // TODO: The PR is not yet in a published release of cargo-xwin.
        .env("XWIN_INCLUDE_DEBUG_SYMBOLS", "true")
        .current_dir(cwd)
        .arg(format!("+{}", ctx.rust_release.name()))
        // We need although we're only doing a check run (no code generation) due to build scripts.
        // Specifically we need this to successfully cross-compile `ring` for msvc targets.
        .arg("xwin")
        .arg("check")
        .arg("--target")
        .arg(ctx.target.name())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let output = cmd.output()?;
    ensure!(
        output.status.success(),
        "cargo check failed:\n{}\n{:?}",
        String::from_utf8_lossy(&output.stderr),
        cmd
    );

    // TODO: This is still fraught with peril... consider e.g. flate2 (different selectable backends)
    let feature_filter = |cratee: &str, all_features: &[&str], feature: &str| {
        // Note the `!` here...
        !match (cratee, feature) {
            // Slightly awkward `match` here since we want to ensure that we run into the last case
            // if none of the above match.
            ("log" | "tracing", f)
                if f.starts_with("max_level_") || f.starts_with("release_max_level_") =>
            {
                true
            }
            ("ahash", "compile-time-rng") => true,
            ("hashbrown", "ahash-compile-time-rng") => true,
            ("flate2", _) => true, // flate2 supports different backends selectable via features
            ("object", f) if f != "all" => true, // `object`` doesn't support --all-features but instead offers an `all` feature
            ("hyper", "ffi") => true,
            ("rand", "packed_simd") => true,
            ("rand", "simd_support") => true,
            ("libm", "musl-reference-tests") => true,
            ("parking_lot", "deadlock_detection" | "send_guard") => true, // Incompatible features; and most likely not enabled anyway
            ("futures-util", "bilock") => true, // Requires `unstable` feature which we filter out
            ("getrandom", "test-in-browser") => true,
            ("path-dedot" | "path-absolutize", _) => true, // Multiple conflicting cache implementations
            ("once_cell", "parking_lot") => true,
            ("parking_lot", "stdweb" | "wasm-bindgen") => true,
            ("instant", "js-sys" | "stdweb" | "wasm-bindgen" | "wasm-bindgen_rs" | "web-sys") => {
                true
            }
            ("encoding_rs", "simd-accel" | "any_all_workaround") => true,
            // # Only enable default features
            // Multiple backends; Unfortunately old versions default to the Windows-incompatible
            // "termion" backend so even the very first check above fails...
            ("tui", f) if f != "default" => true,
            // These are optional dependencies for the `rustc-dep-of-std` feature which break normal compilation
            (_, f)
                if all_features.contains(&"rustc-dep-of-std")
                    && ["core", "alloc", "std", "compiler_builtins"].contains(&f) =>
            {
                true
            }
            (_, "alloc") if all_features.contains(&"std") => true, // Dont enable alloc feature if `std` is present
            (_, "no-panic") => true, // no-panic is a crate which (ab)uses the linker causing sigmake to fail
            _ => {
                feature == "rustc-dep-of-std" // Only used by rustc
                || feature.starts_with("__") // Internal features
                || feature == "no_std" // Intended for no_std (this pattern is actually discouraged by Cargo since it isn't additive)
                || feature == "unstable" // Often require nightly
                    || (!ctx.rust_release.is_nightly() && feature.contains("nightly"))
                // These presumably don't compile on a stable toolchains
            }
        }
    };

    let mut cargo_opts = CargoOptions::new();
    cargo_opts.set_target_platform(PlatformSpec::from(Platform::from_triple(
        Triple::new(ctx.target.name())?,
        TargetFeatures::Unknown,
    )));

    let package_graph = MetadataCommand::new()
        .current_dir(cwd)
        .build_graph()
        .unwrap();

    let initials = package_graph
        .resolve_workspace()
        .to_feature_set(StandardFeatures::Default);
    let features_only = package_graph
        .resolve_none()
        .to_feature_set(StandardFeatures::Default);
    let cargo_set = CargoSet::new(initials, features_only, &cargo_opts)?;

    // TODO: Do this more granularly since currenctly one bad feature will reset us completely.

    let mut new_crates = HashSet::<DetectedCrate>::new();
    for p in cargo_set
        .target_features()
        .packages_with_features(DependencyDirection::Forward)
    {
        if p.package().name() == DUMMY_CRATE_NAME {
            continue;
        }

        let p = p.package();
        let all_features: Vec<_> = p.named_features().collect();
        let new_crate = DetectedCrate {
            name: p.name().to_owned(),
            version: DetectedVersion::Release(p.version().to_string()),
            features: Some(
                all_features
                    .iter()
                    .filter(|f| feature_filter(p.name(), &all_features, f))
                    .map(|s| (*s).to_owned())
                    .collect(),
            ),
        };
        new_crates.insert(new_crate);
        // println!("{}", p.name());
        // for f in p.named_features() {
        //     println!("  {}", f);
        // }
    }

    if new_crates == crates {
        // We've reached a fixed point
        info!("Reached fixed point for dependency graph");
        Ok((crates, true))
    } else {
        info!("Extended dependency graph");
        // Recursive call to try extending again; will also check if the current extension even
        // compiles
        match determine_transitive_dependencies_and_max_features_inner(ctx, cwd, new_crates) {
            Ok(crates) => Ok(crates),
            Err(e) => {
                warn!("Failed to extend dependency graph: {}", e);
                // Return crates before extension
                Ok((crates, false))
            }
        }
    }
}

fn determine_transitive_dependencies_and_max_features(
    ctx: &Context,
    old_registry_index: &Option<PathBuf>,
    crates: HashSet<DetectedCrate>,
    keep_tmpdir_on_fail: bool,
) -> Result<HashSet<DetectedCrate>> {
    let tmpdir = TempDir::new()?;

    // Create empty `main.rs` which is required
    fs::create_dir(tmpdir.path().join("src"))?;
    fs::write(tmpdir.path().join("src/main.rs"), "fn main() {}")?;

    // TODO: Deduplicate code
    if let Some(old_registry_index) = old_registry_index {
        let cargo_config_no_ext = tmpdir.path().join(".cargo").join("config");
        let cargo_config_with_ext = tmpdir.path().join(".cargo").join("config.toml");
        let cargo_config = if cargo_config_no_ext.exists() {
            // Legacy name but has priority (https://doc.rust-lang.org/cargo/reference/config.html#hierarchical-structure)
            cargo_config_no_ext
        } else {
            cargo_config_with_ext
        };

        let mut cargo_config_content = fs::read_to_string(&cargo_config).unwrap_or(String::new());
        cargo_config_content.push_str(&formatdoc!(
            r#"
            [source.crates-io]
            replace-with = "crates-io-from-the-past"

            [source.crates-io-from-the-past]
            registry = "file://{}"
            "#,
            old_registry_index.display()
        ));
        fs::create_dir_all(cargo_config.parent().unwrap())?;
        fs::write(&cargo_config, cargo_config_content)?;
    }

    let ret = determine_transitive_dependencies_and_max_features_inner(ctx, tmpdir.path(), crates);
    // Two possibilities:
    // - Initial compilation already fails (incidated by `Err` variant)
    // - Or one of the exapansion steps failed (incidated by `Ok` variant with `false` in tuple)
    if keep_tmpdir_on_fail && (ret.is_err() || matches!(ret, Ok((_, false)))) {
        info!("Keeping tmpdir at {}", tmpdir.into_path().display());
    }
    ret.map(|(c, _)| c)
}

pub async fn generate_signatures_for_crates(
    ctx: &Context<'_>,
    crates: HashSet<DetectedCrate>,
    debug_crate_compilation: Option<&str>,
) -> Result<()> {
    let last_cargo_update_date = determine_last_cargo_update_date(&crates).await?;
    let old_registry_index = last_cargo_update_date
        .map(|date| {
            checkout_old_registry_index(
                // Add a small time delta so we don't miss the very index update which led us to
                // this `date`.
                date.checked_add_signed(TimeDelta::minutes(1)).unwrap(),
            )
        })
        .transpose()?;

    let crates = determine_transitive_dependencies_and_max_features(
        ctx,
        &old_registry_index,
        crates,
        debug_crate_compilation.is_some(), // `keep_tmpdir_on_fail: bool`; not really clean...
    )?;
    info!("Crates planned for signature generation:");
    for c in &crates {
        info!("  - {} {} (features: {:?})", c.name, c.version, c.features);
    }

    let mut index = SparseIndex::new_cargo_default()?;
    let index_config = IndexConfig {
        dl: "https://crates.io/api/v1/crates".to_owned(),
        api: None,
    };

    let mut failed_crates = Vec::new();
    let mut skipped_benches_crates = Vec::new();
    let mut used_default_features_crates = Vec::new();
    for cratee in crates {
        if let Some(c) = debug_crate_compilation {
            if cratee.name != c {
                continue;
            }
        }

        match &cratee.version {
            DetectedVersion::Release(ver) => {
                // First check if crate is already known in local sparse index; If not update local
                // index and check again
                let index_crate = match find_sparse_index(&mut index, &cratee.name, ver) {
                    Some(c) => c,
                    None => {
                        update_sparse_index(&mut index, &cratee.name).await?;
                        match find_sparse_index(&mut index, &cratee.name, ver) {
                            Some(c) => c,
                            None => {
                                error!(
                                    "Crate couldn't be found on crates.io: {} {}",
                                    cratee.name, ver
                                );
                                continue;
                            }
                        }
                    }
                };
                info!(
                    "Compiling crate {} {}",
                    index_crate.name(),
                    index_crate.version(),
                );

                let crate_tarball_path = caching_http::download_file(
                    index_crate.download_url(&index_config).unwrap(),
                    Some(*index_crate.checksum()),
                )
                .await?;

                let mut tmp_dir = TempDir::new()?;
                let tar_gz = File::open(crate_tarball_path)?;
                let tar = GzDecoder::new(tar_gz);
                let mut archive = Archive::new(tar);
                archive.unpack(&tmp_dir)?;

                let mut subdirs = fs::read_dir(tmp_dir.path())?;
                let mut crate_dir = subdirs.next().unwrap()?.path();
                assert!(crate_dir.is_dir());
                assert!(
                    subdirs.next().is_none(),
                    "encountered more than one directory unpacked from crate tarball"
                );

                // TODO: Move out; Also catch errors
                // NOTE: `.cargo_vcs_info.json` was added in Cargo 1.30 (2018-10-25)
                // https://github.com/rust-lang/cargo/blob/master/CHANGELOG.md#cargo-130-2018-10-25
                let vcs_info = std::fs::read_to_string(crate_dir.join(".cargo_vcs_info.json")).ok();
                if let Some(vcs_info) = vcs_info {
                    let cargo_toml = std::fs::read_to_string(crate_dir.join("Cargo.toml"))?;
                    let cargo_toml = toml::from_str::<Table>(&cargo_toml)?;
                    let Some(toml::Value::String(mut repo_url)) =
                        cargo_toml["package"].get("repository").cloned()
                    else {
                        continue;
                    };

                    // Reference for allowed names: https://github.com/dead-claudia/github-limits
                    let gh_url_regex = regex::Regex::new(
                        r#"https://(www\.)?github\.com/[[:alnum:]\-]+/[[:alnum:].\-_]+/"#,
                    )?;
                    if let Some(gh_url) = gh_url_regex
                        .captures(&repo_url)
                        .map(|capture| capture[0].to_owned())
                    {
                        repo_url = gh_url;
                    }

                    #[derive(Debug, Deserialize)]
                    struct CargoVcsInfo {
                        git: CargoVcsInfoGit,
                        // NOTE: This field was added in Cargo 1.57 (2021-12-02)
                        // https://github.com/rust-lang/cargo/blob/master/CHANGELOG.md#cargo-157-2021-12-02
                        path_in_vcs: Option<String>,
                    }
                    #[derive(Debug, Deserialize)]
                    struct CargoVcsInfoGit {
                        sha1: String,
                    }
                    let info: CargoVcsInfo = serde_json::from_str(&vcs_info)?;

                    let crate_checkout = tempfile::tempdir()?;

                    let try_clone = || -> Result<()> {
                        // TODO: Some crates share the same repo and are cloned multiple times which could be optimized (e.g. windows-rs)
                        info!("Cloning {} @ {}", repo_url, info.git.sha1);
                        // TODO: Extract function
                        let url = gix::url::parse(repo_url.as_bytes().into())?;
                        let mut prepare_clone = gix::prepare_clone(url, crate_checkout.path())?;
                        let (mut prepare_checkout, _) = prepare_clone.fetch_then_checkout(
                            gix::progress::Discard,
                            &gix::interrupt::IS_INTERRUPTED,
                        )?;
                        prepare_checkout.main_worktree(
                            gix::progress::Discard,
                            &gix::interrupt::IS_INTERRUPTED,
                        )?;

                        // NOTE: Sometimes a commit hash is referenced which is not part of the main
                        //       history (not sure how that happenes exactly; maybe manual git
                        //       merge?) For example
                        //       https://github.com/RustCrypto/block-ciphers/commit/e39cf00f1b6de69623aa48c403bef5a9104aab8d;
                        //       In this case we need to manually fetch the commit before we can
                        //       checkout
                        exec_cmd(
                            Command::new("git")
                                .current_dir(&crate_checkout)
                                .arg("fetch")
                                .arg("origin")
                                .arg(&info.git.sha1),
                        )?;
                        exec_cmd(
                            Command::new("git")
                                .args(["-c", "advice.detachedHead=false"])
                                .current_dir(&crate_checkout)
                                .arg("reset")
                                .arg("--hard")
                                .arg(&info.git.sha1),
                        )?;

                        // TODO: For crates which are missing `path_in_vcs` we should be able to
                        //       find the correct crate subdirectory in the repo
                        crate_dir = crate_checkout
                            .path()
                            .join(info.path_in_vcs.as_deref().unwrap_or(""));
                        tmp_dir = crate_checkout;

                        Ok(())
                    };

                    if let Err(e) = try_clone() {
                        error!("Cloning failed: {}", e);
                        error!("Falling back to crates.io source tarball...")
                    }
                }

                // Benches are a very common compilation error source since they often depend on
                // nightly features and are handled somewhat special by cargo. (one example: resvg
                // fails to compile with `cargo build --all-targets` since the bencher dependency
                // somehow doesn't get included by cargo)
                // So to sidestep that first try without skipping benches. If that fails skip them.
                let mut skipped_benches = false;
                let mut used_default_features = false;
                let mut gen_sigs = |skip_benches: bool, use_default_features: bool| {
                    skipped_benches = skip_benches;
                    used_default_features = use_default_features;
                    compile_crate_and_generate_signatures(
                        ctx,
                        &cratee,
                        &crate_dir,
                        &old_registry_index,
                        skip_benches,
                        use_default_features,
                    )
                };

                if let Err(e) = gen_sigs(false, false)
                    .or_else(|_| gen_sigs(true, false))
                    .or_else(|_| gen_sigs(true, true))
                {
                    failed_crates.push(cratee);
                    error!(
                        "Failed to generate signatures for {} {}: {}\n{}",
                        index_crate.name(),
                        index_crate.version(),
                        e,
                        e.backtrace()
                    );
                } else if used_default_features {
                    used_default_features_crates.push(cratee);
                } else if skipped_benches {
                    skipped_benches_crates.push(cratee);
                }

                if debug_crate_compilation.is_some() {
                    error!("Debug crate tmpdir is at {}", crate_dir.display());
                    std::process::exit(0); // Skips destructors ( => tmpdir remains)
                }
            }
            DetectedVersion::Git(commit) => {
                // TODO: Could use something like GitHub search: `hashbrown hash:f677701` but don't
                //       know if it's a good idea to do this automatically...``
                error!(
                    "Currently unimplemented Git dependency: {} {}",
                    &cratee.name, commit
                );
            }
        }
    }

    if !failed_crates.is_empty() {
        error!("Failed to generate signatures for:");
        for failed in failed_crates {
            error!("- {} {}", failed.name, failed.version);
        }
        error!("Check the log for further details.");
    }

    if !skipped_benches_crates.is_empty() {
        warn!("Had to skip benches compilation for:");
        for skipped in skipped_benches_crates {
            warn!("- {} {}", skipped.name, skipped.version);
        }
        warn!("Check the log for further details.");
    }

    if !used_default_features_crates.is_empty() {
        warn!("Had to use default features (and skip benches compilation) for:");
        for used_default in used_default_features_crates {
            warn!("- {} {}", used_default.name, used_default.version);
        }
        warn!("Check the log for further details.");
    }

    Ok(())
}

async fn get_crates_io_version(
    cached: &mut HashMap<String, Vec<crates_io_api::Version>>,
    client: &AsyncClient,
    name: &str,
    version: &str,
) -> Result<Option<crates_io_api::Version>> {
    // If we already know the crates.io metadata for the requested version just return that...
    if let Some(v) = cached
        .get(name)
        .and_then(|versions| versions.iter().find(|v| v.num == version))
    {
        debug!("  {} {} (cached)", name, version);
        return Ok(Some(v.clone()));
    }

    // ...otherwise try to get fresh data
    let versions = client.get_crate(name).await?.versions;
    let ret = versions.iter().find(|v| v.num == version).cloned();
    cached.insert(name.to_owned(), versions);

    debug!("  {} {}", name, version);
    Ok(ret)
}

fn compile_crate_and_generate_signatures(
    ctx: &Context,
    cratee: &DetectedCrate,
    crate_dir: &Path,
    old_registry_index: &Option<PathBuf>,
    skip_benches: bool,
    use_default_features: bool,
) -> Result<()> {
    // Setup a Cargo "source replacement" to use the the crate registry index at an old state. This
    // is our best-effort attempt at replicating the Cargo.lock of the actual binary.
    // Reference: https://doc.rust-lang.org/cargo/reference/source-replacement.html
    // The "source replacement" feature exists since 2016 at least
    // (https://github.com/rust-lang/cargo/issues/3066)

    if let Some(old_registry_index) = old_registry_index {
        let cargo_config_no_ext = crate_dir.join(".cargo").join("config");
        let cargo_config_with_ext = crate_dir.join(".cargo").join("config.toml");
        let cargo_config = if cargo_config_no_ext.exists() {
            // Legacy name but has priority (https://doc.rust-lang.org/cargo/reference/config.html#hierarchical-structure)
            cargo_config_no_ext
        } else {
            cargo_config_with_ext
        };

        let mut cargo_config_content = fs::read_to_string(&cargo_config).unwrap_or(String::new());
        // Our source replacement may already exist from a previous try
        if !cargo_config_content.contains("crates-io-from-the-past") {
            cargo_config_content.push_str(&formatdoc!(
                r#"
                [source.crates-io]
                replace-with = "crates-io-from-the-past"

                [source.crates-io-from-the-past]
                registry = "file://{}"
                "#,
                old_registry_index.display()
            ));
            fs::create_dir_all(cargo_config.parent().unwrap())?;
            fs::write(&cargo_config, cargo_config_content)?;
        }
    }

    // NOTE: This will copy our old registry index to the cargo cache directory...
    exec_cmd(
        Command::new("cargo")
            .current_dir(crate_dir)
            // Use the git CLI instead of libgit2 which has performance problems:
            // https://github.com/rust-lang/cargo/issues/11014
            .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
            .arg(format!("+{}", ctx.rust_release.name()))
            .arg("update"),
    )?;

    let mut cmd = Command::new("cargo");

    cmd.current_dir(crate_dir)
        // Set lint cap level to the lowest possible value which effectively disables all
        // warnings. We need this since some projects run with `#[deny(warnings)]` which may
        // cause our build to fail.
        // Reference: https://doc.rust-lang.org/rustc/lints/levels.html#capping-lints
        // NOTE: Enabling `--cap-lints allow` causes the following error to be thrown when
        //       compiling for musl:
        //       `error: output of --print=file-names missing when learning about target-specific information from rustc`
        // NOTE: Can't use this for all targets due to
        //       https://github.com/rust-lang/cargo/issues/8010. Fortunately this isn't a
        //       must-have anymore since we can time-travel for the registry index.
        // .env("RUSTFLAGS", "--cap-lints allow")
        .env_remove("CARGO")
        .env("RUSTC_BOOTSTRAP", "1")
        .env("CARGO_TARGET_DIR", "./target") // Override target dir so we don't need to pay attention to workspaces
        .env("RUSTFLAGS", "--emit=obj") // TODO: Docs
        .env("XWIN_ARCH", "x86,x86_64")
        // This is sometimes required for successful compilation. Dunno why exactly...
        // (https://github.com/rust-cross/cargo-xwin/pull/123)
        // TODO: The PR is not yet in a published release of cargo-xwin.
        .env("XWIN_INCLUDE_DEBUG_SYMBOLS", "true")
        .arg(format!("+{}", ctx.rust_release.name()))
        .arg("xwin")
        .arg("build")
        .arg("--target")
        .arg(ctx.target.name());

    // NOTE: Can't use `--profile <dev,release>` since that was only introduced in Cargo 1.57
    //       (2021-12-02).
    match ctx.compiler_options.profile {
        Profile::Dev => {} // This is already the default profile
        Profile::Release => {
            cmd.arg("--release");
        }
    }

    if !use_default_features {
        match &cratee.features {
            // TODO: Use `--no-default-features` here before listing our features...
            // TODO: Currently this may still miss features activated by other features which are enabled in the final dependency graph; Need to query guppy for activated features (ideally for the specific target platform)
            Some(feats) => cmd.arg("--features").arg(feats.join(",")),
            None => cmd.arg("--all-features"),
        };
    }

    if skip_benches {
        cmd.arg("--lib")
            .arg("--bins")
            .arg("--tests")
            .arg("--examples");
    } else {
        cmd.arg("--all-targets");
    }

    // Apply user-selected compiler options via environment variables
    // NOTE: This is supported since Cargo 1.43 (2020-04-23)
    let env_var_prefix = match ctx.compiler_options.profile {
        Profile::Dev => "CARGO_PROFILE_DEV_",
        Profile::Release => "CARGO_PROFILE_RELEASE_",
    };
    let options = [
        (
            "CODEGEN_UNITS",
            ctx.compiler_options.codegen_units.map(|o| o.to_string()),
        ),
        (
            "LTO",
            ctx.compiler_options
                .lto
                .as_ref()
                .map(|o| o.value().to_owned()),
        ),
        (
            "OPT_LEVEL",
            ctx.compiler_options
                .opt_level
                .as_ref()
                .map(|o| o.value().to_owned()),
        ),
        // Explicitly disable symbol stripping; Although this probably isn't set anyways...
        // TODO: This option was introduced in in Rust 1.59 (Feb. 24, 2022) so we mustn't enable it
        //       for older releases.
        // ("STRIP", Some("none".to_owned())),
    ];
    for (opt, opt_val) in options {
        if let Some(val) = opt_val {
            cmd.env(format!("{env_var_prefix}{opt}"), val);
        }
    }

    exec_cmd(&mut cmd)?;

    let target_dir = crate_dir
        .join("target")
        .join(ctx.target.name())
        .join(ctx.compiler_options.profile.target_subdir());

    let mut input_globs = Vec::new();
    for subdir in ["", "deps", "examples"] {
        // Subdirs reference: https://doc.rust-lang.org/cargo/guide/build-cache.html
        let dir = &target_dir.join(subdir);
        // We have to check this explicitly here since `pelf` fails if the glob matches nothing
        if fs::read_dir(dir)?.any(|f| f.unwrap().file_name().as_encoded_bytes().ends_with(b".o")) {
            input_globs.push(dir.to_str().unwrap().to_owned() + "/*.o");
        }
    }

    let sig_name = format!("{}-{}", cratee.name, cratee.version);
    let sig_file_name = format!("{}.sig", sig_name);
    std::fs::create_dir_all(ctx.out_path)?;
    let sig_out_path = ctx.out_path.join(sig_file_name);
    ida::generate_signatures(
        ctx.ida_flair_path,
        &target_dir,
        &input_globs,
        ctx.target,
        &sig_name,
        &sig_out_path,
    )?;

    Ok(())
}

fn exec_cmd(cmd: &mut Command) -> Result<()> {
    ensure!(cmd.status()?.success(), "failed command: {:?}", cmd);
    Ok(())
}

pub fn prepare_toolchain(ctx: &Context) -> Result<()> {
    exec_cmd(Command::new("rustup").args([
        "toolchain",
        "install",
        "--profile",
        "minimal",
        &ctx.rust_release.name(),
    ]))?;
    exec_cmd(Command::new("rustup").args([
        "target",
        "add",
        "--toolchain",
        &ctx.rust_release.name(),
        ctx.target.name(),
    ]))?;
    Ok(())
}

pub fn detect_used_crates(bin: &[u8]) -> Result<HashSet<DetectedCrate>> {
    // https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
    // (changed to non-capturing groups)
    let semver_re = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?";

    // Registry is usually either `github.com-1ecc6299db9ec823` (old) or
    // `index.crates.io-6f17d22bba15001f` (new sparse index)
    // Registry names contains a hash: https://users.rust-lang.org/t/where-does-6f17d22bba15001f-come-from-in-index-crates-io-6f17d22bba15001f
    // The first part (`cargo/registry/src`) isn't always present for some reason...; Example:
    // https://hackropole.fr/en/challenges/reverse/fcsc2024-reverse-archiver/ only has
    // `index.crates.io-6f17d22bba15001f/clap_lex-0.7.0/...`
    // In the future this may change even more: https://rust-lang.github.io/rfcs/3127-trim-paths.html
    let registry_re = Regex::new(&format!(
        r"(?:cargo[/\\]registry[/\\]src[/\\])?[A-Za-z0-9_\-.]+-[[:xdigit:]]{{16}}[/\\]([A-Za-z0-9_\-.]+)-({semver_re})[/\\]"
    ))?;
    let mut crates: HashSet<_> = registry_re
        .captures_iter(bin)
        .map(|m| {
            let (_, [name, version]) = m.extract();
            DetectedCrate {
                name: str::from_utf8(name).unwrap().to_owned(),
                version: DetectedVersion::Release(str::from_utf8(version).unwrap().to_owned()),
                features: None,
            }
        })
        .collect();

    let git_re = Regex::new(
        r"(?:cargo[/\\]git[/\\]checkouts[/\\])?([A-Za-z0-9_\-]+)-[[:xdigit:]]{16}[/\\]([[:xdigit:]]{7})[/\\]",
    )?;
    let git_crates: HashSet<_> = git_re
        .captures_iter(bin)
        .map(|m| {
            let (_, [name, commit]) = m.extract();
            DetectedCrate {
                name: str::from_utf8(name).unwrap().to_owned(),
                version: DetectedVersion::Git(str::from_utf8(commit).unwrap().to_owned()),
                features: None,
            }
        })
        .collect();

    crates.extend(git_crates);

    if crates.is_empty() {
        warn!("Failed to detect any crate dependencies...");
    } else {
        info!("Detected crates:");
        for cratee in &crates {
            info!("  - {} {}", cratee.name, cratee.version);
        }
    }

    Ok(crates)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DetectedCrate {
    name: String,
    version: DetectedVersion,
    // NOTE: If `features` is `None` (when crate graph expansion fails) we will fall back to using
    //       `--all-features` during crate compilation
    features: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectedVersion {
    Release(String),
    Git(String),
}

impl Display for DetectedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DetectedVersion::Release(s) => s,
            DetectedVersion::Git(s) => s,
        })
    }
}

fn find_sparse_index(index: &mut SparseIndex, crate_name: &str, version: &str) -> Option<Version> {
    let cratee = index.crate_from_cache(crate_name).ok()?;
    cratee
        .versions()
        .iter()
        .find(|&v| v.version() == version)
        .cloned()
}

// TODO: Could probably do this in parallel using HTTP/2 (but probably not needed)
async fn update_sparse_index(index: &mut SparseIndex, crate_name: &str) -> Result<()> {
    let req = index.make_cache_request(crate_name)?.body(())?;
    let req: reqwest::Request = req.map(|()| reqwest::Body::default()).try_into()?;

    let client = ClientBuilder::new()
        .gzip(true) // On by default but this ensures that the requisite crate feature is enabled
        .build()?;
    let res = client.execute(req).await?;

    let mut res_builder = http::Response::builder()
        .status(res.status())
        .version(res.version());
    res_builder
        .headers_mut()
        .unwrap()
        .extend(res.headers().iter().map(|(k, v)| (k.clone(), v.clone())));

    let body = res.bytes().await?;
    let res = res_builder.body(body.to_vec())?;

    index.parse_cache_response(crate_name, res, true)?;

    Ok(())
}
