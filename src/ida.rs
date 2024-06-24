use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str,
};

use anyhow::{bail, ensure, Result};
use log::*;
use tempfile::TempDir;

use crate::ReleaseWithManifest;

pub fn generate_signatures(
    tmp_dir: &TempDir,
    flair_path: &Path,
    release_manifest: &ReleaseWithManifest,
    out_dir: PathBuf,
) -> Result<PathBuf> {
    info!("Generating IDA F.L.I.R.T. signatures...");

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
    info!(
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

    std::fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join(format!("{}.sig", release_manifest.release.path_name()));
    std::fs::copy(tmp_dir.path().join("std.sig"), &out_path)?;
    info!("Generated {}", out_path.display());

    // TODO: zipsig?

    Ok(out_path)
}
