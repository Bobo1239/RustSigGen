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

    let bin_path = flair_path.join("bin/linux");
    if !bin_path.exists() {
        bail!("FLAIR directory doesn't seem correct; failed to find `bin/linux`")
    }

    let pat_path = tmp_dir.path().join("std.pat");
    let sig_path = tmp_dir.path().join("std.sig");
    let exc_path = tmp_dir.path().join("std.exc");

    let status = Command::new(bin_path.join("pelf"))
        .arg(tmp_dir.path().join("*.o"))
        .arg(&pat_path)
        .stderr(Stdio::null())
        .status()?;
    ensure!(status.success(), "pelf failed; non-zero exit code");

    let mut sigmake_command = Command::new(bin_path.join("sigmake"));
    sigmake_command
        .arg(format!("-n{}", release_manifest.release.path_name()))
        .arg(&pat_path)
        .arg(&sig_path);

    // Not checking for exit code here since it will be non-zero on collisions (which we expect)
    let output = sigmake_command.output()?;
    info!(
        "sigmake output: {}",
        str::from_utf8(&output.stderr)?.lines().next().unwrap()
    );

    let exc = std::fs::read_to_string(&exc_path)?;
    // Skipping the first four lines indicates to `sigmake` that we just want to skip the
    // collisions.
    // TODO: We can handle some of the collisions to get better signatures
    let new_exc = exc.lines().skip(4).collect::<Vec<_>>().join("\n");
    std::fs::write(&exc_path, new_exc)?;

    let status = sigmake_command.status()?;
    ensure!(status.success(), "sigmake failed; non-zero exit code");

    let output = Command::new(bin_path.join("zipsig"))
        .arg(&sig_path)
        .output()?;
    info!("zipsig output: {}", str::from_utf8(&output.stdout)?.trim());
    ensure!(status.success(), "zipsig failed; non-zero exit code");

    std::fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join(format!("{}.sig", release_manifest.release.path_name()));
    std::fs::copy(sig_path, &out_path)?;
    info!("Generated {}", out_path.display());

    Ok(out_path)
}
