use std::{cmp::Ordering, mem};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str,
};

use crate::{ReleaseWithManifest, Target};
use anyhow::{bail, ensure, Result};
use log::*;
use rustc_demangle::Demangle;

pub fn generate_signatures_for_std(
    std_tmp_path: &Path,
    flair_path: &Path,
    release_manifest: &ReleaseWithManifest,
    target: &Target,
    out_dir: PathBuf,
) -> Result<PathBuf> {
    let out_path = out_dir.join(format!(
        "{}.sig",
        release_manifest.release.signature_base_file_name()
    ));
    generate_signatures(
        flair_path,
        std_tmp_path,
        &[std_tmp_path.to_str().unwrap().to_owned() + "/*.o"],
        target,
        &release_manifest.release.signature_base_file_name(),
        &out_path,
    )?;
    Ok(out_path)
}

pub fn generate_signatures(
    flair_path: &Path,
    tmp_path: &Path,
    input_globs: &[String],
    target: &Target,
    library_name: &str,
    out_path: &Path,
) -> Result<()> {
    info!("Generating IDA F.L.I.R.T. signatures...");

    // TODO: Support for running on Windows/macOS host
    let bin_path = flair_path.join("bin/x64linux"); // FIXME: IDA 8.4 path is `bin/linux`; need to check which is available
    ensure!(
        bin_path.exists(),
        "FLAIR directory doesn't seem correct; failed to find `bin/x64linux`"
    );

    let pat_path = tmp_path.join("flirt.pat");
    let sig_path = tmp_path.join("flirt.sig");
    let exc_path = tmp_path.join("flirt.exc");

    let parser = match target {
        Target::X8664LinuxGnu => "pelf",
        Target::X8664LinuxMusl => "pelf",
        Target::X8664WindowsMsvc => "pcf",
        Target::X8664WindowsGnu => "pcf",
    };

    let status = Command::new(bin_path.join(parser))
        .arg("-S") // "split functions inside sections"; Required for Windows MinGW for some reason
        .args(input_globs)
        .arg(&pat_path)
        .stderr(Stdio::null())
        .status()?;
    ensure!(status.success(), "{} failed; non-zero exit code", parser);

    let mut sigmake_command = Command::new(bin_path.join("sigmake"));
    sigmake_command
        .arg(format!("-n{}", library_name))
        .arg(&pat_path)
        .arg(&sig_path);

    let output = sigmake_command.output()?;
    // If successful we have our .sig file; otherwise we need to resolve conflicts and try again
    if !output.status.success() {
        let output_stderr = str::from_utf8(&output.stderr)?;
        info!("sigmake output: {}", output_stderr);
        if output_stderr.contains("NO LIBRARY MODULES ARE FOUND") {
            bail!("Can't generate signatures.")
        }

        let exc = std::fs::read_to_string(&exc_path)?;
        let resolved_exc = resolve_conflicts(&exc);
        std::fs::write(&exc_path, resolved_exc)?;

        // sigmake doesn't emit anything if there were no errors
        let output = sigmake_command.output()?;
        // TODO: This is a workaround for an IDA bug and should be removed in the future; After
        //       conflict resolution sigmake shouldn't be able to fail again...
        if !output.status.success() {
            let output_stderr = str::from_utf8(&output.stderr)?;
            info!("sigmake output: {}", output_stderr);

            let exc = std::fs::read_to_string(&exc_path)?;
            let resolved_exc = resolve_conflicts(&exc);
            std::fs::write(&exc_path, resolved_exc)?;

            let status = sigmake_command.status()?;
            ensure!(status.success(), "sigmake failed; non-zero exit code");
        }
    }

    let output = Command::new(bin_path.join("zipsig"))
        .arg(&sig_path)
        .output()?;
    info!("zipsig output: {}", str::from_utf8(&output.stdout)?.trim());
    ensure!(status.success(), "zipsig failed; non-zero exit code");

    std::fs::create_dir_all(out_path.parent().unwrap())?;
    std::fs::copy(sig_path, out_path)?;
    info!("Generated {}", out_path.display());
    Ok(())
}

fn resolve_conflicts(exc: &str) -> String {
    let mut new_exc = String::new();
    let mut conflicts = 0;
    let mut resolved = 0;
    // Skip first block which just contains instructions for how to resolve conflicts
    'outer: for block in exc.split("\n\n") {
        let mut already_resolved = false;
        let mut candidates = Vec::new();
        for (i, line) in block.lines().enumerate() {
            // Skip instructions block
            if line == ";--------- (delete these lines to allow sigmake to read this file)" {
                continue 'outer;
            }

            // This block is already resolved from a previous run
            if line.starts_with("+") {
                already_resolved = true;
            }

            let raw_sym = line.split("\t").next().unwrap().trim();
            candidates.push(match rustc_demangle::try_demangle(raw_sym) {
                Ok(demangle) => SymbolType::Rust(demangle, i),
                Err(_) => SymbolType::Other(raw_sym, i),
            });
        }

        if already_resolved {
            for l in block.lines() {
                new_exc.push_str(l);
                new_exc.push('\n');
            }
            new_exc.push('\n');
        } else {
            // Our ordering sorts Rust symbols to the beginning
            candidates.sort();

            let selection = match &candidates[..] {
                [sym] => {
                    // TODO: Only one option!? Possibly a sigmake bug? (already reported to kirschju)
                    debug!("Singular conflict: {}", sym.demangled());
                    // We must not select the singular one since it causes sigmake to stop with
                    // conflicts again.
                    // Some(0)
                    None
                }
                // NOTE: Intrinsics are provided by https://github.com/rust-lang/compiler-builtins. (https://github.com/rust-lang/rust/blob/91376f416222a238227c84a848d168835ede2cc3/library/std/Cargo.toml#L20)
                //       Can be useful to understand why certain implementations have the same asm.
                [rs_sym @ SymbolType::Rust(_, rs_idx), rest @ ..]
                    if rs_sym.demangled().starts_with("compiler_builtins::")
                        && rest.iter().all(|s| {
                            if let SymbolType::Other(s, _) = s {
                                s.starts_with("__")
                            } else {
                                false
                            }
                        }) =>
                {
                    Some(*rs_idx)
                }
                candidates
                    if candidates
                        .iter()
                        .all(|s| s.demangled_no_hash() == candidates[0].demangled_no_hash()) =>
                {
                    Some(0)
                }
                _ => {
                    debug!("Unresolved conflicts:");
                    for s in candidates {
                        debug!("{:?}", s);
                    }
                    debug!("---");
                    None
                }
            };

            for (i, l) in block.lines().enumerate() {
                if selection == Some(i) {
                    new_exc.push('+');
                }
                new_exc.push_str(l);
                new_exc.push('\n');
            }
            new_exc.push('\n');

            conflicts += 1;
            if selection.is_some() {
                resolved += 1;
            }
        }
    }

    info!("Resolved {}/{} signature conflicts.", resolved, conflicts);
    new_exc.to_owned()
}

#[derive(Debug)]
enum SymbolType<'a> {
    Rust(Demangle<'a>, usize),
    #[allow(dead_code)]
    Other(&'a str, usize),
}

impl PartialEq for SymbolType<'_> {
    fn eq(&self, other: &Self) -> bool {
        mem::discriminant(self) == mem::discriminant(other)
    }
}

impl Eq for SymbolType<'_> {}

impl PartialOrd for SymbolType<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymbolType<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (SymbolType::Rust(_, _), SymbolType::Rust(_, _)) => Ordering::Equal,
            (SymbolType::Rust(_, _), SymbolType::Other(_, _)) => Ordering::Less,
            (SymbolType::Other(_, _), SymbolType::Rust(_, _)) => Ordering::Greater,
            (SymbolType::Other(_, _), SymbolType::Other(_, _)) => Ordering::Equal,
        }
    }
}

impl SymbolType<'_> {
    fn demangled(&self) -> String {
        match self {
            SymbolType::Rust(demangle, _) => format!("{}", demangle),
            SymbolType::Other(sym, _) => (*sym).to_owned(),
        }
    }

    fn demangled_no_hash(&self) -> String {
        match self {
            SymbolType::Rust(demangle, _) => format!("{:#}", demangle),
            SymbolType::Other(sym, _) => (*sym).to_owned(),
        }
    }
}
