use std::{env, fs, path::PathBuf};

use anyhow::Result;
use clap::{arg, Parser};
use log::*;

use signature_generator::{self as sig_gen};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the FLIRT directory. Needed to get access to `sigmake` and co. If not set signature
    /// generation for IDA will be skipped.
    #[arg(short, long)]
    flair_path: Option<PathBuf>,
    /// Path of binary to generate signatures for
    bin_path: PathBuf,
    /// Output directory
    out_path: Option<PathBuf>,
    /// Keep extracted files (for debugging purposes)
    #[arg(short, long)]
    keep_extracted_files: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info"))
        .format_timestamp(None)
        .format_target(false)
        .init();

    let args = Args::parse();

    let bin = fs::read(args.bin_path)?;
    let (release_manifest, target) = sig_gen::detect_rustc_release(&bin).await?;

    let std_lib = sig_gen::download_std_lib(&release_manifest, target).await?;
    let tmp_dir = sig_gen::extract_object_files_to_tmp_dir(&std_lib, &release_manifest)?;

    let tmp_path = if args.keep_extracted_files {
        let p = tmp_dir.into_path();
        info!("Keeping extracted files at {}", p.display());
        p
    } else {
        tmp_dir.path().to_owned()
    };

    if let Some(flair_path) = args.flair_path {
        sig_gen::ida::generate_signatures_for_std(
            &tmp_path,
            &flair_path,
            &release_manifest,
            &target,
            args.out_path.map(Ok).unwrap_or_else(env::current_dir)?,
        )?;
    }

    Ok(())
}
