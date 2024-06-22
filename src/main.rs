use std::{env, fs, path::PathBuf};

use anyhow::Result;
use clap::{arg, Parser};

use signature_generator as sig_gen;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let bin = fs::read(args.bin_path)?;
    let (release_manifest, target) = sig_gen::detect_rustc_release(&bin).await?;
    let std_lib = sig_gen::download_std_lib(&release_manifest, target).await?;
    let tmp_dir = sig_gen::extract_object_files_to_tmp_dir(&std_lib, &release_manifest)?;

    if let Some(flair_path) = args.flair_path {
        println!("Generating IDA F.L.I.R.T. signatures...");
        sig_gen::ida::generate_signatures(
            &tmp_dir,
            &flair_path,
            &release_manifest,
            args.out_path.map(Ok).unwrap_or_else(env::current_dir)?,
        )?;
    }

    Ok(())
}
