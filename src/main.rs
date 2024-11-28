use std::{env, fs, path::PathBuf};

use anyhow::Result;
use clap::{Parser, ValueEnum};
use log::*;

use signature_generator::{
    crate_sigs::{self, Context},
    ida, std_sigs, CompilerOptions,
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the FLIRT directory. Needed to get access to `sigmake` and co. If not set signature
    /// generation for IDA will be skipped.
    #[arg(short, long, env = "IDA_FLAIR_PATH")]
    flair_path: Option<PathBuf>,
    /// Keep extracted std files; for debugging `std` mode
    #[arg(short, long)]
    keep_extracted_files: bool,
    /// Only compile specific dependency crate and keep working directory; for debugging `crate`
    /// mode compilation failures; also keeps tmpdir used for dependancy graph expansion if that
    /// failed
    #[arg(short, long)]
    debug_crate: Option<String>,
    #[arg(short, long)]
    /// Output directory for signature files
    out_path: Option<PathBuf>,

    #[command(flatten)]
    compiler_options: CompilerOptions,

    /// TODO
    mode: GenerateSignatureMode,
    /// Path of binary to generate signatures for
    bin_path: PathBuf,
}

#[derive(Debug, Clone, ValueEnum)]
enum GenerateSignatureMode {
    Std,
    Crates,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Enable backtraces by default
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info"))
        .format_timestamp(None)
        .format_target(false)
        .init();

    let args = Args::parse();
    let out_path = args.out_path.map(Ok).unwrap_or_else(env::current_dir)?;

    let bin = fs::read(args.bin_path)?;
    let (release_manifest, target) = std_sigs::detect_rustc_release(&bin).await?;

    match args.mode {
        GenerateSignatureMode::Std => {
            let std_lib = std_sigs::download_std_lib(&release_manifest, target).await?;
            let tmp_dir = std_sigs::extract_object_files_to_tmp_dir(&std_lib, &release_manifest)?;

            let tmp_path = if args.keep_extracted_files {
                let p = tmp_dir.into_path();
                info!("Keeping extracted std files at {}", p.display());
                p
            } else {
                tmp_dir.path().to_owned()
            };

            if let Some(flair_path) = args.flair_path {
                ida::generate_signatures_for_std(
                    &tmp_path,
                    &flair_path,
                    &release_manifest,
                    &target,
                    out_path,
                )?;
            } else {
                warn!("--flair-path not set; not creating signatures...")
            }
        }
        GenerateSignatureMode::Crates => {
            let detected_crates = crate_sigs::detect_used_crates(&bin)?;
            if let Some(flair_path) = args.flair_path {
                let ctx = Context {
                    rust_release: release_manifest.release(),
                    target: &target,
                    out_path: &out_path,
                    ida_flair_path: &flair_path,
                    compiler_options: &args.compiler_options,
                };

                crate_sigs::prepare_toolchain(&ctx)?;
                crate_sigs::generate_signatures_for_crates(
                    &ctx,
                    detected_crates,
                    args.debug_crate.as_deref(),
                )
                .await?;
            } else {
                warn!("--flair-path not set; not creating signatures...")
            }
        }
    }

    Ok(())
}
