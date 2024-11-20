use std::{fs, path::PathBuf, sync::OnceLock};

use pyo3::prelude::*;
use tokio::runtime::Runtime;

use signature_generator::{ida, std_sigs};

fn tokio() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| Runtime::new().unwrap())
}

#[pyfunction]
async fn generate_signature_for_bin(
    bin_path: PathBuf,
    flair_path: PathBuf,
    out_path: PathBuf,
) -> PyResult<PathBuf> {
    let sig_file = tokio()
        .spawn(async move {
            let bin = fs::read(bin_path)?;
            let (release_manifest, target) = std_sigs::detect_rustc_release(&bin).await?;
            let std_lib = std_sigs::download_std_lib(&release_manifest, target).await?;
            let tmp_dir = std_sigs::extract_object_files_to_tmp_dir(&std_lib, &release_manifest)?;

            ida::generate_signatures_for_std(
                tmp_dir.path(),
                &flair_path,
                &release_manifest,
                &target,
                out_path,
            )
        })
        .await
        .unwrap()?;

    Ok(sig_file)
}

#[pymodule]
fn ida_rust_plugin(m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3_log::init();
    m.add_function(wrap_pyfunction!(generate_signature_for_bin, m)?)?;
    Ok(())
}
