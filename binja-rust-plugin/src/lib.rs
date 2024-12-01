use std::{fs, path::PathBuf, sync::OnceLock};

use pyo3::prelude::*;
use tokio::runtime::Runtime;

use rust_sig_gen::std_sigs;

fn tokio() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| Runtime::new().unwrap())
}

#[pyfunction]
async fn download_rust_std(bin_path: PathBuf) -> PyResult<PathBuf> {
    tokio()
        .spawn(async move {
            let bin = fs::read(bin_path)?;
            let (release_manifest, target) = std_sigs::detect_rustc_release(&bin).await?;
            let std_lib = std_sigs::download_std_lib(&release_manifest, target).await?;
            let tmp_dir = std_sigs::extract_object_files_to_tmp_dir(&std_lib, &release_manifest)?;
            // Tempdir removal is not done automatically anymore! Must be handled on Python side.
            Ok(tmp_dir.into_path())
        })
        .await
        .unwrap()
}

#[pyfunction]
async fn signature_library_name(bin_path: PathBuf) -> PyResult<String> {
    // TODO: Should be possible to return a tuple in function above but for some reason only the
    // first tuple element reaches the Python side...
    tokio()
        .spawn(async move {
            let bin = fs::read(bin_path)?;
            let (release_manifest, _) = std_sigs::detect_rustc_release(&bin).await?;
            Ok(release_manifest.release().std_signature_base_file_name())
        })
        .await
        .unwrap()
}

#[pymodule]
fn binja_rust_plugin(m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3_log::init();
    m.add_function(wrap_pyfunction!(download_rust_std, m)?)?;
    m.add_function(wrap_pyfunction!(signature_library_name, m)?)?;
    Ok(())
}
