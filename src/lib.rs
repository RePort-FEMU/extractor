use pyo3::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use binwalk::{AnalysisResults, Binwalk};

#[pyfunction]
#[pyo3(signature = (file_path, verbose=false, extract=false, recursive=false, search_all=true, exclude_signatures=None, include_signatures=None, output_directory=None))]
#[allow(unused_variables)]
pub fn run_binwalk(
    file_path: String,
    verbose: bool,
    extract: bool,
    recursive: bool,
    search_all: bool,
    exclude_signatures: Option<Vec<String>>,
    include_signatures: Option<Vec<String>>,
    output_directory: Option<String>,
    py: Python,
) -> PyResult<Vec<PyObject>> {
    let file_path_buf = PathBuf::from(&file_path);
    if !file_path_buf.exists() {
        return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
            format!("File not found: {}", file_path),
        ));
    }

    let results: AnalysisResults = if extract {
        let outdir = output_directory.unwrap_or_else(|| {
            file_path_buf
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".".to_string())
        });

        // configure() creates a symlink <outdir>/<filename> -> target file.
        // If runBinwalk is called multiple times on the same file with the same
        // output dir (e.g. archive pass then rootfs pass), the second call fails
        // because the symlink already exists. Remove it first.
        if let Some(fname) = file_path_buf.file_name() {
            let symlink = PathBuf::from(&outdir).join(fname);
            if symlink.is_symlink() {
                let _ = fs::remove_file(&symlink);
            }
        }

        let binwalker = Binwalk::configure(
            Some(file_path.clone()),
            Some(outdir),
            include_signatures,
            exclude_signatures,
            None,
            false,
        )
        .map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Failed to configure binwalk")
        })?;

        // Use base_target_file (the symlink inside output dir) so extracted files
        // land inside the configured output directory.
        let target = binwalker.base_target_file.clone();
        binwalker.analyze(&target, true)
    } else {
        let binwalker = Binwalk::configure(
            None,
            None,
            include_signatures,
            exclude_signatures,
            None,
            false,
        )
        .map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Failed to configure binwalk")
        })?;

        let file_data = fs::read(&file_path_buf).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                "Failed to read file {}: {}",
                file_path, e
            ))
        })?;

        AnalysisResults {
            file_path: file_path.clone(),
            file_map: binwalker.scan(&file_data),
            extractions: HashMap::new(),
        }
    };

    let mut py_results = Vec::new();
    for sig in &results.file_map {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("offset", sig.offset as u64)?;
        dict.set_item("id", sig.id.clone())?;
        dict.set_item("size", sig.size as u64)?;
        dict.set_item("confidence", (sig.confidence as f64) / 100.0)?;
        dict.set_item("description", sig.description.clone())?;

        if let Some(ext) = results.extractions.get(&sig.id) {
            let ext_dict = pyo3::types::PyDict::new_bound(py);
            ext_dict.set_item("size", ext.size.unwrap_or(0) as u64)?;
            ext_dict.set_item("success", ext.success)?;
            ext_dict.set_item("extractor", ext.extractor.clone())?;
            ext_dict.set_item("output_dir", ext.output_directory.clone())?;
            dict.set_item("extraction_details", ext_dict)?;
        } else {
            dict.set_item("extraction_details", py.None())?;
        }

        py_results.push(dict.into());
    }

    Ok(py_results)
}

#[pymodule]
fn _lib(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run_binwalk, m)?)?;
    Ok(())
}
