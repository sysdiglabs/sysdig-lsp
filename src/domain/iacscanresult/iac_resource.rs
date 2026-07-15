use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IacResource {
    /// Absolute path of the file the finding was reported on.
    pub source: PathBuf,
    /// Location of the resource inside the file, as reported by the scanner
    /// (e.g. `spec.template.spec.containers[0]`).
    pub location: String,
    pub resource_type: String,
    pub name: String,
}
