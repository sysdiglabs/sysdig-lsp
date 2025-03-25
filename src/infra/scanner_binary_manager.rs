#![allow(dead_code)] // FIXME: to be removed later, when this is used

use regex::Regex;
use semver::Version;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::process::Command;

#[derive(Error, Debug)]
pub(in crate::infra) enum ScannerBinaryManagerError {
    #[error("operating system is not supported, current supported systems are linux and darwin")]
    UnsupportedOS,

    #[error("architecture is not supported, current supported architectures are arm64 and amd64")]
    UnsupportedArch,

    #[error("the scanner is not installed")]
    NotInstalled,

    #[error("the installed scanner is not executable")]
    NotExecutable,

    #[error("i/o error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("error extracting the version from output: {0}")]
    VersionExtractionError(String),

    #[error("error parsing version: {0}")]
    VersionParsingError(#[from] semver::Error),

    #[error("error performing http request: {0}")]
    HTTPError(#[from] reqwest::Error),
}

#[derive(Clone, Default)]
pub(super) struct ScannerBinaryManager {}

impl ScannerBinaryManager {
    const fn version(&self) -> Version {
        Version::new(1, 20, 0)
    }

    pub async fn install_expected_version_if_not_present(
        &mut self,
    ) -> Result<PathBuf, ScannerBinaryManagerError> {
        let expected_version = self.version();
        let binary_path = self.binary_path_for_version(&expected_version);

        if self
            .needs_to_install_it(&binary_path, &expected_version)
            .await?
        {
            self.install_expected_version(&binary_path, &expected_version)
                .await?;
        }

        Ok(binary_path)
    }

    async fn needs_to_install_it(
        &self,
        binary_path: &Path,
        expected_version: &Version,
    ) -> Result<bool, ScannerBinaryManagerError> {
        match self.get_current_installed_version_from(binary_path).await {
            Ok(current_version) => Ok(&current_version < expected_version),
            Err(err) => match err {
                ScannerBinaryManagerError::NotInstalled => Ok(true),
                _ => Err(err),
            },
        }
    }

    async fn install_expected_version(
        &self,
        binary_path: &Path,
        expected_version: &Version,
    ) -> Result<(), ScannerBinaryManagerError> {
        let response = reqwest::get(self.download_url(expected_version)?).await?;
        let body = response.bytes().await?;

        let parent_path = binary_path.parent().ok_or_else(|| {
            ScannerBinaryManagerError::IOError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "parent not found",
            ))
        })?;

        tokio::fs::create_dir_all(parent_path).await?;
        tokio::fs::write(&binary_path, &body).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755)).await?;

        Ok(())
    }

    fn download_url(&self, version: &Version) -> Result<String, ScannerBinaryManagerError> {
        let os = match std::env::consts::OS {
            "linux" => "linux",
            "macos" => "darwin",
            _ => return Err(ScannerBinaryManagerError::UnsupportedOS),
        };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => return Err(ScannerBinaryManagerError::UnsupportedArch),
        };

        Ok(format!(
            "https://download.sysdig.com/scanning/bin/sysdig-cli-scanner/{version}/{os}/{arch}/sysdig-cli-scanner"
        ))
    }

    async fn get_current_installed_version_from(
        &self,
        binary_path: &Path,
    ) -> Result<semver::Version, ScannerBinaryManagerError> {
        if !binary_path.exists() {
            return Err(ScannerBinaryManagerError::NotInstalled);
        }

        if !self.is_executable(binary_path).await {
            return Err(ScannerBinaryManagerError::NotExecutable);
        }

        let output = Command::new(binary_path).arg("--version").output().await?;

        if !output.status.success() {
            return Err(ScannerBinaryManagerError::IOError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "status command is not succesful: {}",
                    output.status.code().unwrap_or(0)
                ),
            )));
        }

        // We merge both stdout and stderr in case they switch from one or another. Happened from 1.17.0 to 1.20.0
        let stdout =
            String::from_utf8_lossy(&output.stdout) + String::from_utf8_lossy(&output.stderr);
        let version_str = Regex::new(r"Sysdig CLI Scanner (\d+\.\d+\.\d+)")
            .unwrap()
            .captures(&stdout)
            .and_then(|captures| captures.get(1))
            .map(|x| x.as_str())
            .ok_or_else(|| {
                ScannerBinaryManagerError::VersionExtractionError(stdout.clone().into_owned())
            })?;

        Ok(Version::parse(version_str)?)
    }

    async fn is_executable(&self, binary_path: &Path) -> bool {
        #[cfg(unix)]
        {
            match tokio::fs::metadata(binary_path).await {
                Ok(metadata) => {
                    let permissions = metadata.permissions();
                    permissions.mode() & 0o111 != 0
                }
                _ => false,
            }
        }

        #[cfg(windows)]
        {
            if let Some(ext) = binary_path.extension() {
                matches!(ext.to_str(), Some("exe") | Some("bat") | Some("cmd"))
            } else {
                false
            }
        }
    }

    fn binary_path_for_version(&self, version: &Version) -> PathBuf {
        let mut cache_dir = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
        cache_dir.push("sysdig-cli-scanner");
        cache_dir.push(format!("sysdig-cli-scanner.{}", version));
        cache_dir
    }
}

#[cfg(test)]
mod tests {
    use super::ScannerBinaryManager;
    use core::panic;
    use semver::Version;
    use serial_test::file_serial;

    #[tokio::test]
    async fn it_gets_the_wanted_version() {
        let mgr = ScannerBinaryManager::default();

        assert_eq!(mgr.version().to_string(), "1.20.0");
    }

    #[tokio::test]
    async fn it_retrieves_the_binary_path() {
        let mgr = ScannerBinaryManager::default();

        assert!(
            mgr.binary_path_for_version(&Version::new(1, 20, 0))
                .ends_with(".cache/sysdig-cli-scanner/sysdig-cli-scanner.1.20.0")
        );
    }

    #[tokio::test]
    async fn it_will_download_from_the_correct_url() {
        let mgr = ScannerBinaryManager::default();

        assert_eq!(
            mgr.download_url(&Version::new(1, 20, 0)).unwrap(),
            "https://download.sysdig.com/scanning/bin/sysdig-cli-scanner/1.20.0/linux/amd64/sysdig-cli-scanner"
        );
    }

    #[tokio::test]
    #[file_serial]
    async fn it_downloads_if_it_doesnt_exist() {
        let mut mgr = ScannerBinaryManager::default();

        let binary_path = mgr.binary_path_for_version(&mgr.version());
        let _ = tokio::fs::remove_file(&binary_path).await;

        mgr.install_expected_version_if_not_present()
            .await
            .unwrap_or_else(|e| panic!("{}", e));

        assert_eq!(
            mgr.get_current_installed_version_from(&binary_path)
                .await
                .unwrap()
                .to_string(),
            "1.20.0"
        );
    }

    #[tokio::test]
    #[file_serial]
    async fn it_doesnt_download_if_it_exists() {
        let mut mgr = ScannerBinaryManager::default();

        let binary_path = mgr.binary_path_for_version(&mgr.version());

        mgr.install_expected_version_if_not_present()
            .await
            .unwrap_or_else(|e| panic!("{}", e));
        mgr.install_expected_version_if_not_present()
            .await
            .unwrap_or_else(|e| panic!("{}", e));

        assert_eq!(
            mgr.get_current_installed_version_from(&binary_path)
                .await
                .unwrap()
                .to_string(),
            "1.20.0"
        );
    }
}
