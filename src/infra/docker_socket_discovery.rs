use std::path::PathBuf;

use bollard::Docker;
use tracing::{debug, info, warn};

/// Result of a successful Docker connection, including the socket path used.
pub struct DockerConnection {
    /// The connected Docker client
    pub client: Docker,
    /// The socket path that was used to connect.
    /// Format: "unix:///path/to/socket" for Unix sockets, or the DOCKER_HOST value if set.
    pub socket_path: String,
}

/// List of Docker socket paths to try, in order of preference.
/// The first successful connection will be used.
fn get_candidate_socket_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        // Standard Docker socket location (Linux/macOS)
        PathBuf::from("/var/run/docker.sock"),
    ];

    // Add Colima socket paths if HOME is available
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(&home);

        // Colima Docker sockets (various locations)
        paths.push(home_path.join(".colima/docker.sock"));
        paths.push(home_path.join(".colima/default/docker.sock"));

        // Colima containerd socket - Note: This uses Docker-compatible API
        // when Colima is configured with Docker compatibility layer
        paths.push(home_path.join(".colima/default/containerd.sock"));

        // Lima default socket (used by some Colima configurations)
        paths.push(home_path.join(".lima/default/sock/docker.sock"));
    }

    // Podman socket (for potential future compatibility)
    if let Ok(xdg_runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        paths.push(PathBuf::from(xdg_runtime_dir).join("podman/podman.sock"));
    }

    paths
}

/// Attempts to connect to Docker using multiple socket paths.
///
/// This function tries the following in order:
/// 1. `DOCKER_HOST` environment variable (if set)
/// 2. Standard Docker socket at `/var/run/docker.sock`
/// 3. Colima sockets at `$HOME/.colima/docker.sock`, `$HOME/.colima/default/docker.sock`
/// 4. Colima containerd socket at `$HOME/.colima/default/containerd.sock`
/// 5. Lima socket at `$HOME/.lima/default/sock/docker.sock`
///
/// Returns a `DockerConnection` containing both the client and the socket path used,
/// or an error if no socket could be connected.
pub fn connect_to_docker() -> Result<DockerConnection, DockerConnectionError> {
    // First, check if DOCKER_HOST is set - if so, use Bollard's default behavior
    if let Ok(docker_host) = std::env::var("DOCKER_HOST") {
        debug!("DOCKER_HOST environment variable is set: {}", docker_host);
        match Docker::connect_with_local_defaults() {
            Ok(client) => {
                info!("Connected to Docker via DOCKER_HOST: {}", docker_host);
                return Ok(DockerConnection {
                    client,
                    socket_path: docker_host,
                });
            }
            Err(e) => {
                warn!("Failed to connect via DOCKER_HOST ({}): {}", docker_host, e);
                // Continue to try other sockets
            }
        }
    }

    // Try each candidate socket path
    let candidate_paths = get_candidate_socket_paths();
    let mut last_error = None;

    for socket_path in &candidate_paths {
        if !socket_path.exists() {
            debug!("Socket path does not exist: {:?}", socket_path);
            continue;
        }

        debug!("Attempting to connect to Docker socket: {:?}", socket_path);

        let socket_path_str = match socket_path.to_str() {
            Some(s) => s,
            None => {
                warn!("Invalid socket path (non-UTF8): {:?}", socket_path);
                continue;
            }
        };

        match Docker::connect_with_unix(socket_path_str, 120, bollard::API_DEFAULT_VERSION) {
            Ok(client) => {
                info!("Successfully connected to Docker socket: {:?}", socket_path);
                return Ok(DockerConnection {
                    client,
                    socket_path: format!("unix://{}", socket_path_str),
                });
            }
            Err(e) => {
                debug!("Failed to connect to socket {:?}: {}", socket_path, e);
                last_error = Some((socket_path.clone(), e));
            }
        }
    }

    // If no socket worked, return an error with helpful information
    let tried_paths: Vec<String> = candidate_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    Err(DockerConnectionError {
        tried_paths,
        last_error: last_error.map(|(path, err)| format!("{}: {}", path.display(), err)),
    })
}

/// Error returned when no Docker socket could be connected.
#[derive(Debug)]
pub struct DockerConnectionError {
    /// List of socket paths that were attempted
    pub tried_paths: Vec<String>,
    /// The last error encountered (if any)
    pub last_error: Option<String>,
}

impl std::fmt::Display for DockerConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Failed to connect to Docker. Tried sockets: [{}]",
            self.tried_paths.join(", ")
        )?;
        if let Some(ref last_err) = self.last_error {
            write!(f, ". Last error: {}", last_err)?;
        }
        Ok(())
    }
}

impl std::error::Error for DockerConnectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_candidate_socket_paths_includes_standard_path() {
        let paths = get_candidate_socket_paths();
        assert!(paths.contains(&PathBuf::from("/var/run/docker.sock")));
    }

    #[test]
    fn test_get_candidate_socket_paths_includes_colima_paths() {
        if std::env::var("HOME").is_ok() {
            let paths = get_candidate_socket_paths();
            let home = std::env::var("HOME").unwrap();

            assert!(paths.contains(&PathBuf::from(format!("{}/.colima/docker.sock", home))));
            assert!(paths.contains(&PathBuf::from(format!(
                "{}/.colima/default/docker.sock",
                home
            ))));
            assert!(paths.contains(&PathBuf::from(format!(
                "{}/.colima/default/containerd.sock",
                home
            ))));
        }
    }

    #[test]
    fn test_docker_connection_error_display() {
        let error = DockerConnectionError {
            tried_paths: vec![
                "/var/run/docker.sock".to_string(),
                "/home/user/.colima/docker.sock".to_string(),
            ],
            last_error: Some("Connection refused".to_string()),
        };

        let display = format!("{}", error);
        assert!(display.contains("/var/run/docker.sock"));
        assert!(display.contains(".colima/docker.sock"));
        assert!(display.contains("Connection refused"));
    }

    // Integration test - only runs if Docker is available
    #[tokio::test]
    async fn test_connect_to_docker_succeeds_when_docker_available() {
        // This test will pass if any Docker socket is available
        let result = connect_to_docker();

        // We can't guarantee Docker is available in CI, so we just verify the function runs
        match result {
            Ok(connection) => {
                // Verify the connection works by pinging
                let ping_result = connection.client.ping().await;
                assert!(
                    ping_result.is_ok(),
                    "Connected to Docker but ping failed: {:?}",
                    ping_result.err()
                );

                // Verify socket_path is not empty and in expected format
                assert!(
                    !connection.socket_path.is_empty(),
                    "socket_path should not be empty"
                );
                assert!(
                    connection.socket_path.starts_with("unix://")
                        || connection.socket_path.starts_with("tcp://")
                        || connection.socket_path.contains("docker"),
                    "socket_path should be in expected format: {}",
                    connection.socket_path
                );
            }
            Err(e) => {
                // If no Docker is available, that's OK - just verify error is informative
                assert!(!e.tried_paths.is_empty());
                eprintln!("No Docker available (expected in some environments): {}", e);
            }
        }
    }

    #[test]
    fn test_socket_path_format_for_unix_socket() {
        // Validates the format logic for Unix sockets
        let raw_path = "/var/run/docker.sock";
        let formatted = format!("unix://{}", raw_path);
        assert_eq!(formatted, "unix:///var/run/docker.sock");
    }
}
