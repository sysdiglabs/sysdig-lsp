use std::fmt::Display;

use tower_lsp::{
    jsonrpc::{self, Error},
    lsp_types::{ExecuteCommandParams, Location, Url},
};

const CMD_EXECUTE_SCAN: &str = "sysdig-lsp.execute-scan";
const CMD_BUILD_AND_SCAN: &str = "sysdig-lsp.execute-build-and-scan";
const CMD_EXECUTE_IAC_SCAN: &str = "sysdig-lsp.execute-iac-scan";

// The variants intentionally mirror the `sysdig-lsp.execute-*` command identifiers.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum SupportedCommands {
    ExecuteBaseImageScan { location: Location, image: String },
    ExecuteBuildAndScan { location: Location },
    ExecuteIacScan { uri: Option<Url> },
}

impl SupportedCommands {
    pub fn as_string_command(&self) -> String {
        match self {
            SupportedCommands::ExecuteBaseImageScan { .. } => CMD_EXECUTE_SCAN,
            SupportedCommands::ExecuteBuildAndScan { .. } => CMD_BUILD_AND_SCAN,
            SupportedCommands::ExecuteIacScan { .. } => CMD_EXECUTE_IAC_SCAN,
        }
        .to_string()
    }

    pub fn all_supported_commands_as_string() -> Vec<String> {
        [CMD_EXECUTE_SCAN, CMD_BUILD_AND_SCAN, CMD_EXECUTE_IAC_SCAN]
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }
}

impl TryFrom<ExecuteCommandParams> for SupportedCommands {
    type Error = jsonrpc::Error;

    fn try_from(value: ExecuteCommandParams) -> std::result::Result<Self, Self::Error> {
        match (value.command.as_str(), value.arguments.as_slice()) {
            (CMD_EXECUTE_SCAN, [location, image]) => Ok(SupportedCommands::ExecuteBaseImageScan {
                location: serde_json::from_value(location.clone())
                    .map_err(|_| Error::invalid_params("location must be a Location object"))?,
                image: image
                    .as_str()
                    .ok_or_else(|| Error::invalid_params("image must be string"))?
                    .to_owned(),
            }),
            (CMD_BUILD_AND_SCAN, [location]) => Ok(SupportedCommands::ExecuteBuildAndScan {
                location: serde_json::from_value(location.clone())
                    .map_err(|_| Error::invalid_params("location must be a Location object"))?,
            }),
            (CMD_EXECUTE_IAC_SCAN, []) => Ok(SupportedCommands::ExecuteIacScan { uri: None }),
            (CMD_EXECUTE_IAC_SCAN, [uri]) => {
                let uri = uri
                    .as_str()
                    .ok_or_else(|| Error::invalid_params("uri must be a string"))?;
                let uri = Url::parse(uri)
                    .map_err(|e| Error::invalid_params(format!("uri must be a valid URI: {e}")))?;
                Ok(SupportedCommands::ExecuteIacScan { uri: Some(uri) })
            }
            (CMD_EXECUTE_IAC_SCAN, _) => {
                Err(Error::invalid_params("expected at most one uri argument"))
            }
            (other, _) => Err(Error::invalid_params(format!(
                "command not supported: {other}"
            ))),
        }
    }
}

impl Display for SupportedCommands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportedCommands::ExecuteBaseImageScan { location, image } => {
                write!(
                    f,
                    "ExecuteBaseImageScan(location: {location:?}, image: {image})",
                )
            }
            SupportedCommands::ExecuteBuildAndScan { location } => {
                write!(f, "ExecuteBuildAndScan(location: {location:?})")
            }
            SupportedCommands::ExecuteIacScan { uri } => {
                write!(f, "ExecuteIacScan(uri: {uri:?})")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SupportedCommands;
    use serde_json::json;
    use tower_lsp::{jsonrpc, lsp_types::ExecuteCommandParams};

    fn params(command: &str, arguments: Vec<serde_json::Value>) -> ExecuteCommandParams {
        ExecuteCommandParams {
            command: command.to_string(),
            arguments,
            ..Default::default()
        }
    }

    #[test]
    fn it_parses_iac_scan_without_arguments() {
        let command: SupportedCommands = params("sysdig-lsp.execute-iac-scan", vec![])
            .try_into()
            .unwrap_or_else(|e| panic!("failed to parse: {e}"));

        assert!(matches!(
            command,
            SupportedCommands::ExecuteIacScan { uri: None }
        ));
    }

    #[test]
    fn it_parses_iac_scan_with_a_uri_argument() {
        let command: SupportedCommands =
            params("sysdig-lsp.execute-iac-scan", vec![json!("file:///a.yaml")])
                .try_into()
                .unwrap_or_else(|e| panic!("failed to parse: {e}"));

        match command {
            SupportedCommands::ExecuteIacScan { uri: Some(uri) } => {
                assert_eq!(uri.as_str(), "file:///a.yaml")
            }
            other => panic!("unexpected command: {other}"),
        }
    }

    #[test]
    fn it_rejects_iac_scan_with_a_non_string_argument() {
        let result: Result<SupportedCommands, _> =
            params("sysdig-lsp.execute-iac-scan", vec![json!(42)]).try_into();

        assert!(result.is_err());
    }

    #[test]
    fn it_rejects_iac_scan_with_an_invalid_uri() {
        let result: Result<SupportedCommands, _> =
            params("sysdig-lsp.execute-iac-scan", vec![json!("not a uri")]).try_into();

        assert!(result.is_err());
    }

    #[test]
    fn it_rejects_iac_scan_with_multiple_arguments() {
        let result: Result<SupportedCommands, jsonrpc::Error> = params(
            "sysdig-lsp.execute-iac-scan",
            vec![json!("file:///a.yaml"), json!("file:///b.yaml")],
        )
        .try_into();

        let err = result.expect_err("should reject multiple arguments");
        assert!(err.message.contains("at most one"));
    }
}
