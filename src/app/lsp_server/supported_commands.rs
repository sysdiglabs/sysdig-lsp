use std::fmt::Display;

use super::CommandInfo;
use serde_json::json;
use tower_lsp::{
    jsonrpc::{self, Error},
    lsp_types::{ExecuteCommandParams, Location},
};

const CMD_EXECUTE_SCAN: &str = "sysdig-lsp.execute-scan";
const CMD_BUILD_AND_SCAN: &str = "sysdig-lsp.execute-build-and-scan";

#[derive(Debug, Clone)]
pub enum SupportedCommands {
    ExecuteBaseImageScan { location: Location, image: String },
    ExecuteBuildAndScan { location: Location },
}

impl SupportedCommands {
    fn as_string_command(&self) -> String {
        match self {
            SupportedCommands::ExecuteBaseImageScan { .. } => CMD_EXECUTE_SCAN,
            SupportedCommands::ExecuteBuildAndScan { .. } => CMD_BUILD_AND_SCAN,
        }
        .to_string()
    }

    pub fn all_supported_commands_as_string() -> Vec<String> {
        [CMD_EXECUTE_SCAN, CMD_BUILD_AND_SCAN]
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }
}

impl From<SupportedCommands> for CommandInfo {
    fn from(value: SupportedCommands) -> Self {
        match &value {
            SupportedCommands::ExecuteBaseImageScan { location, image } => CommandInfo {
                title: "Scan base image".to_owned(),
                command: value.as_string_command(),
                arguments: Some(vec![json!(location), json!(image)]),
                range: location.range,
            },

            SupportedCommands::ExecuteBuildAndScan { location } => CommandInfo {
                title: "Build and scan".to_owned(),
                command: value.as_string_command(),
                arguments: Some(vec![json!(location)]),
                range: location.range,
            },
        }
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
        }
    }
}
