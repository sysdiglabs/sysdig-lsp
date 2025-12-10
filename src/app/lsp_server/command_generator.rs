use serde_json::{Value, json};
use tower_lsp::lsp_types::{CodeLens, Command, Location, Range, Url};

use crate::app::lsp_server::supported_commands::SupportedCommands;
use crate::infra::{parse_compose_file, parse_dockerfile, parse_k8s_manifest};

pub struct CommandInfo {
    pub title: String,
    pub command: String,
    pub arguments: Option<Vec<Value>>,
    pub range: Range,
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

impl From<CommandInfo> for Command {
    fn from(value: CommandInfo) -> Self {
        Command {
            title: value.title,
            command: value.command,
            arguments: value.arguments,
        }
    }
}

impl From<CommandInfo> for CodeLens {
    fn from(value: CommandInfo) -> Self {
        CodeLens {
            range: value.range,
            command: Some(Command {
                title: value.title,
                command: value.command,
                arguments: value.arguments,
            }),
            data: None,
        }
    }
}

pub fn generate_commands_for_uri(uri: &Url, content: &str) -> Result<Vec<CommandInfo>, String> {
    let file_uri = uri.as_str();

    if file_uri.contains("docker-compose.yml")
        || file_uri.contains("compose.yml")
        || file_uri.contains("docker-compose.yaml")
        || file_uri.contains("compose.yaml")
    {
        generate_compose_commands(uri, content)
    } else if is_k8s_manifest_file(file_uri, content) {
        generate_k8s_manifest_commands(uri, content)
    } else {
        Ok(generate_dockerfile_commands(uri, content))
    }
}

fn generate_compose_commands(url: &Url, content: &str) -> Result<Vec<CommandInfo>, String> {
    let mut commands = vec![];
    match parse_compose_file(content) {
        Ok(instructions) => {
            for instruction in instructions {
                commands.push(
                    SupportedCommands::ExecuteBaseImageScan {
                        location: Location::new(url.clone(), instruction.range),
                        image: instruction.image_name,
                    }
                    .into(),
                );
            }
        }
        Err(err) => return Err(format!("{}", err)),
    }

    Ok(commands)
}

fn is_k8s_manifest_file(file_uri: &str, content: &str) -> bool {
    // Must be a YAML file
    if !(file_uri.ends_with(".yaml") || file_uri.ends_with(".yml")) {
        return false;
    }

    // Check for K8s manifest indicators in content
    // K8s manifests typically have "apiVersion" and "kind" fields
    content.contains("apiVersion:") && content.contains("kind:")
}

fn generate_k8s_manifest_commands(url: &Url, content: &str) -> Result<Vec<CommandInfo>, String> {
    let mut commands = vec![];
    match parse_k8s_manifest(content) {
        Ok(instructions) => {
            for instruction in instructions {
                commands.push(
                    SupportedCommands::ExecuteBaseImageScan {
                        location: Location::new(url.clone(), instruction.range),
                        image: instruction.image_name,
                    }
                    .into(),
                );
            }
        }
        Err(err) => return Err(format!("{}", err)),
    }

    Ok(commands)
}

fn generate_dockerfile_commands(uri: &Url, content: &str) -> Vec<CommandInfo> {
    let mut commands = vec![];
    let instructions = parse_dockerfile(content);
    if let Some(last_from_instruction) = instructions
        .iter()
        .filter(|instruction| instruction.keyword == "FROM")
        .next_back()
    {
        let range = last_from_instruction.range;
        commands.push(
            SupportedCommands::ExecuteBuildAndScan {
                location: Location::new(uri.clone(), range),
            }
            .into(),
        );
        if let Some(image) = last_from_instruction.arguments.first() {
            commands.push(
                SupportedCommands::ExecuteBaseImageScan {
                    location: Location::new(uri.clone(), range),
                    image: image.to_owned(),
                }
                .into(),
            );
        }
    }
    commands
}
