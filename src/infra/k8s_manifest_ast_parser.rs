use thiserror::Error;
use tower_lsp::lsp_types::{Position, Range};

#[derive(Debug, PartialEq)]
pub struct ImageInstruction {
    pub image_name: String,
    pub range: Range,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid yaml: {0}")]
    InvalidYaml(marked_yaml::LoadError),
}

pub fn parse_k8s_manifest(content: &str) -> Result<Vec<ImageInstruction>, ParseError> {
    let mut instructions = Vec::new();

    let node = marked_yaml::parse_yaml(0, content).map_err(ParseError::InvalidYaml)?;
    find_images_recursive(&node, &mut instructions, content);

    Ok(instructions)
}

fn find_images_recursive(
    node: &marked_yaml::Node,
    instructions: &mut Vec<ImageInstruction>,
    content: &str,
) {
    match node {
        marked_yaml::Node::Mapping(map) => {
            // Check if this is a containers or initContainers array
            for (key, value) in map.iter() {
                let key_str = key.as_str();
                if key_str == "containers" || key_str == "initContainers" {
                    find_container_images(value, instructions, content);
                } else if key_str == "image" {
                    if let Some(instruction) = try_create_image_instruction(value, content) {
                        instructions.push(instruction);
                    }
                } else {
                    find_images_recursive(value, instructions, content);
                }
            }
        }
        marked_yaml::Node::Sequence(seq) => {
            for item in seq.iter() {
                find_images_recursive(item, instructions, content);
            }
        }
        _ => {}
    }
}

fn find_container_images(
    node: &marked_yaml::Node,
    instructions: &mut Vec<ImageInstruction>,
    content: &str,
) {
    let marked_yaml::Node::Sequence(containers) = node else {
        return;
    };

    for container in containers.iter() {
        let marked_yaml::Node::Mapping(container_map) = container else {
            continue;
        };

        if let Some(image_node) = container_map.get("image")
            && let Some(instruction) = try_create_image_instruction(image_node, content)
        {
            instructions.push(instruction);
        }
    }
}

fn try_create_image_instruction(
    node: &marked_yaml::Node,
    content: &str,
) -> Option<ImageInstruction> {
    let marked_yaml::Node::Scalar(scalar) = node else {
        return None;
    };

    let image_name = scalar.as_str().trim().to_string();
    if !is_valid_image_name(&image_name) {
        return None;
    }

    let start = node.span().start()?;

    let range = calculate_range(start, &image_name, content);
    Some(ImageInstruction { image_name, range })
}

fn is_valid_image_name(name: &str) -> bool {
    !name.is_empty() && name != "null"
}

fn calculate_range(start: &marked_yaml::Marker, image_name: &str, content: &str) -> Range {
    let start_line = start.line() as u32 - 1;
    let start_char = start.column() as u32 - 1;

    let start_line_content = content.lines().nth(start_line as usize).unwrap_or("");
    let first_char = start_line_content.chars().nth(start_char as usize);

    let mut raw_len = image_name.len();
    if let Some(c) = first_char
        && (c == '"' || c == '\'')
    {
        raw_len += 2;
    }

    let end_char = start_char + raw_len as u32;

    Range {
        start: Position {
            line: start_line,
            character: start_char,
        },
        end: Position {
            line: start_line,
            character: end_char,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::Position;

    #[test]
    fn test_parse_simple_pod() {
        let content = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 8,
                        character: 11
                    },
                    end: Position {
                        line: 8,
                        character: 23
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_deployment_with_multiple_containers() {
        let content = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-deployment
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.19
      - name: sidecar
        image: busybox:latest
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:1.19".to_string(),
                range: Range {
                    start: Position {
                        line: 10,
                        character: 15
                    },
                    end: Position {
                        line: 10,
                        character: 25
                    },
                },
            }
        );
        assert_eq!(
            result[1],
            ImageInstruction {
                image_name: "busybox:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 12,
                        character: 15
                    },
                    end: Position {
                        line: 12,
                        character: 29
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_with_init_containers() {
        let content = r#"
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
spec:
  initContainers:
  - name: init-myservice
    image: busybox:1.28
  containers:
  - name: myapp-container
    image: nginx:1.19
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].image_name, "busybox:1.28");
        assert_eq!(result[1].image_name, "nginx:1.19");
    }

    #[test]
    fn test_parse_statefulset() {
        let content = r#"
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:stable
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].image_name, "nginx:stable");
    }

    #[test]
    fn test_parse_cronjob() {
        let content = r#"
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox:1.28
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].image_name, "busybox:1.28");
    }

    #[test]
    fn test_parse_with_quoted_values() {
        let content = r#"
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: web
    image: "nginx:latest"
  - name: db
    image: 'postgres:13'
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 6,
                        character: 11
                    },
                    end: Position {
                        line: 6,
                        character: 25
                    },
                },
            }
        );
        assert_eq!(
            result[1],
            ImageInstruction {
                image_name: "postgres:13".to_string(),
                range: Range {
                    start: Position {
                        line: 8,
                        character: 11
                    },
                    end: Position {
                        line: 8,
                        character: 24
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_with_complex_image_name() {
        let content = r#"
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: private-registry.company.com:5000/project/team/service-image:1.2.3-beta
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].image_name,
            "private-registry.company.com:5000/project/team/service-image:1.2.3-beta"
        );
    }

    #[test]
    fn test_parse_empty_file() {
        let content = "";
        let result = parse_k8s_manifest(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let content = r#"
apiVersion: v1
kind: Pod
spec:
  containers
  - name: app
    image: nginx
"#;
        let result = parse_k8s_manifest(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_null_or_empty_image_values() {
        let content = r#"
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app1
    image:
  - name: app2
    image: ""
  - name: app3
    image: null
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_daemonset() {
        let content = r#"
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
spec:
  template:
    spec:
      containers:
      - name: fluentd
        image: fluentd:v1.0
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].image_name, "fluentd:v1.0");
    }

    #[test]
    fn test_parse_job() {
        let content = r#"
apiVersion: batch/v1
kind: Job
metadata:
  name: pi
spec:
  template:
    spec:
      containers:
      - name: pi
        image: perl:5.34
"#;
        let result = parse_k8s_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].image_name, "perl:5.34");
    }
}
