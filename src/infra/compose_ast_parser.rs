use tower_lsp::lsp_types::{Position, Range};

#[derive(Debug, PartialEq)]
pub struct ImageInstruction {
    pub image_name: String,
    pub range: Range,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidYaml(marked_yaml::LoadError),
}

pub fn parse_compose_file(content: &str) -> Result<Vec<ImageInstruction>, ParseError> {
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
            if let Some(services) = map.get("services") {
                find_images_recursive(services, instructions, content);
                return; // Stop descending further from the root if 'services' is found
            }

            for (key, value) in map.iter() {
                if key.as_str() == "image" {
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
    fn test_parse_simple_compose_file() {
        let content = r#"
services:
  web:
    image: nginx:latest
"#;
        let result = parse_compose_file(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 3,
                        character: 11
                    },
                    end: Position {
                        line: 3,
                        character: 23
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_compose_file_with_multiple_services() {
        let content = r#"
version: '3.8'
services:
  web:
    image: nginx:latest
  db:
    image: postgres:13
  api:
    build: .
"#;
        let result = parse_compose_file(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 4,
                        character: 11
                    },
                    end: Position {
                        line: 4,
                        character: 23
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
                        line: 6,
                        character: 11
                    },
                    end: Position {
                        line: 6,
                        character: 22
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_compose_file_no_image() {
        let content = r#"
services:
  web:
    build: .
"#;
        let result = parse_compose_file(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_empty_file() {
        let content = "";
        let result = parse_compose_file(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let content = r#"
services:
  web:
    image: nginx:latest
  db
    image: postgres:13
"#;
        let result = parse_compose_file(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_quoted_keys() {
        let content = r#"
services:
  web:
    "image": nginx:latest
"#;
        let result = parse_compose_file(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 3,
                        character: 13
                    },
                    end: Position {
                        line: 3,
                        character: 25
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_with_quoted_values() {
        let content = r#"
services:
  web:
    image: "nginx:latest"
  db:
    image: 'postgres:13'
"#;
        let result = parse_compose_file(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 3,
                        character: 11
                    },
                    end: Position {
                        line: 3,
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
                        line: 5,
                        character: 11
                    },
                    end: Position {
                        line: 5,
                        character: 24
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_with_multiline_literal() {
        let content = r#"
services:
  web:
    image: |
      nginx:latest
"#;
        let result = parse_compose_file(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 4,
                        character: 6
                    },
                    end: Position {
                        line: 4,
                        character: 18
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_with_complex_image_name() {
        let content = r#"
services:
  complex_service:
    image: private-registry.company.com:5000/project/team/service-image:1.2.3-beta
"#;
        let result = parse_compose_file(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name:
                    "private-registry.company.com:5000/project/team/service-image:1.2.3-beta"
                        .to_string(),
                range: Range {
                    start: Position {
                        line: 3,
                        character: 11
                    },
                    end: Position {
                        line: 3,
                        character: 82
                    },
                },
            }
        );
    }

    #[test]
    fn test_parse_with_null_or_empty_image_values() {
        let content = r#"
services:
  web:
    image:
  db:
    image: ""
  cache:
    image: null
"#;
        let result = parse_compose_file(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_with_end_of_line_comment() {
        let content = r#"
services:
  web:
    image: nginx:latest # Use the latest nginx image
"#;
        let result = parse_compose_file(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ImageInstruction {
                image_name: "nginx:latest".to_string(),
                range: Range {
                    start: Position {
                        line: 3,
                        character: 11
                    },
                    end: Position {
                        line: 3,
                        character: 23
                    },
                },
            }
        );
    }
}
