use tower_lsp::lsp_types::{Position, Range};

#[derive(Debug, PartialEq, Eq)]
pub struct Instruction {
    pub keyword: String,
    pub arguments: Vec<String>,
    pub arguments_str: String,
    pub comment: Option<String>,
    pub range: Range,
}

pub fn parse_dockerfile(contents: &str) -> Vec<Instruction> {
    let lines: Vec<&str> = contents.lines().collect();
    let mut instructions = Vec::new();

    let mut current_line_iteration = 0;
    while current_line_iteration < lines.len() {
        if lines[current_line_iteration].trim().is_empty() {
            current_line_iteration += 1;
            continue;
        }

        let start_line = current_line_iteration;
        let start_column = lines[current_line_iteration]
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(0);

        let mut aggregated_trimmed = lines[current_line_iteration].trim().to_string();
        let mut raw_instruction = String::new();
        raw_instruction.push_str(lines[current_line_iteration]);

        let mut end_line = current_line_iteration;

        while raw_instruction.trim_end().ends_with('\\') {
            if raw_instruction.ends_with('\\') {
                raw_instruction.pop();
            }
            aggregated_trimmed.pop();
            current_line_iteration += 1;
            if current_line_iteration >= lines.len() {
                break;
            }

            aggregated_trimmed.push(' ');
            aggregated_trimmed.push_str(lines[current_line_iteration].trim());
            raw_instruction.push(' ');
            raw_instruction.push_str(lines[current_line_iteration]);
            end_line = current_line_iteration;
        }

        let end_column = lines[end_line].trim_end().len();
        let range = Range::new(
            Position::new(
                start_line.min(u32::MAX as usize) as u32,
                start_column.min(u32::MAX as usize) as u32,
            ),
            Position::new(
                end_line.min(u32::MAX as usize) as u32,
                end_column.min(u32::MAX as usize) as u32,
            ),
        );
        let (actual_instruction, comment) = match aggregated_trimmed.split_once("#") {
            Some((instr, comm)) => (instr, Some(comm.trim().to_string())),
            None => (aggregated_trimmed.as_str(), None),
        };

        let (raw_instruction_without_comment, _) = match raw_instruction.split_once("#") {
            Some((instr, _)) => (instr, ()),
            None => (raw_instruction.as_str(), ()),
        };

        let trimmed_actual = actual_instruction.trim_start();
        let keyword_end = trimmed_actual
            .find(char::is_whitespace)
            .unwrap_or(trimmed_actual.len());
        let keyword = trimmed_actual[..keyword_end].to_uppercase();

        let raw_trimmed = raw_instruction_without_comment.trim_start();
        let mut parts = raw_trimmed.splitn(2, char::is_whitespace);
        // Skip first element (the keyword)
        parts.next();
        let arguments_str = parts.next().unwrap_or("").to_string();

        let arguments: Vec<String> = trimmed_actual[keyword_end..]
            .split_whitespace()
            .map(String::from)
            .collect();

        instructions.push(Instruction {
            keyword,
            arguments,
            arguments_str,
            comment,
            range,
        });
        current_line_iteration += 1;
    }

    instructions
}

#[cfg(test)]
mod tests {
    use tower_lsp::lsp_types::{Position, Range};

    use crate::infra::dockerfile_ast_parser::Instruction;

    use super::parse_dockerfile;

    #[test]
    fn it_parses_a_basic_dockerfile() {
        let dockerfile = "FROM alpine";

        let instructions = parse_dockerfile(dockerfile);

        assert_eq!(
            instructions,
            vec![Instruction {
                keyword: "FROM".to_string(),
                arguments: ["alpine".to_string()].to_vec(),
                arguments_str: "alpine".to_string(),
                comment: None,
                range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }]
        );
    }

    #[test]
    fn it_parses_a_multiline_dockerfile() {
        let dockerfile = r#"FROM ubuntu:20.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
"#;

        let instructions = parse_dockerfile(dockerfile);

        assert_eq!(
            instructions,
            vec![
                Instruction {
                    keyword: "FROM".to_string(),
                    arguments: ["ubuntu:20.04".to_string()].to_vec(),
                    arguments_str: "ubuntu:20.04".to_string(),
                    comment: None,
                    range: Range::new(Position::new(0, 0), Position::new(0,17)),
                },
                Instruction {
                    keyword: "RUN".to_string(),
                    arguments: [
                        "apt-get",
                        "update",
                        "&&",
                        "apt-get",
                        "install",
                        "-y",
                        "--no-install-recommends",
                        "curl",
                        "wget",
                        "ca-certificates",
                        "&&",
                        "apt-get",
                        "clean",
                        "&&",
                        "rm",
                        "-rf",
                        "/var/lib/apt/lists/*"
                    ]
                    .into_iter()
                    .map(ToString::to_string)
                    .collect(),
                    arguments_str: "apt-get update && apt-get install -y --no-install-recommends      curl      wget      ca-certificates   && apt-get clean   && rm -rf /var/lib/apt/lists/*".to_string(),
                    comment: None,
                    range: Range::new(Position::new(2, 0), Position::new(7,31)),
                }
            ]
        );
    }

    #[test]
    fn it_parses_a_comprehensive_dockerfile() {
        // This test checks multiple instructions with inline comments and multiline instructions.
        let dockerfile = r#"FROM ubuntu:20.04   # Use Ubuntu 20.04 as base image

RUN apt-get update && apt-get install -y --no-install-recommends \
curl \
wget \
git \
&& rm -rf /var/lib/apt/lists/*   # Clean up apt caches

CMD ["echo", "Hello, world!"]   # Print greeting
"#;
        let instructions = parse_dockerfile(dockerfile);
        let expected = vec![
            Instruction {
                keyword: "FROM".to_string(),
                arguments: vec!["ubuntu:20.04".to_string()],
                arguments_str: "ubuntu:20.04   ".to_string(),
                comment: Some("Use Ubuntu 20.04 as base image".to_string()),
                range: Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 52,
                    },
                },
            },
            Instruction {
                keyword: "RUN".to_string(),
                arguments: vec![
                    "apt-get".to_string(),
                    "update".to_string(),
                    "&&".to_string(),
                    "apt-get".to_string(),
                    "install".to_string(),
                    "-y".to_string(),
                    "--no-install-recommends".to_string(),
                    "curl".to_string(),
                    "wget".to_string(),
                    "git".to_string(),
                    "&&".to_string(),
                    "rm".to_string(),
                    "-rf".to_string(),
                    "/var/lib/apt/lists/*".to_string(),
                ],
                arguments_str: "apt-get update && apt-get install -y --no-install-recommends  curl  wget  git  && rm -rf /var/lib/apt/lists/*   ".to_string(),
                comment: Some("Clean up apt caches".to_string()),
                range: Range {
                    start: Position {
                        line: 2,
                        character: 0,
                    },
                    end: Position {
                        line: 6,
                        character: 54,
                    },
                },
            },
            Instruction {
                keyword: "CMD".to_string(),
                arguments: ["[\"echo\",".to_string(), "\"Hello,".to_string(), "world!\"]".to_string()].to_vec(),
                arguments_str: "[\"echo\", \"Hello, world!\"]   ".to_string(),
                comment: Some("Print greeting".to_string()),
                range: Range {
                    start: Position {
                        line: 8,
                        character: 0,
                    },
                    end: Position {
                        line: 8,
                        character: 48,
                    },
                },
            },
        ];
        assert_eq!(instructions, expected);
    }
}
