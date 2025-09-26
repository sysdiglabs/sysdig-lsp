use serde_json::json;
use tower_lsp::lsp_types::{CodeActionOrCommand, CodeLens, Command, MessageType, Position, Range};

mod test;

#[tokio::test]
async fn when_the_lsp_is_loaded_initializes_correctly() {
    let mut client = test::TestClient::new();
    let response = client.initialize_lsp().await;

    assert!(response.capabilities.code_action_provider.is_some());
    assert!(
        client
            .recorder()
            .messages_shown()
            .await
            .contains(&(MessageType::INFO, "Sysdig LSP initialized".to_string()))
    )
}

#[tokio::test]
async fn when_the_client_asks_for_the_existing_code_actions_it_receives_the_available_code_actions()
{
    let mut client = test::TestClient::new_initialized().await;

    client
        .open_file_with_contents("Dockerfile", "FROM alpine")
        .await;

    let response = client
        .request_available_actions_in_line("Dockerfile", 0)
        .await;

    assert_eq!(
        response.unwrap(),
        vec![
            CodeActionOrCommand::Command(Command {
                title: "Build and scan".to_string(),
                command: "sysdig-lsp.execute-build-and-scan".to_string(),
                arguments: Some(vec![json!("file://dockerfile/"), json!(0)])
            }),
            CodeActionOrCommand::Command(Command {
                title: "Scan base image".to_string(),
                command: "sysdig-lsp.execute-scan".to_string(),
                arguments: Some(vec![json!("file://dockerfile/"), json!(0), json!("alpine")])
            })
        ]
    );
}

#[tokio::test]
async fn when_the_client_asks_for_the_existing_code_actions_but_the_dockerfile_contains_multiple_froms_it_only_returns_the_latest()
 {
    let mut client = test::TestClient::new_initialized().await;

    client
        .open_file_with_contents("Dockerfile", "FROM alpine\nFROM ubuntu")
        .await;

    let response_for_first_line = client
        .request_available_actions_in_line("Dockerfile", 0)
        .await;
    assert!(response_for_first_line.unwrap().is_empty());

    let response_for_second_line = client
        .request_available_actions_in_line("Dockerfile", 1)
        .await;

    assert_eq!(
        response_for_second_line.unwrap(),
        vec![
            CodeActionOrCommand::Command(Command {
                title: "Build and scan".to_string(),
                command: "sysdig-lsp.execute-build-and-scan".to_string(),
                arguments: Some(vec![json!("file://dockerfile/"), json!(1)])
            }),
            CodeActionOrCommand::Command(Command {
                title: "Scan base image".to_string(),
                command: "sysdig-lsp.execute-scan".to_string(),
                arguments: Some(vec![json!("file://dockerfile/"), json!(1), json!("ubuntu")])
            })
        ]
    );
}

#[tokio::test]
async fn when_the_client_asks_for_the_existing_code_lens_it_receives_the_available_code_lens() {
    let mut client = test::TestClient::new_initialized().await;

    // Open a Dockerfile containing a single "FROM" statement.
    client
        .open_file_with_contents("Dockerfile", "FROM alpine")
        .await;

    // Request code lens on the line with the FROM statement (line 0).
    let response = client
        .request_available_code_lens_in_file("Dockerfile")
        .await;

    // Expect a CodeLens with the appropriate command.
    assert_eq!(
        response.unwrap(),
        vec![
            CodeLens {
                range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                command: Some(Command {
                    title: "Build and scan".to_string(),
                    command: "sysdig-lsp.execute-build-and-scan".to_string(),
                    arguments: Some(vec![json!("file://dockerfile/"), json!(0)])
                }),
                data: None
            },
            CodeLens {
                range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                command: Some(Command {
                    title: "Scan base image".to_string(),
                    command: "sysdig-lsp.execute-scan".to_string(),
                    arguments: Some(vec![json!("file://dockerfile/"), json!(0), json!("alpine")])
                }),
                data: None
            }
        ]
    );
}

#[tokio::test]
async fn when_the_client_asks_for_the_existing_code_lens_but_the_dockerfile_contains_multiple_froms_it_only_returns_the_latest()
 {
    let mut client = test::TestClient::new_initialized().await;
    client
        .open_file_with_contents("Dockerfile", "FROM alpine\nFROM ubuntu")
        .await;

    let response = client
        .request_available_code_lens_in_file("Dockerfile")
        .await;

    assert_eq!(
        response.unwrap(),
        vec![
            CodeLens {
                range: Range::new(Position::new(1, 0), Position::new(1, 0)),
                command: Some(Command {
                    title: "Build and scan".to_string(),
                    command: "sysdig-lsp.execute-build-and-scan".to_string(),
                    arguments: Some(vec![json!("file://dockerfile/"), json!(1)])
                }),
                data: None
            },
            CodeLens {
                range: Range::new(Position::new(1, 0), Position::new(1, 0)),
                command: Some(Command {
                    title: "Scan base image".to_string(),
                    command: "sysdig-lsp.execute-scan".to_string(),
                    arguments: Some(vec![json!("file://dockerfile/"), json!(1), json!("ubuntu")])
                }),
                data: None
            }
        ]
    );
}

#[tokio::test]
async fn when_the_client_asks_for_code_lens_in_a_compose_file_it_receives_them() {
    let mut client = test::TestClient::new_initialized().await;
    client
        .open_file_with_contents(
            "docker-compose.yml",
            include_str!("fixtures/docker-compose.yml"),
        )
        .await;

    let response = client
        .request_available_code_lens_in_file("docker-compose.yml")
        .await;

    assert_eq!(
        response.unwrap(),
        vec![
            CodeLens {
                range: Range::new(Position::new(2, 11), Position::new(2, 23)),
                command: Some(Command {
                    title: "Scan base image".to_string(),
                    command: "sysdig-lsp.execute-scan".to_string(),
                    arguments: Some(vec![
                        json!("file://docker-compose.yml/"),
                        json!(2),
                        json!("nginx:latest")
                    ])
                }),
                data: None
            },
            CodeLens {
                range: Range::new(Position::new(4, 11), Position::new(4, 22)),
                command: Some(Command {
                    title: "Scan base image".to_string(),
                    command: "sysdig-lsp.execute-scan".to_string(),
                    arguments: Some(vec![
                        json!("file://docker-compose.yml/"),
                        json!(4),
                        json!("postgres:13")
                    ])
                }),
                data: None
            }
        ]
    );
}

#[tokio::test]
async fn when_the_client_asks_for_code_actions_in_a_compose_file_it_receives_them() {
    let mut client = test::TestClient::new_initialized().await;
    client
        .open_file_with_contents(
            "docker-compose.yml",
            include_str!("fixtures/docker-compose.yml"),
        )
        .await;

    let response = client
        .request_available_actions_in_line("docker-compose.yml", 2)
        .await;

    assert_eq!(
        response.unwrap(),
        vec![CodeActionOrCommand::Command(Command {
            title: "Scan base image".to_string(),
            command: "sysdig-lsp.execute-scan".to_string(),
            arguments: Some(vec![
                json!("file://docker-compose.yml/"),
                json!(2),
                json!("nginx:latest")
            ])
        })]
    );
}

#[tokio::test]
async fn when_the_client_asks_for_code_lens_in_a_complex_compose_yaml_file_it_receives_them() {
    let mut client = test::TestClient::new_initialized().await;
    client
        .open_file_with_contents("compose.yaml", include_str!("fixtures/compose.yaml"))
        .await;

    let response = client
        .request_available_code_lens_in_file("compose.yaml")
        .await;

    assert_eq!(
        response.unwrap(),
        vec![
            CodeLens {
                range: Range::new(Position::new(4, 13), Position::new(4, 25)),
                command: Some(Command {
                    title: "Scan base image".to_string(),
                    command: "sysdig-lsp.execute-scan".to_string(),
                    arguments: Some(vec![
                        json!("file://compose.yaml/"),
                        json!(4),
                        json!("nginx:latest")
                    ])
                }),
                data: None
            },
            CodeLens {
                range: Range::new(Position::new(9, 6), Position::new(9, 17)),
                command: Some(Command {
                    title: "Scan base image".to_string(),
                    command: "sysdig-lsp.execute-scan".to_string(),
                    arguments: Some(vec![
                        json!("file://compose.yaml/"),
                        json!(9),
                        json!("postgres:13")
                    ])
                }),
                data: None
            },
            CodeLens {
                range: Range::new(Position::new(13, 11), Position::new(13, 21)),
                command: Some(Command {
                    title: "Scan base image".to_string(),
                    command: "sysdig-lsp.execute-scan".to_string(),
                    arguments: Some(vec![
                        json!("file://compose.yaml/"),
                        json!(13),
                        json!("my-api:1.0")
                    ])
                }),
                data: None
            }
        ]
    );
}
