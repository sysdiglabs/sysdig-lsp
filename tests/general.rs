use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, MessageType, Position, Range};

mod test;

#[tokio::test]
async fn when_the_lsp_is_loaded_initializes_correctly() {
    let mut client = test::TestClient::new();
    let response = client.initialize_lsp().await;

    assert!(response.capabilities.code_action_provider.is_some());
    assert!(client
        .recordings()
        .received_log_messages()
        .await
        .contains(&(MessageType::INFO, "Sysdig LSP initialized!".to_string())))
}

#[tokio::test]
async fn when_the_file_contains_a_from_image_it_returns_available_actions() {
    let mut client = test::TestClient::new();
    client.initialize_lsp().await;

    client
        .open_file_with_contents(
            "Dockerfile",
            "\
FROM ubuntu
        ",
        )
        .await;

    assert_eq!(
        client.recordings().received_diagnostics().await.first(),
        Some(&Diagnostic {
            range: Range {
                start: Position {
                    line: 0,
                    character: 0
                },
                end: Position {
                    line: 0,
                    character: 4
                }
            },
            severity: Some(DiagnosticSeverity::WARNING),
            source: Some("sysdig-lsp".to_string()),
            message: "Vulnerabilities found: 5 Critical, 10 High, 12 Low, 50 Negligible"
                .to_string(),
            ..Default::default()
        })
    );
}
