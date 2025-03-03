use serde_json::json;
use tower_lsp::lsp_types::{CodeActionOrCommand, Command, MessageType};

mod test;

#[tokio::test]
async fn when_the_lsp_is_loaded_initializes_correctly() {
    let mut client = test::TestClient::new();
    let response = client.initialize_lsp().await;

    assert!(response.capabilities.code_action_provider.is_some());
    assert!(client
        .recorder()
        .received_log_messages()
        .await
        .contains(&(MessageType::INFO, "Sysdig LSP initialized!".to_string())))
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
        vec![CodeActionOrCommand::Command(Command {
            title: "Run function".to_string(),
            command: "execute_scan".to_string(),
            arguments: Some(vec![json!("file://dockerfile/"), json!(0)])
        })]
    );
}

#[tokio::test]
async fn when_the_client_executes_the_scan_image_code_action_it_receives_the_vulnerabilities() {
    let mut client = test::TestClient::new_initialized().await;

    client
        .open_file_with_contents("Dockerfile", "FROM alpine")
        .await;

    client
        .execute_action("execute_scan", &[json!("file://dockerfile/"), json!(0)])
        .await;

    let received_diagnostics = client
        .recorder()
        .diagnostics_displayed_for_file("file://dockerfile/")
        .await
        .unwrap();
    assert_eq!(received_diagnostics.len(), 1);
    assert_eq!(received_diagnostics.iter().filter(|x| x.message == "Vulnerabilities for alpine: 1 Critical, 2 High, 6 Medium, 10 Low, 50 Negligible. At least, lol").count(), 1)
}
