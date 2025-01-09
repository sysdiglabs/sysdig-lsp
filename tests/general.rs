mod setup;

#[tokio::test]
async fn when_the_lsp_is_loaded_initializes_correctly() {
    let mut client = setup::new_lsp_client();

    let response = client.initialize_lsp().await;

    assert!(response.capabilities.code_action_provider.is_some());
}
