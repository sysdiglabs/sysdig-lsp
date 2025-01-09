mod setup;

#[tokio::test]
async fn when_the_lsp_is_loaded_it_listens_on_a_port() {
    let lsp = setup::new_lsp();
    let client = setup::new_client(&lsp);

    assert!(client.can_connect_to_lsp().await);
}
