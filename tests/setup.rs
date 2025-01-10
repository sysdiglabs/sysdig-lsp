use sysdig_lsp::LSP;
use tower_lsp::lsp_types::{InitializeParams, InitializeResult, InitializedParams};
use tower_lsp::LanguageServer;
use tower_lsp::LspService;

pub struct Client {
    service: LspService<LSP>,
}

impl Client {
    pub async fn initialize_lsp(&mut self) -> InitializeResult {
        let lsp = self.service.inner();

        let result = lsp
            .initialize(InitializeParams::default())
            .await
            .expect("initialize failed");

        lsp.initialized(InitializedParams {}).await;

        result
    }
}

pub fn new_lsp_client() -> Client {
    let (service, _) = LspService::new(|client| LSP::new(client));

    return Client { service };
}
