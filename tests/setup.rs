use sysdig_lsp::LSP;
use tower_lsp::lsp_types::InitializeParams;
use tower_lsp::LanguageServer;

pub struct Client<'a> {
    lsp: &'a LSP,
}

impl Client<'_> {
    pub async fn can_connect_to_lsp(&self) -> bool {
        self.lsp
            .initialize(InitializeParams::default())
            .await
            .is_ok()
    }
}

pub fn new_lsp() -> LSP {
    LSP::default()
}

pub fn new_client(lsp: &LSP) -> Client {
    Client { lsp }
}
