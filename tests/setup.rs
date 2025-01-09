use std::collections::HashMap;
use std::io;
use std::path::Path;

use sysdig_lsp::{Filesystem, LSP};
use tower_lsp::lsp_types::{InitializeParams, InitializeResult, InitializedParams};
use tower_lsp::LanguageServer;
use tower_lsp::LspService;

pub struct Client {
    service: LspService<LSP<FakeFilesystem>>,
}

#[derive(Default)]
struct FakeFilesystem {
    files: HashMap<String, String>,
}

#[async_trait::async_trait]
impl Filesystem for FakeFilesystem {
    async fn read_file<A: AsRef<Path> + Send>(&self, path: A) -> io::Result<String> {
        self.files
            .get(&path.as_ref().to_string_lossy().into_owned())
            .cloned()
            .ok_or(io::Error::new(io::ErrorKind::NotFound, "not found"))
    }
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
    let (service, _) = LspService::new(|client| LSP::new(client, FakeFilesystem::default()));

    return Client { service };
}
