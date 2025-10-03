use serde_json::Value;
use std::borrow::Cow;
use tokio::sync::RwLock;
use tower_lsp::LanguageServer;
use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::{
    CodeActionParams, CodeActionResponse, CodeLens, CodeLensParams, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandParams, Hover,
    HoverParams, InitializeParams, InitializeResult, InitializedParams, Range,
};

use super::{InMemoryDocumentDatabase, LSPClient};

pub mod command_generator;
pub mod commands;
mod lsp_server_inner;
pub mod supported_commands;
use crate::app::component_factory::ComponentFactory;
use lsp_server_inner::LSPServerInner;

pub trait WithContext {
    fn with_message(self, message: impl Into<Cow<'static, str>>) -> Self;
}

impl WithContext for Error {
    fn with_message(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        self.message = message.into();
        self
    }
}

pub struct LSPServer<C, F: ComponentFactory> {
    inner: RwLock<LSPServerInner<C, F>>,
}

impl<C, F: ComponentFactory> LSPServer<C, F> {
    pub fn new(client: C, component_factory: F) -> LSPServer<C, F> {
        LSPServer {
            inner: RwLock::new(LSPServerInner::new(client, component_factory)),
        }
    }
}

struct CommandInfo {
    title: String,
    command: String,
    arguments: Option<Vec<Value>>,
    range: Range,
}

#[async_trait::async_trait]
impl<C, F> LanguageServer for LSPServer<C, F>
where
    C: LSPClient + Send + Sync + 'static,
    F: ComponentFactory + Send + Sync + 'static,
{
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        self.inner.write().await.initialize(params).await
    }

    async fn initialized(&self, params: InitializedParams) {
        self.inner.read().await.initialized(params).await
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        self.inner
            .write()
            .await
            .did_change_configuration(params)
            .await
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.inner.read().await.did_open(params).await
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        self.inner.read().await.did_change(params).await
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        self.inner.read().await.code_action(params).await
    }

    async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        self.inner.read().await.code_lens(params).await
    }

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        self.inner.read().await.execute_command(params).await
    }

    async fn hover(&self, _params: HoverParams) -> Result<Option<Hover>> {
        Ok(Some(Hover {
            contents: tower_lsp::lsp_types::HoverContents::Markup(
                tower_lsp::lsp_types::MarkupContent {
                    kind: tower_lsp::lsp_types::MarkupKind::Markdown,
                    value: "## Sysdig Scan Result
### Summary
* **Type**: dockerImage
* **PullString**: ubuntu:23.04
* **ImageID**: `sha256:f4cdeba72b994748f5eb1f525a70a9cc553b66037ec37e23645fbf3f0f5c160d`
* **Digest**: `sha256:5a828e28de105c3d7821c4442f0f5d1c52dc16acf4999d5f31a3bc0f03f06edd`
* **BaseOS**: ubuntu 23.04

| TOTAL VULNS FOUND  | CRITICAL | HIGH | MEDIUM         | LOW            | NEGLIGIBLE |
|:------------------:|:--------:|:----:|:--------------:|:--------------:|:----------:|
| 11                 | 0        | 0    | 9 (9 Fixable)  | 2 (2 Fixable)  | 0          |

### Fixable Packages
| PACKAGE            | TYPE | VERSION                | SUGGESTED FIX          | CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE | EXPLOIT |
|:-------------------|:----:|:-----------------------|:-----------------------|:--------:|:----:|:------:|:---:|:----------:|:-------:|
| libgnutls30        | os   | 3.7.8-5ubuntu1.1       | 3.7.8-5ubuntu1.2       | -        | -    | 2      | -   | -          | -       |
| libc-bin           | os   | 2.37-0ubuntu2.1        | 2.37-0ubuntu2.2        | -        | -    | 1      | 1   | -          | -       |
| libc6              | os   | 2.37-0ubuntu2.1        | 2.37-0ubuntu2.2        | -        | -    | 1      | 1   | -          | -       |
| libpam-modules     | os   | 1.5.2-5ubuntu1         | 1.5.2-5ubuntu1.1       | -        | -    | 1      | -   | -          | -       |
| libpam-modules-bin | os   | 1.5.2-5ubuntu1         | 1.5.2-5ubuntu1.1       | -        | -    | 1      | -   | -          | -       |
| libpam-runtime     | os   | 1.5.2-5ubuntu1         | 1.5.2-5ubuntu1.1       | -        | -    | 1      | -   | -          | -       |
| libpam0g           | os   | 1.5.2-5ubuntu1         | 1.5.2-5ubuntu1.1       | -        | -    | 1      | -   | -          | -       |
| tar                | os   | 1.34+dfsg-1.2ubuntu0.1 | 1.34+dfsg-1.2ubuntu0.2 | -        | -    | 1      | -   | -          | -       |

### Policy Evaluation

| POLICY                                | STATUS | FAILURES | RISKS ACCEPTED |
|:--------------------------------------|:------:|:--------:|:--------------:|
| carholder policy - pk                 | ❌     | 1        | 0              |
| Critical Vulnerability Found          | ✅     | 0        | 0              |
| Forbid Secrets in Images              | ✅     | 0        | 0              |
| NIST SP 800-Star                      | ❌     | 14       | 0              |
| PolicyCardHolder                      | ❌     | 1        | 0              |
| Sensitive Information or Secret Found | ✅     | 0        | 0              |
| Sysdig Best Practices                 | ✅     | 0        | 0              |

### Vulnerability Detail

| VULN CVE      | SEVERITY | PACKAGES | FIXABLE | EXPLOITABLE | ACCEPTED RISK | AGE         |
|---------------|----------|----------|---------|-------------|---------------|-------------|
| CVE-2024-22365| Medium   | 4        | ✅      | ❌          | ❌            | 2 years ago |
| CVE-2023-5156 | Medium   | 2        | ✅      | ❌          | ❌            | 2 years ago |
| CVE-2023-39804| Medium   | 1        | ✅      | ❌          | ❌            | 2 years ago |
| CVE-2024-0553 | Medium   | 1        | ✅      | ❌          | ❌            | 2 years ago |
| CVE-2024-0567 | Medium   | 1        | ✅      | ❌          | ❌            | 2 years ago |
| CVE-2023-4806 | Low      | 2        | ✅      | ❌          | ❌            | 2 years ago |
"
                    .to_string(),
                },
            ),
            range: None,
        }))
    }

    async fn shutdown(&self) -> Result<()> {
        self.inner.read().await.shutdown().await
    }
}
