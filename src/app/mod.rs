pub mod component_factory;
mod document_database;
mod iac_scanner;
mod image_builder;
mod image_scanner;
mod lsp_client;
mod lsp_interactor;
mod lsp_server;
mod markdown;
mod queries;

pub use document_database::*;
pub use iac_scanner::{IacScanError, IacScanScope, IacScanner};

/// `Diagnostic.source` tags identifying which scan type produced a diagnostic.
/// Each producer replaces only its own diagnostics, so different scan types
/// coexist on the same document with independent lifecycles.
pub const IAC_DIAGNOSTIC_SOURCE: &str = "sysdig-iac";
pub const VULN_DIAGNOSTIC_SOURCE: &str = "sysdig-vuln";
pub use image_builder::{ImageBuildError, ImageBuildResult, ImageBuilder};
pub use image_scanner::{ImageScanError, ImageScanner};
pub use lsp_client::LSPClient;
pub use lsp_interactor::LspInteractor;
pub use lsp_server::LSPServer;
