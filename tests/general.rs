mod common;

use common::TestSetup;
use rstest::{fixture, rstest};
use serde_json::json;
use std::collections::HashMap;
use sysdig_lsp::domain::scanresult::architecture::Architecture;
use sysdig_lsp::domain::scanresult::evaluation_result::EvaluationResult;
use sysdig_lsp::domain::scanresult::operating_system::{Family, OperatingSystem};
use sysdig_lsp::domain::scanresult::scan_result::ScanResult;
use sysdig_lsp::domain::scanresult::scan_type::ScanType;
use tower_lsp::LanguageServer;
use tower_lsp::lsp_types::{
    CodeActionContext, CodeActionParams, DiagnosticSeverity, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, ExecuteCommandParams, HoverParams,
    InitializeParams, PartialResultParams, Position, Range, TextDocumentIdentifier,
    TextDocumentItem, TextDocumentPositionParams, Url, VersionedTextDocumentIdentifier,
    WorkDoneProgressParams,
};

#[fixture]
async fn initialized_server() -> TestSetup {
    let setup = TestSetup::new();
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": {
                "apiUrl": "http://localhost:8080",
                "api_token": "dummy-token"
            }
        })),
        ..Default::default()
    };
    let result = setup.server.initialize(params).await;
    assert!(result.is_ok());
    setup
}

#[rstest]
#[tokio::test]
async fn test_initialize_advertises_all_supported_commands() {
    let setup = TestSetup::new();
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
        })),
        ..Default::default()
    };
    let result = setup.server.initialize(params).await.unwrap();

    let advertised = result
        .capabilities
        .execute_command_provider
        .expect("executeCommand capability must be advertised")
        .commands;
    for command in [
        "sysdig-lsp.execute-scan",
        "sysdig-lsp.execute-build-and-scan",
        "sysdig-lsp.execute-iac-scan",
    ] {
        assert!(
            advertised.iter().any(|c| c == command),
            "clients gate executeCommand on advertised capabilities; missing: {command}"
        );
    }
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_did_change_configuration(#[future] initialized_server: TestSetup) {
    let params = DidChangeConfigurationParams {
        settings: serde_json::json!({
            "sysdig": {
                "apiUrl": "http://localhost:8080",
                "api_token": "dummy-token"
            }
        }),
    };
    initialized_server
        .server
        .did_change_configuration(params)
        .await;
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_did_open(#[future] initialized_server: TestSetup) {
    let params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem::new(
            "file:///Dockerfile".parse().unwrap(),
            "dockerfile".to_string(),
            1,
            "FROM alpine".to_string(),
        ),
    };
    initialized_server.server.did_open(params).await;
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_did_change(#[future] initialized_server: TestSetup) {
    let params = DidChangeTextDocumentParams {
        text_document: VersionedTextDocumentIdentifier::new(
            "file:///Dockerfile".parse().unwrap(),
            1,
        ),
        content_changes: vec![],
    };
    initialized_server.server.did_change(params).await;
}

#[fixture]
fn open_file_url() -> Url {
    "file:///Dockerfile".parse().unwrap()
}

#[fixture]
#[awt]
async fn server_with_open_file(
    #[future] initialized_server: TestSetup,
    open_file_url: Url,
) -> TestSetup {
    initialized_server
        .server
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem::new(
                open_file_url.clone(),
                "dockerfile".to_string(),
                1,
                "FROM alpine".to_string(),
            ),
        })
        .await;
    initialized_server
}

use sysdig_lsp::domain::scanresult::{package_type::PackageType, severity::Severity};

#[fixture]
fn scan_result() -> ScanResult {
    let mut result = ScanResult::new(
        ScanType::Docker,
        "alpine:latest".to_string(),
        "sha256:12345".to_string(),
        Some("sha256:67890".to_string()),
        OperatingSystem::new(Family::Linux, "alpine:3.18".to_string()),
        123456,
        Architecture::Amd64,
        HashMap::new(),
        chrono::Utc::now(),
        EvaluationResult::Passed,
    );

    let layer = result.add_layer(
        "sha256:layer1".to_string(),
        0,
        Some(1024),
        "COPY . .".to_string(),
    );

    let package1 = result.add_package(
        PackageType::Os,
        "package1".to_string(),
        "1.0.0".to_string(),
        "/usr/lib/package1".to_string(),
        layer.clone(),
    );

    result.add_package(
        PackageType::Os,
        "package2".to_string(),
        "2.0.0".to_string(),
        "/usr/lib/package2".to_string(),
        layer,
    );

    let vulnerability = result.add_vulnerability(
        "CVE-2021-1234".to_string(),
        Severity::High,
        chrono::NaiveDate::from_ymd_opt(2021, 1, 1).unwrap(),
        None,
        false,
        Some("1.0.1".to_string()),
    );

    package1.add_vulnerability_found(vulnerability);

    result
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_code_action(#[future] server_with_open_file: TestSetup, open_file_url: Url) {
    let params = CodeActionParams {
        text_document: TextDocumentIdentifier::new(open_file_url),
        range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        context: CodeActionContext::default(),
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };
    let result = server_with_open_file
        .server
        .code_action(params)
        .await
        .unwrap()
        .unwrap();

    let mut result_json = serde_json::to_value(result).unwrap();
    // Sort by command title to have a deterministic order for comparison
    result_json.as_array_mut().unwrap().sort_by(|a, b| {
        a["title"]
            .as_str()
            .unwrap()
            .cmp(b["title"].as_str().unwrap())
    });

    let expected_json = serde_json::json!([
        {
            "arguments": [
                {
                    "range": {
                        "end": { "character": 11, "line": 0 },
                        "start": { "character": 0, "line": 0 }
                    },
                    "uri": "file:///Dockerfile"
                }
            ],
            "command": "sysdig-lsp.execute-build-and-scan",
            "title": "Build and scan"
        },
        {
            "arguments": [
                {
                    "range": {
                        "end": { "character": 11, "line": 0 },
                        "start": { "character": 0, "line": 0 }
                    },
                    "uri": "file:///Dockerfile"
                },
                "alpine"
            ],
            "command": "sysdig-lsp.execute-scan",
            "title": "Scan base image"
        }
    ]);

    assert_eq!(result_json, expected_json);
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_code_lens(#[future] server_with_open_file: TestSetup, open_file_url: Url) {
    let params = tower_lsp::lsp_types::CodeLensParams {
        text_document: TextDocumentIdentifier::new(open_file_url),
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let result = server_with_open_file
        .server
        .code_lens(params)
        .await
        .unwrap()
        .unwrap();

    let mut result_json = serde_json::to_value(result).unwrap();
    // Sort by command title to have a deterministic order for comparison
    result_json.as_array_mut().unwrap().sort_by(|a, b| {
        a["command"]["title"]
            .as_str()
            .unwrap()
            .cmp(b["command"]["title"].as_str().unwrap())
    });

    let expected_json = serde_json::json!([
        {
            "command": {
                "arguments": [
                    {
                        "range": {
                            "end": { "character": 11, "line": 0 },
                            "start": { "character": 0, "line": 0 }
                        },
                        "uri": "file:///Dockerfile"
                    }
                ],
                "command": "sysdig-lsp.execute-build-and-scan",
                "title": "Build and scan"
            },
            "range": {
                "end": { "character": 11, "line": 0 },
                "start": { "character": 0, "line": 0 }
            }
        },
        {
            "command": {
                "arguments": [
                    {
                        "range": {
                            "end": { "character": 11, "line": 0 },
                            "start": { "character": 0, "line": 0 }
                        },
                        "uri": "file:///Dockerfile"
                    },
                    "alpine"
                ],
                "command": "sysdig-lsp.execute-scan",
                "title": "Scan base image"
            },
            "range": {
                "end": { "character": 11, "line": 0 },
                "start": { "character": 0, "line": 0 }
            }
        }
    ]);

    assert_eq!(result_json, expected_json);
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_execute_command(
    #[future] server_with_open_file: TestSetup,
    open_file_url: Url,
    scan_result: ScanResult,
) {
    server_with_open_file
        .component_factory
        .image_scanner
        .lock()
        .await
        .expect_scan_image()
        .with(mockall::predicate::eq("alpine"))
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    server_with_open_file
        .client_recorder
        .diagnostics
        .lock()
        .await
        .clear();

    let params = ExecuteCommandParams {
        command: "sysdig-lsp.execute-scan".to_string(),
        arguments: vec![
            json!({"range":{"end":{"character":11,"line":0},"start":{"character": 0,"line":0}},"uri":open_file_url}),
            json!("alpine"),
        ],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    let result = server_with_open_file.server.execute_command(params).await;
    assert!(result.is_ok());

    let diagnostics = server_with_open_file
        .client_recorder
        .diagnostics
        .lock()
        .await;
    assert_eq!(diagnostics.len(), 1);
    let diagnostic = &diagnostics[0].1[0];
    assert_eq!(
        diagnostic.message,
        "Vulnerabilities found for alpine: 0 Critical, 1 High, 0 Medium, 0 Low, 0 Negligible"
    );
    assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::ERROR));
    assert_eq!(
        diagnostic.range,
        Range::new(Position::new(0, 0), Position::new(0, 11))
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_hover(
    #[future] server_with_open_file: TestSetup,
    open_file_url: Url,
    scan_result: ScanResult,
) {
    // Given
    server_with_open_file
        .component_factory
        .image_scanner
        .lock()
        .await
        .expect_scan_image()
        .with(mockall::predicate::eq("alpine"))
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    let params = ExecuteCommandParams {
        command: "sysdig-lsp.execute-scan".to_string(),
        arguments: vec![
            json!({"range":{"end":{"character":11,"line":0},"start":{"character": 0,"line":0}},"uri":open_file_url.clone()}),
            json!("alpine"),
        ],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    let result = server_with_open_file.server.execute_command(params).await;
    assert!(result.is_ok());

    // When
    let params = HoverParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier::new(open_file_url),
            position: Position::new(0, 5), // Position inside "alpine"
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    let result = server_with_open_file.server.hover(params).await;
    assert!(result.is_ok());
    let hover = result.unwrap().unwrap();

    // Then
    let expected_markdown = r#"## Sysdig Scan Result
### Summary
* **PullString**: alpine:latest
* **ImageID**: `sha256:12345`
* **Digest**: `sha256:67890`
* **BaseOS**: alpine:3.18

| TOTAL VULNS FOUND | CRITICAL |     HIGH      | MEDIUM | LOW | NEGLIGIBLE |
|-------------------|----------|---------------|--------|-----|------------|
|         1         |    0     | 1 (1 Fixable) |   0    |  0  |     0      |

### Fixable Packages
| PACKAGE  | TYPE | VERSION | SUGGESTED FIX | CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE | EXPLOIT |
|----------|------|---------|---------------|----------|------|--------|-----|------------|---------|
| package1 |  os  | 1.0.0   | 1.0.1         |    -     |  1   |   -    |  -  |     -      |    -    |


### Vulnerability Detail

| VULN CVE      | SEVERITY | PACKAGES | FIXABLE | EXPLOITABLE | ACCEPTED RISK |
|---------------|----------|----------|---------|-------------|---------------|
| CVE-2021-1234 | High     | 1        | ✅      | ❌          | ❌            |"#;

    let expected_json = serde_json::json!({
        "contents": {
            "kind": "markdown",
            "value": expected_markdown.to_string()
        }
    });
    assert_eq!(serde_json::to_value(hover).unwrap(), expected_json);
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_shutdown(#[future] initialized_server: TestSetup) {
    let result = initialized_server.server.shutdown().await;
    assert!(result.is_ok());
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_k8s_manifest_code_lens(#[future] initialized_server: TestSetup) {
    let k8s_url: Url = "file:///deployment.yaml".parse().unwrap();
    let k8s_content = include_str!("fixtures/k8s-deployment.yaml");

    initialized_server
        .server
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem::new(
                k8s_url.clone(),
                "yaml".to_string(),
                1,
                k8s_content.to_string(),
            ),
        })
        .await;

    let params = tower_lsp::lsp_types::CodeLensParams {
        text_document: TextDocumentIdentifier::new(k8s_url.clone()),
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let result = initialized_server
        .server
        .code_lens(params)
        .await
        .unwrap()
        .unwrap();

    let result_json = serde_json::to_value(result).unwrap();

    let expected_json = serde_json::json!([
        {
            "command": {
                "arguments": ["file:///deployment.yaml"],
                "command": "sysdig-lsp.execute-iac-scan",
                "title": "Scan IaC file"
            },
            "range": {
                "end": { "character": 0, "line": 0 },
                "start": { "character": 0, "line": 0 }
            }
        },
        {
            "command": {
                "arguments": [
                    {
                        "range": {
                            "end": { "character": 25, "line": 10 },
                            "start": { "character": 15, "line": 10 }
                        },
                        "uri": "file:///deployment.yaml"
                    },
                    "nginx:1.19"
                ],
                "command": "sysdig-lsp.execute-scan",
                "title": "Scan base image"
            },
            "range": {
                "end": { "character": 25, "line": 10 },
                "start": { "character": 15, "line": 10 }
            }
        }
    ]);

    assert_eq!(result_json, expected_json);
}

use std::path::PathBuf;
use sysdig_lsp::app::{IacScanError, IacScanScope};
use sysdig_lsp::domain::iacscanresult::{
    iac_finding::IacFinding, iac_resource::IacResource, iac_scan_result::IacScanResult,
    iac_severity::IacSeverity,
};
use tower_lsp::lsp_types::MessageType;

fn file_scope(uri: &str, path: &str) -> IacScanScope {
    IacScanScope::File {
        uri: uri.parse().unwrap(),
        path: PathBuf::from(path),
    }
}

fn iac_finding_for(source: &str, name: &str) -> IacFinding {
    IacFinding {
        name: name.to_string(),
        severity: IacSeverity::High,
        resources: vec![IacResource {
            source: PathBuf::from(source),
            location: "spec.template.spec.containers[0]".to_string(),
            resource_type: "Deployment".to_string(),
            name: "nginx-deployment".to_string(),
        }],
    }
}

fn execute_iac_scan_params(arguments: Vec<serde_json::Value>) -> ExecuteCommandParams {
    ExecuteCommandParams {
        command: "sysdig-lsp.execute-iac-scan".to_string(),
        arguments,
        work_done_progress_params: WorkDoneProgressParams::default(),
    }
}

fn last_published_diagnostics_for<'a>(
    published: &'a [(String, Vec<tower_lsp::lsp_types::Diagnostic>)],
    url: &str,
) -> Option<&'a Vec<tower_lsp::lsp_types::Diagnostic>> {
    published
        .iter()
        .rev()
        .find(|(u, _)| u == url)
        .map(|(_, d)| d)
}

#[fixture]
#[awt]
async fn server_with_open_k8s_manifest(#[future] initialized_server: TestSetup) -> TestSetup {
    initialized_server
        .server
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem::new(
                "file:///deployment.yaml".parse().unwrap(),
                "yaml".to_string(),
                1,
                include_str!("fixtures/k8s-deployment.yaml").to_string(),
            ),
        })
        .await;
    initialized_server
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_execute_iac_scan_for_single_file(#[future] server_with_open_k8s_manifest: TestSetup) {
    let scan_result = IacScanResult {
        findings: vec![iac_finding_for(
            "/deployment.yaml",
            "Container runs without memory limits",
        )],
    };
    server_with_open_k8s_manifest
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .withf(|scope| *scope == file_scope("file:///deployment.yaml", "/deployment.yaml"))
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    server_with_open_k8s_manifest
        .client_recorder
        .diagnostics
        .lock()
        .await
        .clear();

    let result = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;
    assert!(result.is_ok());

    let diagnostics = server_with_open_k8s_manifest
        .client_recorder
        .diagnostics
        .lock()
        .await;
    let diags_for_file = last_published_diagnostics_for(&diagnostics, "file:///deployment.yaml")
        .expect("no diagnostics published for the scanned file");

    assert_eq!(diags_for_file.len(), 1);
    let diagnostic = &diags_for_file[0];
    assert_eq!(
        diagnostic.message,
        "Container runs without memory limits: spec.template.spec.containers[0] (Deployment: nginx-deployment)"
    );
    assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::ERROR));
    assert_eq!(
        diagnostic.range,
        Range::new(Position::new(0, 0), Position::new(0, 0))
    );
    assert_eq!(diagnostic.source.as_deref(), Some("sysdig-iac"));
}

#[rstest]
#[tokio::test]
async fn test_execute_iac_scan_for_workspace_publishes_multiple_files() {
    let setup = TestSetup::new();
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": {
                "apiUrl": "http://localhost:8080",
                "api_token": "dummy-token"
            }
        })),
        workspace_folders: Some(vec![tower_lsp::lsp_types::WorkspaceFolder {
            uri: "file:///workspace".parse().unwrap(),
            name: "workspace".to_string(),
        }]),
        ..Default::default()
    };
    assert!(setup.server.initialize(params).await.is_ok());

    let scan_result = IacScanResult {
        findings: vec![
            iac_finding_for("/workspace/a.yaml", "Finding in a"),
            iac_finding_for("/workspace/subdir/b.yaml", "Finding in b"),
        ],
    };
    setup
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .withf(|scope| *scope == IacScanScope::Directory(PathBuf::from("/workspace")))
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    let result = setup
        .server
        .execute_command(execute_iac_scan_params(vec![]))
        .await;
    assert!(result.is_ok());

    let diagnostics = setup.client_recorder.diagnostics.lock().await;
    let diags_a = last_published_diagnostics_for(&diagnostics, "file:///workspace/a.yaml")
        .expect("no diagnostics for a.yaml");
    let diags_b = last_published_diagnostics_for(&diagnostics, "file:///workspace/subdir/b.yaml")
        .expect("no diagnostics for subdir/b.yaml");

    assert_eq!(diags_a.len(), 1);
    assert!(diags_a[0].message.starts_with("Finding in a"));
    assert_eq!(diags_b.len(), 1);
    assert!(diags_b[0].message.starts_with("Finding in b"));
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_iac_rescan_clears_stale_diagnostics(
    #[future] server_with_open_k8s_manifest: TestSetup,
) {
    let scan_result = IacScanResult {
        findings: vec![iac_finding_for("/deployment.yaml", "Stale finding")],
    };
    {
        let mut scanner = server_with_open_k8s_manifest
            .component_factory
            .iac_scanner
            .lock()
            .await;
        scanner
            .expect_scan_iac()
            .times(1)
            .returning(move |_| Ok(scan_result.clone()));
        scanner
            .expect_scan_iac()
            .times(1)
            .returning(|_| Ok(IacScanResult::default()));
    }

    let first = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;
    assert!(first.is_ok());
    let second = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;
    assert!(second.is_ok());

    let diagnostics = server_with_open_k8s_manifest
        .client_recorder
        .diagnostics
        .lock()
        .await;
    let last = last_published_diagnostics_for(&diagnostics, "file:///deployment.yaml")
        .expect("no diagnostics published for the scanned file");
    assert!(
        last.is_empty(),
        "stale IaC diagnostics were not cleared: {last:?}"
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_iac_scan_preserves_image_scan_diagnostics(
    #[future] server_with_open_k8s_manifest: TestSetup,
    scan_result: ScanResult,
) {
    // First, an image scan on the same document produces a vulnerability diagnostic
    server_with_open_k8s_manifest
        .component_factory
        .image_scanner
        .lock()
        .await
        .expect_scan_image()
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    let image_scan = server_with_open_k8s_manifest
        .server
        .execute_command(ExecuteCommandParams {
            command: "sysdig-lsp.execute-scan".to_string(),
            arguments: vec![
                json!({"range":{"end":{"character":25,"line":10},"start":{"character":15,"line":10}},"uri":"file:///deployment.yaml"}),
                json!("nginx:1.19"),
            ],
            work_done_progress_params: WorkDoneProgressParams::default(),
        })
        .await;
    assert!(image_scan.is_ok());

    // Then an IaC scan on the same file
    let iac_result = IacScanResult {
        findings: vec![iac_finding_for("/deployment.yaml", "IaC finding")],
    };
    server_with_open_k8s_manifest
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(1)
        .returning(move |_| Ok(iac_result.clone()));

    let iac_scan = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;
    assert!(iac_scan.is_ok());

    let diagnostics = server_with_open_k8s_manifest
        .client_recorder
        .diagnostics
        .lock()
        .await;
    let last = last_published_diagnostics_for(&diagnostics, "file:///deployment.yaml")
        .expect("no diagnostics published");

    let sources: Vec<_> = last.iter().filter_map(|d| d.source.as_deref()).collect();
    assert!(
        sources.contains(&"sysdig-vuln") && sources.contains(&"sysdig-iac"),
        "both scan types must coexist on the same document, got: {sources:?}"
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_execute_iac_scan_shows_error_when_scanner_fails(
    #[future] server_with_open_k8s_manifest: TestSetup,
) {
    server_with_open_k8s_manifest
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(1)
        .returning(|_| Err(IacScanError::InternalScannerError("boom".into())));

    let result = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;
    assert!(result.is_err());

    let messages = server_with_open_k8s_manifest
        .client_recorder
        .messages
        .lock()
        .await;
    assert!(
        messages
            .iter()
            .any(|(t, m)| *t == MessageType::ERROR && m.contains("boom")),
        "expected an ERROR message to be shown to the client, got: {messages:?}"
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_execute_iac_scan_without_workspace_root_fails(
    #[future] initialized_server: TestSetup,
) {
    let result = initialized_server
        .server
        .execute_command(execute_iac_scan_params(vec![]))
        .await;

    let err = result.expect_err("should fail without a workspace root");
    assert!(err.message.contains("no workspace root"));
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_iac_lens_is_offered_even_if_image_parsing_fails(
    #[future] initialized_server: TestSetup,
) {
    let compose_url: Url = "file:///docker-compose.yml".parse().unwrap();
    initialized_server
        .server
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem::new(
                compose_url.clone(),
                "yaml".to_string(),
                1,
                "services: [broken".to_string(),
            ),
        })
        .await;

    let result = initialized_server
        .server
        .code_lens(tower_lsp::lsp_types::CodeLensParams {
            text_document: TextDocumentIdentifier::new(compose_url),
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        })
        .await
        .unwrap()
        .unwrap();

    // The IaC scan doesn't need parseable image instructions: the CLI scanner
    // parses the file itself, so the lens survives image parse failures.
    assert_eq!(result.len(), 1);
    let lens = serde_json::to_value(&result[0]).unwrap();
    assert_eq!(lens["command"]["command"], "sysdig-lsp.execute-iac-scan");
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_iac_scan_aggregates_multiple_findings_on_the_same_file(
    #[future] server_with_open_k8s_manifest: TestSetup,
) {
    let scan_result = IacScanResult {
        findings: vec![
            iac_finding_for("/deployment.yaml", "First finding"),
            iac_finding_for("/deployment.yaml", "Second finding"),
        ],
    };
    server_with_open_k8s_manifest
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    let result = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;
    assert!(result.is_ok());

    let diagnostics = server_with_open_k8s_manifest
        .client_recorder
        .diagnostics
        .lock()
        .await;
    let last = last_published_diagnostics_for(&diagnostics, "file:///deployment.yaml")
        .expect("no diagnostics published");

    assert_eq!(last.len(), 2);
    let messages: Vec<_> = last.iter().map(|d| d.message.as_str()).collect();
    assert!(messages[0].starts_with("First finding"));
    assert!(messages[1].starts_with("Second finding"));
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_execute_iac_scan_maps_invalid_configuration_to_invalid_params(
    #[future] server_with_open_k8s_manifest: TestSetup,
) {
    server_with_open_k8s_manifest
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(1)
        .returning(|_| Err(IacScanError::InvalidConfiguration("bad token".to_string())));

    let result = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;

    let err = result.expect_err("should fail with invalid configuration");
    assert_eq!(err.code, tower_lsp::jsonrpc::ErrorCode::InvalidParams);
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_execute_iac_scan_rejects_non_file_uris(#[future] initialized_server: TestSetup) {
    let result = initialized_server
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "https://example.com/deployment.yaml"
        )]))
        .await;

    let err = result.expect_err("should reject non-file URIs");
    assert!(err.message.contains("only file:// URIs are supported"));
}

#[rstest]
#[tokio::test]
async fn test_workspace_root_falls_back_to_root_uri() {
    let setup = TestSetup::new();
    #[allow(deprecated)]
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
        })),
        root_uri: Some("file:///workspace".parse().unwrap()),
        ..Default::default()
    };
    assert!(setup.server.initialize(params).await.is_ok());

    setup
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .withf(|scope| *scope == IacScanScope::Directory(PathBuf::from("/workspace")))
        .times(1)
        .returning(|_| Ok(IacScanResult::default()));

    let result = setup
        .server
        .execute_command(execute_iac_scan_params(vec![]))
        .await;
    assert!(result.is_ok());
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_image_rescan_preserves_iac_diagnostics(
    #[future] server_with_open_k8s_manifest: TestSetup,
    scan_result: ScanResult,
) {
    // IaC scan first
    let iac_result = IacScanResult {
        findings: vec![iac_finding_for("/deployment.yaml", "IaC finding")],
    };
    server_with_open_k8s_manifest
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(1)
        .returning(move |_| Ok(iac_result.clone()));

    let iac_scan = server_with_open_k8s_manifest
        .server
        .execute_command(execute_iac_scan_params(vec![json!(
            "file:///deployment.yaml"
        )]))
        .await;
    assert!(iac_scan.is_ok());

    // Image scan afterwards must not wipe the IaC findings
    server_with_open_k8s_manifest
        .component_factory
        .image_scanner
        .lock()
        .await
        .expect_scan_image()
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    let image_scan = server_with_open_k8s_manifest
        .server
        .execute_command(ExecuteCommandParams {
            command: "sysdig-lsp.execute-scan".to_string(),
            arguments: vec![
                json!({"range":{"end":{"character":25,"line":10},"start":{"character":15,"line":10}},"uri":"file:///deployment.yaml"}),
                json!("nginx:1.19"),
            ],
            work_done_progress_params: WorkDoneProgressParams::default(),
        })
        .await;
    assert!(image_scan.is_ok());

    let diagnostics = server_with_open_k8s_manifest
        .client_recorder
        .diagnostics
        .lock()
        .await;
    let last = last_published_diagnostics_for(&diagnostics, "file:///deployment.yaml")
        .expect("no diagnostics published");

    let sources: Vec<_> = last.iter().filter_map(|d| d.source.as_deref()).collect();
    assert!(
        sources.contains(&"sysdig-vuln") && sources.contains(&"sysdig-iac"),
        "image rescan must preserve IaC diagnostics, got: {sources:?}"
    );
}

#[rstest]
#[tokio::test]
async fn test_workspace_rescan_clears_files_dropped_from_the_report() {
    let setup = TestSetup::new();
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
        })),
        workspace_folders: Some(vec![tower_lsp::lsp_types::WorkspaceFolder {
            uri: "file:///workspace".parse().unwrap(),
            name: "workspace".to_string(),
        }]),
        ..Default::default()
    };
    assert!(setup.server.initialize(params).await.is_ok());

    {
        let mut scanner = setup.component_factory.iac_scanner.lock().await;
        let first_result = IacScanResult {
            findings: vec![
                iac_finding_for("/workspace/a.yaml", "Finding in a"),
                iac_finding_for("/workspace/b.yaml", "Finding in b"),
            ],
        };
        scanner
            .expect_scan_iac()
            .times(1)
            .returning(move |_| Ok(first_result.clone()));
        let second_result = IacScanResult {
            findings: vec![iac_finding_for("/workspace/b.yaml", "Finding in b")],
        };
        scanner
            .expect_scan_iac()
            .times(1)
            .returning(move |_| Ok(second_result.clone()));
    }

    for _ in 0..2 {
        let result = setup
            .server
            .execute_command(execute_iac_scan_params(vec![]))
            .await;
        assert!(result.is_ok());
    }

    let diagnostics = setup.client_recorder.diagnostics.lock().await;
    let last_a = last_published_diagnostics_for(&diagnostics, "file:///workspace/a.yaml")
        .expect("a.yaml should have received a clearing publish");
    assert!(
        last_a.is_empty(),
        "findings for a file dropped from the report must be cleared: {last_a:?}"
    );
    let last_b = last_published_diagnostics_for(&diagnostics, "file:///workspace/b.yaml")
        .expect("no diagnostics for b.yaml");
    assert_eq!(last_b.len(), 1);
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_document_edit_preserves_iac_diagnostics_and_clears_vuln_ones(
    #[future] server_with_open_k8s_manifest: TestSetup,
    scan_result: ScanResult,
) {
    // Produce one IaC and one vulnerability diagnostic on the same document
    let iac_result = IacScanResult {
        findings: vec![iac_finding_for("/deployment.yaml", "IaC finding")],
    };
    server_with_open_k8s_manifest
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(1)
        .returning(move |_| Ok(iac_result.clone()));
    server_with_open_k8s_manifest
        .component_factory
        .image_scanner
        .lock()
        .await
        .expect_scan_image()
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    assert!(
        server_with_open_k8s_manifest
            .server
            .execute_command(execute_iac_scan_params(vec![json!(
                "file:///deployment.yaml"
            )]))
            .await
            .is_ok()
    );
    assert!(
        server_with_open_k8s_manifest
            .server
            .execute_command(ExecuteCommandParams {
                command: "sysdig-lsp.execute-scan".to_string(),
                arguments: vec![
                    json!({"range":{"end":{"character":25,"line":10},"start":{"character":15,"line":10}},"uri":"file:///deployment.yaml"}),
                    json!("nginx:1.19"),
                ],
                work_done_progress_params: WorkDoneProgressParams::default(),
            })
            .await
            .is_ok()
    );

    // Editing the document goes through the full lifecycle
    server_with_open_k8s_manifest
        .server
        .did_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(
                "file:///deployment.yaml".parse().unwrap(),
                2,
            ),
            content_changes: vec![tower_lsp::lsp_types::TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "apiVersion: v1\nkind: Pod\n".to_string(),
            }],
        })
        .await;

    let diagnostics = server_with_open_k8s_manifest
        .client_recorder
        .diagnostics
        .lock()
        .await;
    let last = last_published_diagnostics_for(&diagnostics, "file:///deployment.yaml")
        .expect("no diagnostics published");

    let sources: Vec<_> = last.iter().filter_map(|d| d.source.as_deref()).collect();
    assert!(
        sources.contains(&"sysdig-iac"),
        "IaC diagnostics anchor at the top of the file and must survive edits: {sources:?}"
    );
    assert!(
        !sources.contains(&"sysdig-vuln"),
        "vulnerability diagnostics anchor to lines and must be cleared on edits: {sources:?}"
    );
}

#[rstest]
#[tokio::test]
async fn test_workspace_rescan_preserves_findings_outside_the_scanned_root() {
    let setup = TestSetup::new();
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
        })),
        workspace_folders: Some(vec![tower_lsp::lsp_types::WorkspaceFolder {
            uri: "file:///workspace".parse().unwrap(),
            name: "workspace".to_string(),
        }]),
        ..Default::default()
    };
    assert!(setup.server.initialize(params).await.is_ok());

    {
        let mut scanner = setup.component_factory.iac_scanner.lock().await;
        // File-scoped scan of a file outside the workspace root. The path shares
        // the root as a string prefix ("/workspace-other" vs "/workspace") to pin
        // the trailing-slash boundary of the prefix-scoped clearing.
        let outside_result = IacScanResult {
            findings: vec![iac_finding_for(
                "/workspace-other/x.yaml",
                "Outside finding",
            )],
        };
        scanner
            .expect_scan_iac()
            .withf(|scope| matches!(scope, IacScanScope::File { .. }))
            .times(1)
            .returning(move |_| Ok(outside_result.clone()));
        // Workspace scan afterwards returns nothing
        scanner
            .expect_scan_iac()
            .withf(|scope| matches!(scope, IacScanScope::Directory(_)))
            .times(1)
            .returning(|_| Ok(IacScanResult::default()));
    }

    assert!(
        setup
            .server
            .execute_command(execute_iac_scan_params(vec![json!(
                "file:///workspace-other/x.yaml"
            )]))
            .await
            .is_ok()
    );
    assert!(
        setup
            .server
            .execute_command(execute_iac_scan_params(vec![]))
            .await
            .is_ok()
    );

    let diagnostics = setup.client_recorder.diagnostics.lock().await;
    let last = last_published_diagnostics_for(&diagnostics, "file:///workspace-other/x.yaml")
        .expect("no diagnostics for the outside file");
    assert_eq!(
        last.len(),
        1,
        "a workspace scan must not clear findings outside its root: {last:?}"
    );
}

/// IacScanner double that blocks inside scan_iac until released, to observe the
/// server while a command is in flight.
#[derive(Clone)]
struct BlockingIacScanner {
    started: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl sysdig_lsp::app::IacScanner for BlockingIacScanner {
    async fn scan_iac(
        &self,
        _scope: &IacScanScope,
    ) -> Result<IacScanResult, sysdig_lsp::app::IacScanError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(IacScanResult::default())
    }
}

#[derive(Clone)]
struct BlockingComponentFactory {
    iac_scanner: BlockingIacScanner,
}

impl sysdig_lsp::app::component_factory::ComponentFactory for BlockingComponentFactory {
    fn create_components(
        &self,
        _config: sysdig_lsp::app::component_factory::Config,
    ) -> Result<
        sysdig_lsp::app::component_factory::Components,
        sysdig_lsp::app::component_factory::ComponentFactoryError,
    > {
        Ok(sysdig_lsp::app::component_factory::Components {
            scanner: Box::new(common::MockImageScannerWrapper(std::sync::Arc::new(
                tokio::sync::Mutex::new(common::MockImageScanner::new()),
            ))),
            builder: Box::new(common::MockImageBuilderWrapper(std::sync::Arc::new(
                tokio::sync::Mutex::new(common::MockImageBuilder::new()),
            ))),
            iac_scanner: Box::new(self.iac_scanner.clone()),
        })
    }
}

#[rstest]
#[tokio::test]
async fn test_commands_run_without_holding_the_server_lock() {
    use std::sync::Arc;
    use std::time::Duration;

    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let recorder = common::TestClientRecorder::new();
    let server = Arc::new(sysdig_lsp::app::LSPServer::new(
        recorder.clone(),
        BlockingComponentFactory {
            iac_scanner: BlockingIacScanner {
                started: started.clone(),
                release: release.clone(),
            },
        },
    ));

    let init = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
        })),
        ..Default::default()
    };
    assert!(server.initialize(init).await.is_ok());
    server
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem::new(
                "file:///deployment.yaml".parse().unwrap(),
                "yaml".to_string(),
                1,
                include_str!("fixtures/k8s-deployment.yaml").to_string(),
            ),
        })
        .await;

    let command_server = server.clone();
    let command = tokio::spawn(async move {
        command_server
            .execute_command(execute_iac_scan_params(vec![json!(
                "file:///deployment.yaml"
            )]))
            .await
    });
    started.notified().await;

    // While the scan is in flight, a write-lock operation and a read operation
    // must both complete: the command must not hold the (FIFO-fair) server lock.
    tokio::time::timeout(
        Duration::from_secs(1),
        server.did_change_configuration(DidChangeConfigurationParams {
            settings: serde_json::json!({
                "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
            }),
        }),
    )
    .await
    .expect("did_change_configuration deadlocked behind a running command");

    tokio::time::timeout(
        Duration::from_secs(1),
        server.code_lens(tower_lsp::lsp_types::CodeLensParams {
            text_document: TextDocumentIdentifier::new("file:///deployment.yaml".parse().unwrap()),
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        }),
    )
    .await
    .expect("code_lens deadlocked behind a running command")
    .expect("code_lens failed");

    release.notify_one();
    let result = command.await.expect("command task panicked");
    assert!(result.is_ok());
}

#[rstest]
#[tokio::test]
async fn test_workspace_scan_never_publishes_findings_escaping_the_root() {
    let setup = TestSetup::new();
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
        })),
        workspace_folders: Some(vec![tower_lsp::lsp_types::WorkspaceFolder {
            uri: "file:///workspace".parse().unwrap(),
            name: "workspace".to_string(),
        }]),
        ..Default::default()
    };
    assert!(setup.server.initialize(params).await.is_ok());

    // A finding whose source escapes the scanned root (e.g. via `..`) must be
    // dropped: inserting it outside the cleared scope would accumulate duplicates
    // on every rescan.
    let scan_result = IacScanResult {
        findings: vec![
            iac_finding_for("/outside/x.yaml", "Escaping finding"),
            iac_finding_for("/workspace/ok.yaml", "In-root finding"),
        ],
    };
    setup
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(2)
        .returning(move |_| Ok(scan_result.clone()));

    for _ in 0..2 {
        let result = setup
            .server
            .execute_command(execute_iac_scan_params(vec![]))
            .await;
        assert!(result.is_ok());
    }

    let diagnostics = setup.client_recorder.diagnostics.lock().await;
    assert!(
        diagnostics
            .iter()
            .all(|(url, _)| url != "file:///outside/x.yaml"),
        "findings escaping the scanned root must never be published"
    );
    let in_root = last_published_diagnostics_for(&diagnostics, "file:///workspace/ok.yaml")
        .expect("no diagnostics for the in-root file");
    assert_eq!(in_root.len(), 1, "rescans must not accumulate duplicates");
}

#[rstest]
#[tokio::test]
async fn test_execute_command_on_uninitialized_server_surfaces_the_error() {
    let setup = TestSetup::new();

    let result = setup
        .server
        .execute_command(execute_iac_scan_params(vec![json!("file:///a.yaml")]))
        .await;

    let err = result.expect_err("commands must fail before initialization");
    assert!(err.message.contains("LSP not initialized"));

    let messages = setup.client_recorder.messages.lock().await;
    assert!(
        messages
            .iter()
            .any(|(t, m)| *t == MessageType::ERROR && m.contains("LSP not initialized")),
        "the error must be surfaced to the user via showMessage: {messages:?}"
    );
}

#[rstest]
#[tokio::test]
async fn test_workspace_scan_drops_findings_with_relative_sources() {
    let setup = TestSetup::new();
    let params = InitializeParams {
        initialization_options: Some(serde_json::json!({
            "sysdig": { "apiUrl": "http://localhost:8080", "api_token": "dummy-token" }
        })),
        workspace_folders: Some(vec![tower_lsp::lsp_types::WorkspaceFolder {
            uri: "file:///workspace".parse().unwrap(),
            name: "workspace".to_string(),
        }]),
        ..Default::default()
    };
    assert!(setup.server.initialize(params).await.is_ok());

    // A relative source cannot be turned into a file URI: the finding is dropped
    // (with a warning) instead of being published under a broken URI.
    let scan_result = IacScanResult {
        findings: vec![iac_finding_for("relative.yaml", "Relative finding")],
    };
    setup
        .component_factory
        .iac_scanner
        .lock()
        .await
        .expect_scan_iac()
        .times(1)
        .returning(move |_| Ok(scan_result.clone()));

    let result = setup
        .server
        .execute_command(execute_iac_scan_params(vec![]))
        .await;
    assert!(result.is_ok());

    let diagnostics = setup.client_recorder.diagnostics.lock().await;
    assert!(
        diagnostics
            .iter()
            .all(|(_, diags)| diags.iter().all(|d| !d.message.contains("Relative"))),
        "findings with relative sources must not be published: {diagnostics:?}"
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn test_compose_code_lens(#[future] initialized_server: TestSetup) {
    let compose_url: Url = "file:///docker-compose.yml".parse().unwrap();
    initialized_server
        .server
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem::new(
                compose_url.clone(),
                "yaml".to_string(),
                1,
                include_str!("fixtures/docker-compose.yml").to_string(),
            ),
        })
        .await;

    let result = initialized_server
        .server
        .code_lens(tower_lsp::lsp_types::CodeLensParams {
            text_document: TextDocumentIdentifier::new(compose_url),
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        })
        .await
        .unwrap()
        .unwrap();

    let lenses = serde_json::to_value(result).unwrap();
    let lenses = lenses.as_array().unwrap();

    // First lens: whole-file IaC scan
    assert_eq!(
        lenses[0]["command"]["command"],
        "sysdig-lsp.execute-iac-scan"
    );
    assert_eq!(lenses[0]["command"]["title"], "Scan IaC file");
    assert_eq!(
        lenses[0]["command"]["arguments"],
        json!(["file:///docker-compose.yml"])
    );

    // Then one image scan lens per compose image
    let images: Vec<_> = lenses[1..]
        .iter()
        .map(|l| {
            assert_eq!(l["command"]["command"], "sysdig-lsp.execute-scan");
            l["command"]["arguments"][1].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(images, vec!["nginx:latest", "postgres:13"]);
}
