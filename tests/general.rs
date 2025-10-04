mod common;

use common::TestSetup;
use rstest::{fixture, rstest};
use serde_json::json;
use std::collections::HashMap;
use sysdig_lsp::domain::scanresult::architecture::Architecture;
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
    let diagnostic = &diagnostics[0][0];
    assert_eq!(
        diagnostic.message,
        "Vulnerabilities found for alpine: 0 Critical, 1 High, 0 Medium, 0 Low, 0 Negligible"
    );
    assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::INFORMATION));
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

| TOTAL VULNS FOUND | CRITICAL | HIGH        | MEDIUM | LOW | NEGLIGIBLE |
| :-------------: | :----: | :---------: | :--: | :-: | :------: |
| 1               | 0      | 1 (1 Fixable) | 0    | 0   | 0        |


### Fixable Packages
| PACKAGE | TYPE | VERSION | SUGGESTED FIX | CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE | EXPLOIT |
| :----- | :-: | :---- | :---------- | :----: | :-: | :--: | :-: | :------: | :---: |
| package1 | os  | 1.0.0 | 1.0.1       | -      | 1   | -    | -   | -        | -     |



### Vulnerability Detail

| VULN CVE    | SEVERITY | PACKAGES | FIXABLE | EXPLOITABLE | ACCEPTED RISK |
| :---------- | :----- | :----- | :---- | :-------- | :---------- |
| CVE-2021-1234 | High   | 1      | ✅    | ❌        | ❌          |
"#;

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
