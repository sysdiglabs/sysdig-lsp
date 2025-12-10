# Sysdig LSP – Unified Assistant Context & Repository Guidelines

## 1. Project Overview

**Sysdig LSP** is a Language Server Protocol (LSP) implementation written in Rust. It integrates container image vulnerability scanning and Infrastructure-as-Code (IaC) analysis directly into code editors (e.g. VS Code, Helix, Neovim).

It is designed to detect issues early in the development workflow by scanning:

* Dockerfiles
* Docker Compose files
* Kubernetes manifests
* Other IaC files

The server is built on top of the `tower-lsp` framework and integrates with Sysdig’s Secure backend via a dedicated scanner binary and HTTP APIs.

### Key Features

* Vulnerability scanning of base images and dependencies.
* Code Lens support (e.g. “Scan base image” on `FROM` lines).
* Layered analysis for container images.
* Integration with Sysdig’s Secure backend APIs through a CLI scanner binary.

---

## 2. Project Structure & Architecture

The project follows a modular, three-layer, Hexagonal-like architecture that cleanly separates domain logic, application orchestration, and infrastructure concerns.

### 2.1 Workspace & Modules

* Rust workspace with entrypoint in `src/main.rs` (initializes `LSPServer` with `tower-lsp` and configures logging).
* Library exports in `src/lib.rs`, which also enforces linting rules (denies `unwrap` / `expect` in production code).
* LSP orchestration / use-cases live in `src/app`.
* Domain types and business logic live in `src/domain`.
* Adapters and integrations (infrastructure) live in `src/infra`.
* Integration tests and shared fixtures live under `tests/`:
  * `tests/general.rs`
  * `tests/common.rs`
  * `tests/fixtures/` (sample Dockerfiles, scan results, etc.)
* Documentation for user-facing capabilities is under `docs/features/`.
* Build tooling and shortcuts are defined in `Justfile` and `flake.nix`.

### 2.2 Domain Layer (`src/domain/`)

The domain layer contains pure business logic and domain models.

Key module:

* `scanresult/`: defines core entities and value objects:
  * `ScanResult`: core aggregate representing a full scan result.
  * `Vulnerability`: CVE, severity, package details, etc.
  * `Package`: name, version, package type.
  * `Layer`: container image layer information.
  * `Policy`: policy evaluation results.
  * Value objects such as `Severity`, `Architecture`, `OperatingSystem`.

### 2.3 Application Layer (`src/app/`)

The application layer orchestrates domain and infrastructure components and implements LSP-specific behavior.

Key components:

* **`LSPServer` (`lsp_server/`)** – main LSP implementation built on `tower-lsp`:
  * `lsp_server_inner.rs`: core LSP protocol handlers (initialize, text sync, code lenses, commands, diagnostics, hover, etc.).
  * `commands/`: concrete LSP command implementations (e.g. `scan_base_image`, `build_and_scan`).
  * `command_generator.rs`: generates Code Lens entries and associated commands.
  * `supported_commands.rs`: registry of available commands exposed to the client.
* **`LspInteractor`** – manages communication with the LSP client and document state.
* **`ImageScanner`** – trait for scanning container images (implemented by infrastructure components).
* **`ImageBuilder`** – trait for building Docker images.
* **`DocumentDatabase` (`document_database.rs`)** – in-memory store for:
  * Document text
  * Diagnostics (LSP warnings/errors for vulnerabilities)
  * Hover documentation (detailed vulnerability explanations)
* **`markdown/`** – formats scan results into Markdown tables for display in editors.
* **`ComponentFactory`** – abstract factory for dependency injection and component creation.

### 2.4 Infrastructure Layer (`src/infra/`)

The infrastructure layer implements technical concerns and external integrations.

Key components:

* **`SysdigImageScanner`**
  * Integrates with the Sysdig CLI scanner binary and Sysdig Secure backend.
  * Downloads and manages scanner binary versions.
  * Parses JSON scan results (e.g. via `sysdig_image_scanner_json_scan_result_v1.rs`).

* **`DockerImageBuilder`**
  * Builds container images using Bollard (Docker API client).

* **Dockerfile / Compose / K8s Manifest AST Parsers**
  * Parse Dockerfiles to extract image references from `FROM` instructions (including multi-stage builds).
  * Parse Docker Compose YAML (e.g. service `image:` fields).
  * Parse Kubernetes manifests YAML (e.g. `containers[].image` and `initContainers[].image` fields).
    * K8s manifests are detected by checking for both `apiVersion:` and `kind:` fields in YAML files.
    * Supports all common K8s resource types: Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs.
  * Handle complex scenarios such as build args and multi-platform images.
  * Implemented via modules like `dockerfile_ast_parser.rs`, `compose_ast_parser.rs`, and `k8s_manifest_ast_parser.rs`.

* **`ScannerBinaryManager`**
  * Downloads the Sysdig CLI scanner binary on demand.
  * Caches binaries and checks GitHub releases for the latest version compatible with the current platform.

* **`LSPLogger`**
  * `tracing` subscriber that logs diagnostics and events to the LSP client or stderr.

* **`ConcreteComponentFactory`**
  * Production wiring of dependencies implementing the `ComponentFactory` trait.

### 2.5 LSP Protocol Flow

The high-level LSP flow is:

1. **Initialize** – Client sends configuration (e.g. `api_url`, `api_token`) via `initializationOptions`.
2. **`didOpen` / `didChange`** – Document updates trigger parsing and analysis.
3. **`codeLens`** – The server generates “Scan base image” code lenses on relevant lines (e.g. Dockerfile `FROM` instructions).
4. **`executeCommand`** – Clicking a lens triggers commands like `scan_base_image` or `build_and_scan`.
5. **`publishDiagnostics`** – Vulnerability findings are sent as diagnostics to the editor.
6. **`hover`** – Hovering on diagnostics or vulnerable elements shows detailed vulnerability information.

### 2.6 Document State Management

Document state is managed in-memory via `InMemoryDocumentDatabase` (an implementation of `DocumentDatabase`), maintaining per-document:
1. Raw document text.
2. Diagnostics with vulnerability details.
3. Pre-computed hover documentation.

This allows the LSP to provide rich, contextual information without re-running scans on every request.

---

## 3. Development Environment & Tooling

### 3.1 Nix & Development Shell

* `nix develop` – enter a reproducible development shell with the exact Rust toolchain and dependencies required by the project, as defined in `flake.nix`. You can assume the user already started the development shell.

### 3.2 Build Commands

* `cargo build` – build the server in debug mode.
* `cargo build --release` – build an optimized release binary.
* `nix build .#sysdig-lsp` – Nix-based build, with cross targets available (e.g. CI or other architectures).
* Cross-compilation example: `nix build .#sysdig-lsp-linux-amd64`.

The resulting `sysdig-lsp` binary is designed to be run by an LSP client (editor), rather than directly by users.

### 3.3 Testing & Quality Commands

The project uses `just` as a command runner to encapsulate common workflows.

* `just test`
  * Runs the test suite via `cargo nextest run` (primary test runner).
  * Some tests require the `SECURE_API_TOKEN` environment variable.

* `just lint`
  * Runs `cargo check` and `cargo clippy` for quick static analysis.

* `just fmt`
  * Runs `cargo fmt` according to `rustfmt.toml`.

* `just fix`
  * Runs `cargo fix` and `cargo machete` / `cargo machete --fix` to clean up unused dependencies and minor issues.

* `just watch`
  * Provides a watch mode to run tests (or other commands) on file changes.

Additional helpful commands:

* `cargo test -- --nocapture` – run tests with full output when debugging.
* `cargo test --lib` – run only unit tests (faster than running all tests).

**Important:** The tests `infra::sysdig_image_scanner::tests::it_scans_popular_images_correctly_test::case_*` are very slow because they scan real container images. These tests should only be run when making changes to the image scanner. For day-to-day development, skip them or run focused tests instead.

### 3.4 Pre-commit Hooks

Pre-commit hooks are configured in `.pre-commit-config.yaml` to run:

* Formatting (`cargo fmt`).
* `cargo check`.
* `cargo clippy`.

These should run cleanly before opening a PR.
They are automatically executed before a commit is done.
If they are not executed, you need to execute: `pre-commit install` to configure it.
If any of the steps of the pre-commit fails for whatever reason, you need to understand that the commit was not created.

---

## 4. Coding Style, Technologies & Design Patterns

### 4.1 Languages & Key Libraries

* **Language:** Rust (Edition 2024).
* **LSP Framework:** `tower-lsp`.
* **Async Runtime:** `tokio`.
* **HTTP Client:** `reqwest`.
* **Serialization:** `serde`.
* **Logging:** `tracing` (plus `LSPLogger` integration).
* **CLI Args:** `clap`.
* **Testing Libraries:** `rstest`, `mockall`, `serial_test`, along with `cargo nextest`.

### 4.2 Code Style & Naming Conventions

* Use standard Rust formatting (`rustfmt`) with 4-space indentation.
* **Naming:**
  * `snake_case` for modules and functions.
  * `CamelCase` for types.
  * `SCREAMING_SNAKE_CASE` for constants.
* Import ordering uses `reorder_imports = true` in `rustfmt.toml`.
* Prefer trait-based abstractions over concrete types for testability and clear architecture boundaries.
* Keep public APIs documented and keep modules small, mirroring the `app` / `domain` / `infra` boundaries.
* Use `tracing` for structured logging, sending logs to the LSP client or stderr via `LSPLogger`.

### 4.3 Error Handling

Error handling is intentionally strict:

* **No `unwrap()` or `expect()` in non-test code.**
  * Enforced by clippy rules and `src/lib.rs` configuration.
* Use `Result` types with explicit error propagation.
* Prefer `thiserror` for custom error types with rich context.
* Optionally use `anyhow::Context` style patterns for additional context at call sites.
* Convert domain-level errors to appropriate LSP-facing errors at the application boundary.

### 4.4 Dependency Injection via `ComponentFactory`

The `ComponentFactory` trait centralizes creation of major application components and supports testing:

* Receives configuration (e.g. `api_url`, `api_token`) from the client.
* Produces `Components` such as:
  * `ImageScanner` implementations.
  * `ImageBuilder` implementations.
* `ConcreteComponentFactory` wires real components in production.
* Tests can provide mock factories to inject fake scanners/builders for deterministic behavior.

### 4.5 Async / Await & Concurrency

All I/O operations, including scanning, building, and LSP communication, are asynchronous using the `tokio` runtime.

* Shared state within the LSP server uses `RwLock` (or similar primitives) to support concurrent reads with controlled writes.

---

## 5. Testing Strategy & Guidelines

### 5.1 Testing Strategy

* Integration tests live in the `tests/` directory, using real fixtures (e.g. Dockerfiles, sample scan results).
* Fixtures are stored under `tests/fixtures/`.
* **`serial_test`** is used to prevent parallel execution conflicts (e.g. sharing global resources or temporary directories).
* **`mockall`** is used for mocking traits like `ImageScanner` in unit tests.
* `rstest` can be used for parameterized tests.
* Environment: tests may require `SECURE_API_TOKEN` for scenarios that depend on authenticated scanning.

### 5.2 Testing Guidelines

* Primary test runner is `cargo nextest` (via `just test`).
* Add integration coverage in `tests/*.rs` and reuse fixtures in `tests/fixtures/`.
* Name tests descriptively (`should_*` or behavior-oriented names).
* Avoid direct network calls inside tests; prefer fixture-based or mocked interactions instead.
* Add focused unit tests alongside modules using `#[cfg(test)]` for local behavior.
* Broader flows and end-to-end LSP interactions belong in `tests/general.rs`.
* For debugging, `cargo test -- --nocapture` can be used to see all test output.
* Some tests, such as `infra::sysdig_image_scanner::tests::it_scans_popular_images_correctly_test`, are slow because they scan real container images. It is recommended to run them in a focused way or skip them in local development to speed up the feedback loop.

---

## 6. Configuration, Security & Runtime Usage

### 6.1 LSP Initialization & Client Configuration

Clients configure Sysdig LSP via `initializationOptions` in the LSP initialize request, for example:

```json
{
  "sysdig": {
    "api_url": "https://secure.sysdig.com",
    "api_token": "optional, falls back to SECURE_API_TOKEN env var"
  }
}
```

Key points:
* `api_url` should be validated and not hard-coded to environment-specific endpoints in code.
* `api_token` is optional; if absent, the server falls back to the `SECURE_API_TOKEN` environment variable.

### 6.2 Security & Secrets

* Do **not** commit API tokens or other secrets to the repository.
* Prefer environment variables (e.g. `SECURE_API_TOKEN`) or editor initialization options (`sysdig.api_token`).
* Always validate URLs provided via configuration (`sysdig.api_url`).

### 6.3 Supported Usage Pattern

* The `sysdig-lsp` binary is not meant to be run manually; it is launched and driven by an LSP client (such as VS Code, Helix, or Neovim) that speaks the Language Server Protocol.

---

## 7. Releasing

The workflow in .github/workflows/release.yml will create a new release automatically when the version of the crate changes in Cargo.toml in the default git branch.
So, if you attempt to release a new version, you need to update this version. You should try releasing a new version when you do any meaningful change that the user can benefit from.
The guidelines to follow would be:

* New feature is implemented -> Release new version.
* Bug fixes -> Release new version.
* CI/Refactorings/Internal changes -> No need to release new version.
* Documentation changes -> No need to release new version.

The current version of the LSP is not stable yet, so you need to follow the [Semver spec](https://semver.org/spec/v2.0.0.html), with the following guidelines:

* Unless specified, do not attempt to stabilize the version. That is, do not try to update the version to >=1.0.0. Versions for now should be <1.0.0.
* For minor changes, update only the Y in 0.X.Y. For example: 0.5.2 -> 0.5.3
* For major/feature changes, update the X in 0.X.Y and set the Y to 0. For example: 0.5.2 -> 0.6.0

After the commit is merged into the default branch the workflow will cross-compile the project, create a GitHub release of that version, and upload the artifacts to the release.
Check the workflow file in case of doubt.

---

## 8. Development Patterns & Common Gotchas

This section documents important patterns, findings, and gotchas discovered during development that are critical for maintaining consistency and avoiding common pitfalls.

### 8.1 Adding Support for New File Types

When adding support for a new file type (e.g. Kubernetes manifests, Terraform files), follow this pattern established by Docker Compose and K8s manifest implementations:

#### Step 1: Create a Parser Module

1. **Create parser in `src/infra/`**: e.g. `k8s_manifest_ast_parser.rs`
   - Define an `ImageInstruction` struct with `image_name` and `range` (LSP Range)
   - Create a `parse_*` function that returns `Result<Vec<ImageInstruction>, ParseError>`
   - Use `marked_yaml` for YAML parsing to preserve position information for accurate LSP ranges
   - Include comprehensive unit tests covering:
     - Simple cases
     - Multiple images
     - Edge cases (empty, null, invalid YAML)
     - Complex image names with registries
     - Quoted values

2. **Export the parser in `src/infra/mod.rs`**:
   ```rust
   mod k8s_manifest_ast_parser;
   pub use k8s_manifest_ast_parser::parse_k8s_manifest;
   ```

#### Step 2: Integrate into Command Generator

3. **Update `src/app/lsp_server/command_generator.rs`**:
   - Add import for the new parser
   - Create a detection function (e.g. `is_k8s_manifest_file()`)
     - **IMPORTANT**: Detect by content, not just file extension to avoid false positives
     - Example: K8s manifests must contain both `apiVersion:` and `kind:` fields
   - Add branch in `generate_commands_for_uri()` to route to the new file type
   - Create a `generate_*_commands()` function following the established pattern:
     ```rust
     fn generate_k8s_manifest_commands(url: &Url, content: &str) -> Result<Vec<CommandInfo>, String> {
         let mut commands = vec![];
         match parse_k8s_manifest(content) {
             Ok(instructions) => {
                 for instruction in instructions {
                     commands.push(
                         SupportedCommands::ExecuteBaseImageScan {
                             location: Location::new(url.clone(), instruction.range),
                             image: instruction.image_name,
                         }
                         .into(),
                     );
                 }
             }
             Err(err) => return Err(format!("{}", err)),
         }
         Ok(commands)
     }
     ```

#### Step 3: Add Integration Tests

4. **Create fixture in `tests/fixtures/`**: e.g. `k8s-deployment.yaml`
5. **Add integration test in `tests/general.rs`**:
   - Test code lens generation
   - Verify correct ranges and image names
   - Use existing patterns from compose tests as reference

#### Step 4: Update Documentation

6. **Update `README.md`**: Add feature to the features table with version number
7. **Update `AGENTS.md`**: Document the parser in architecture section
8. **Create feature doc**: Add `docs/features/<feature>.md` with examples
9. **Update `docs/features/README.md`**: Add entry for the new feature

### 8.2 File Type Detection Gotchas

**❌ DON'T**: Rely solely on file extensions for detection
```rust
// BAD: Matches ALL YAML files including compose files
fn is_k8s_manifest_file(file_uri: &str) -> bool {
    file_uri.ends_with(".yaml") || file_uri.ends_with(".yml")
}
```

**✅ DO**: Combine file extension with content-based detection
```rust
// GOOD: Checks both extension AND content
fn is_k8s_manifest_file(file_uri: &str, content: &str) -> bool {
    if !(file_uri.ends_with(".yaml") || file_uri.ends_with(".yml")) {
        return false;
    }
    content.contains("apiVersion:") && content.contains("kind:")
}
```

**Why**: File extensions alone can cause false positives. Docker Compose files, K8s manifests, and generic YAML files all use `.yaml`/`.yml` extensions. Content-based detection ensures accurate routing.

### 8.3 Diagnostic Severity Logic

The diagnostic severity shown in the editor should reflect the **actual vulnerability severity**, not just policy evaluation results.

**Current Implementation** (in `src/app/lsp_server/commands/scan_base_image.rs`):
```rust
diagnostic.severity = Some(if *critical_count > 0 || *high_count > 0 {
    DiagnosticSeverity::ERROR       // Red
} else if *medium_count > 0 {
    DiagnosticSeverity::WARNING     // Yellow
} else {
    DiagnosticSeverity::INFORMATION // Blue
});
```

**Gotcha**: The previous implementation used `scan_result.evaluation_result().is_passed()` which only reflected policy pass/fail. This caused High/Critical vulnerabilities to show as INFORMATION (blue) if the policy passed, which was confusing for users.

**When modifying severity logic**: Always base it on vulnerability counts/severity, not policy evaluation.

### 8.4 LSP Range Calculation

When parsing files to extract ranges for code lenses:

1. **Use position-aware parsers**: `marked_yaml` for YAML, custom parsers for Dockerfiles
2. **Account for quotes**: Image names might be quoted in YAML (`"nginx:latest"` or `'nginx:latest'`)
   ```rust
   let mut raw_len = image_name.len();
   if let Some(c) = first_char && (c == '"' || c == '\'') {
       raw_len += 2; // Include quotes in range
   }
   ```
3. **Test with various formats**: Unquoted, single-quoted, double-quoted values
4. **0-indexed LSP positions**: LSP uses 0-indexed line/character positions, but some parsers (like `marked_yaml`) use 1-indexed positions - convert accordingly:
   ```rust
   let start_line = start.line() as u32 - 1;
   let start_char = start.column() as u32 - 1;
   ```

### 8.5 Testing Patterns

**Unit Tests** (`#[cfg(test)]` in modules):
- Test parser logic in isolation
- Use string literals for test input
- Cover edge cases exhaustively
- Run fast (no I/O)

**Integration Tests** (`tests/general.rs`):
- Test full LSP flow: `did_open` → `code_lens` → `execute_command`
- Use fixtures from `tests/fixtures/`
- Mock external dependencies (ImageScanner) with `mockall`
- Verify JSON serialization of LSP responses

**Slow Tests to Skip**:
- `infra::sysdig_image_scanner::tests::it_scans_popular_images_correctly_test::case_*`
- These scan real container images over the network
- Only run when changing scanner-related code
- Use `cargo test --lib -- --skip it_scans_popular_images_correctly_test` for faster feedback

### 8.6 Common Command Patterns

When adding new LSP commands:

1. **Define in `supported_commands.rs`**: Add to `SupportedCommands` enum
2. **Implement in `commands/` directory**: Create a struct implementing `LspCommand` trait
3. **Wire in `lsp_server_inner.rs`**: Add execution handler
4. **Generate in `command_generator.rs`**: Create CommandInfo for code lenses
5. **Test in `tests/general.rs`**: Verify command execution and results

### 8.7 Version Bumping Strategy

Follow semantic versioning for unstable versions (0.X.Y):

- **Patch (0.X.Y → 0.X.Y+1)**: Bug fixes, documentation, refactoring
- **Minor (0.X.Y → 0.X+1.0)**: New features, enhancements
- **Don't stabilize (1.0.0)** unless explicitly instructed

**When to release**:
- ✅ New feature implemented
- ✅ Bug fixes
- ❌ CI/refactoring/internal changes (no user impact)
- ❌ Documentation-only changes

**Release process**:
1. Update version in `Cargo.toml`
2. Commit and merge to default branch
3. GitHub Actions workflow automatically creates release with cross-compiled binaries

---

## 9. Commit & Pull Request Guidelines

To keep history clean and reviews manageable:

* Use conventional-style commits similar to existing history, e.g.:
  * `feat(scope): message`
  * `fix(scope): message`
  * `refactor: message`
* Before opening a commit, run at least:
  * `just fmt`
  * `just lint`
  * `just test`
  * Any relevant `nix build` invocations when touching build tooling.
  * (You can assume they are executed before the commit is created, see Section 3.4)
* Keep commits scoped and reversible; smaller, reviewable PRs are preferred over large, monolithic changes.
* You must also modify AGENTS.md and README.md if applicable for any change you create, so both files are in sync with the project and the documentation does not become obsolete.
