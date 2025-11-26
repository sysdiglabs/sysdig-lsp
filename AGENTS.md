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

* **Dockerfile / Compose AST Parsers**
  * Parse Dockerfiles to extract image references from `FROM` instructions (including multi-stage builds).
  * Parse Docker Compose YAML (e.g. service `image:` fields).
  * Handle complex scenarios such as build args and multi-platform images.
  * Implemented via modules like `ast_parser.rs`.

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

## 7. Commit & Pull Request Guidelines

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
