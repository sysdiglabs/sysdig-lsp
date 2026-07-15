# Roadmap

This document describes the features planned for Sysdig LSP. The goal is for the LSP to become the core engine of the
[Sysdig VSCode Extension](https://github.com/sysdiglabs/vscode-extension) (and other editor plugins), so most of these
features close the gap with what the extension implements today in TypeScript.

Once a feature is implemented, its section should be moved to a dedicated document under [`docs/features/`](./features/README.md)
and the [README feature table](../README.md#features) updated with the release version.

## Structured scan results for clients

Expose the full scan result (packages, vulnerabilities, severities, exploitable/fix-available flags, source locations,
and the policy evaluation tree: Policy → Rule Bundle → Rule → Failure with remediation hints) through a custom LSP
request or notification (e.g. `sysdig/scanResult`). Today the LSP only surfaces results as diagnostics and Markdown
hovers, which is not machine-consumable; clients need structured JSON to render tree views, filters (exploitable /
fix available), and rich UIs like the extension's "Vulnerabilities" and "Policy Evaluation" panels.

## Scan arbitrary image

Allow executing a scan for any image pull string without requiring a document `Location`. The current
`sysdig-lsp.execute-scan` command takes a `Location` argument, so clients cannot trigger a scan from a command palette
prompt (e.g. "Scan Image for Vulnerabilities" in the extension). This needs a command variant that only takes the image
pull string and reports results through the structured scan result channel instead of document diagnostics.

## Scan result summary notification

Send a custom notification with the vulnerability counts per severity (critical/high/medium/low/negligible) and the
policy pass/fail summary after each scan, so clients can render lightweight UI such as a status bar item without
parsing diagnostics.

## Link to scan results in Sysdig Secure

Expose the scan `resultUrl` returned by the scanner so clients can offer an "Open in Sysdig Secure" action. The URL is
already parsed from the scanner JSON output but is currently dropped when mapping to the domain `ScanResult`. Depends on
[uploading results](#upload-scan-results-to-sysdig-secure), since the URL is only meaningful when the result exists in
the backend.

## Standalone / offline mode

Support running the scanner with `--standalone` using a local vulnerability database, with a configurable policy:
always, never, or automatically when the Sysdig backend is unreachable (connectivity check with a short timeout).
Standalone scans skip result upload and policy evaluation.

## Upload scan results to Sysdig Secure

Add a configuration option to upload scan results to the Sysdig Secure backend. The scanner is currently always invoked
with `--skipupload`.

## Custom policies configuration

Allow configuring additional policies to evaluate during scans (scanner `--policy` flag), e.g. via a
`sysdig.policies` initialization option.

## Configurable report detail level

Add a configuration option to toggle detailed CVE tables (CVSS score/vector, exploitability, fix version) in hover
reports, equivalent to the extension's `detailedReports` setting.

## Custom CLI scanner source

Allow configuring a custom download URL for the CLI scanner binary (e.g. for air-gapped environments). The download URL
is currently hardcoded to `download.sysdig.com`.

## Scan whole manifest

Provide a single command that scans all images found in a Docker Compose file or Kubernetes manifest at once, instead of
requiring one command execution per image.

## Build args support in Build and Scan

Accept Dockerfile `ARG` values as arguments of the `sysdig-lsp.execute-build-and-scan` command and forward them as
build args to the Docker build. Prompting the user for the values is client-side UI; the LSP only needs to accept and
apply them.
