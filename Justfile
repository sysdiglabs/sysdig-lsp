# Help commands
default:
    @just --list

test:
    cargo nextest run

fix:
    cargo fix --allow-staged --allow-dirty
    cargo machete --fix

fmt:
    cargo fmt

lint:
    cargo check
    cargo clippy

update:
    nix flake update
    nix develop --command cargo update
    nix develop --command pre-commit autoupdate
    nix develop --command just update-cli-scanner

# Bump the pinned sysdig-cli-scanner to the latest version (lines tagged with newest-version-marker)
update-cli-scanner:
    #!/usr/bin/env bash
    set -euo pipefail
    latest=$(curl --silent --show-error --fail --location https://download.sysdig.com/scanning/sysdig-cli-scanner/latest_version.txt | tr -d '[:space:]')
    IFS=. read -r major minor patch <<< "$latest"
    file=src/infra/scanner_binary_manager.rs
    sd 'Version::new\(\d+, \d+, \d+\)(.*newest-version-marker)' "Version::new($major, $minor, $patch)\${1}" "$file"
    sd '"\d+\.\d+\.\d+"(.*newest-version-marker)' "\"$latest\"\${1}" "$file"
    echo "sysdig-cli-scanner -> $latest"
