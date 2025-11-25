# Help commands
default:
    @just --list

test:
    cargo nextest run

fix:
    cargo fix --allow-staged --allow-dirty

fmt:
    cargo fmt

lint:
    cargo check
    cargo clippy

watch:
    cargo watch -x "nextest run"

update:
    nix flake update
    nix develop --command cargo update
    nix develop --command pre-commit autoupdate
