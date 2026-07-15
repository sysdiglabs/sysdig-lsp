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
