
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
