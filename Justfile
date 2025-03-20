
test:
    cargo nextest run

fix:
    cargo fix --allow-staged --allow-dirty

fmt:
    cargo fmt

watch:
    cargo watch -x "nextest run"
