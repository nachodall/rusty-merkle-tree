.PHONY: build test fmt check

build:
	cargo build

test:
	cargo test

fmt:
	cargo fmt --all -- --check

check:
	cargo check
