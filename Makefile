.PHONY: build test lint clean build-ebpf test-live

build: build-ebpf
	cargo build --workspace

test:
	cargo test --workspace

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

clean:
	cargo clean

build-ebpf:
	./scripts/build-ebpf.sh

test-live: build-ebpf
	./scripts/test-live-observer.sh
