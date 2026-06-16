.PHONY: build test lint clean build-ebpf test-live test-f2-foundation test-f2-runtime test-f2-validation-harness test-f2-runtime-registration

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

test-f2-foundation:
	./scripts/test-f2-foundation.sh

test-f2-runtime: build-ebpf
	./scripts/test-f2-runtime.sh

test-f2-validation-harness:
	./scripts/test-f2-validation-harness.sh

test-f2-runtime-registration:
	./scripts/test-f2-runtime-registration.sh
