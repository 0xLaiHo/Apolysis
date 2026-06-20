.PHONY: build test lint clean build-ebpf test-live test-f2-foundation test-f2-runtime test-f2-validation-harness test-f2-runtime-registration test-f2-runtime-adapters test-f2-runtime-adapter-matrix test-f2-recovery test-f2-performance test-f2-visibility-reports test-f2-production-qualification test-f3-guardrails test-f3-bpf-lsm-live

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

test-f2-runtime-adapters:
	./scripts/test-f2-runtime-adapters.sh

test-f2-runtime-adapter-matrix:
	./scripts/test-f2-runtime-adapter-matrix.sh

test-f2-recovery:
	./scripts/test-f2-recovery.sh

test-f2-performance:
	./scripts/test-f2-performance.sh

test-f2-visibility-reports:
	./scripts/test-f2-visibility-reports.sh

test-f2-production-qualification: test-f2-recovery test-f2-performance test-f2-visibility-reports

test-f3-guardrails:
	./scripts/test-f3-guardrails.sh

test-f3-bpf-lsm-live:
	./scripts/test-f3-bpf-lsm-live.sh
