.PHONY: build test lint clean build-ebpf test-live test-f2-foundation test-f2-runtime test-f2-validation-harness test-f2-runtime-registration test-f2-runtime-adapters test-f2-runtime-adapter-matrix test-f2-recovery test-f2-performance test-f2-visibility-reports test-f2-production-qualification test-f3-guardrails test-f3-bpf-lsm-live test-f4-runtime-guardrails test-f5-production-hardening test-f5-live-deployment test-f5-supply-chain test-f5-helm-production test-f5-release-registry test-f5-tenant-query-retention test-f5-retention-enforcement test-f5-release-promotion-policy test-f5-signing-profile

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

test-f4-runtime-guardrails:
	./scripts/test-f4-runtime-guardrails.sh

test-f5-production-hardening:
	./scripts/test-f5-production-hardening.sh

test-f5-live-deployment:
	./scripts/test-f5-live-deployment.sh

test-f5-supply-chain:
	./scripts/test-f5-supply-chain.sh

test-f5-helm-production:
	./scripts/test-f5-helm-production.sh

test-f5-release-registry:
	./scripts/test-f5-release-registry.sh

test-f5-tenant-query-retention:
	./scripts/test-f5-tenant-query-retention.sh

test-f5-retention-enforcement:
	./scripts/test-f5-retention-enforcement.sh

test-f5-release-promotion-policy:
	./scripts/test-f5-release-promotion-policy.sh

test-f5-signing-profile:
	./scripts/test-f5-signing-profile.sh
