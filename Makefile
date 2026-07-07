.PHONY: build test lint clean build-ebpf test-live quickstart test-quickstart \
	test-jsonl-schema-contract test-community-surface \
	test-local-agent-command-attribution test-intent-correlation \
	test-audit-write-budget test-offline-hash-chain-verify test-timeline-shipping \
	test-codex-mismatch-demo test-codex-live-demo-runbook \
	test-codex-live-demo-public-assets test-codex-live-demo-launch-blog \
	test-codex-live-demo-final-assets \
	test-policy-guardrails test-policy-guardrails-bpf-lsm-live test-runtime-guardrails \
	test-runtime-foundation test-runtime-foundation-runtime \
	test-runtime-foundation-validation-harness test-runtime-foundation-runtime-registration \
	test-runtime-foundation-runtime-adapters test-runtime-foundation-runtime-adapter-matrix \
	test-runtime-foundation-recovery test-runtime-foundation-performance \
	test-runtime-foundation-visibility-reports test-runtime-foundation-production-qualification

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

# Zero-privilege trial: run the intent/side-effect accountability flow on the
# bundled Codex mismatch fixture (no root, no eBPF). See docs/quickstart.md.
quickstart:
	@mkdir -p target/quickstart
	@cargo run -q -p apolysis-cli -- intent ingest \
		--adapter codex-jsonl \
		--input tests/fixtures/codex-mismatch/codex-response-items.jsonl \
		--session codex-mismatch-demo \
		--output target/quickstart/intent.jsonl \
		--workspace-root "$(CURDIR)"
	@cargo run -q -p apolysis-cli -- intent correlate \
		--intent-input target/quickstart/intent.jsonl \
		--timeline-input tests/fixtures/codex-mismatch/observed-timeline.jsonl \
		--output target/quickstart/correlation.jsonl \
		--summary

# --- Product / demo contract gates (run in CI via release-validation.yml) ---

test-jsonl-schema-contract:
	./scripts/test-jsonl-schema-contract.sh

test-community-surface:
	./scripts/test-community-surface.sh

test-quickstart:
	./scripts/test-quickstart.sh

test-intent-correlation:
	./scripts/test-intent-correlation.sh

test-audit-write-budget:
	./scripts/test-audit-write-budget.sh

test-offline-hash-chain-verify:
	./scripts/test-offline-hash-chain-verify.sh

test-timeline-shipping:
	./scripts/test-timeline-shipping.sh

test-local-agent-command-attribution:
	./scripts/test-local-agent-command-attribution.sh

test-codex-mismatch-demo:
	./scripts/test-codex-mismatch-demo.sh

test-codex-live-demo-runbook:
	./scripts/test-codex-live-demo-runbook.sh

test-codex-live-demo-public-assets:
	./scripts/test-codex-live-demo-public-assets.sh

test-codex-live-demo-launch-blog:
	./scripts/test-codex-live-demo-launch-blog.sh

test-codex-live-demo-final-assets:
	./scripts/test-codex-live-demo-final-assets.sh

# --- Policy and runtime-foundation gates (privileged / adapter tests) ---

test-policy-guardrails:
	./scripts/test-policy-guardrails.sh

test-policy-guardrails-bpf-lsm-live:
	./scripts/test-policy-guardrails-bpf-lsm-live.sh

test-runtime-guardrails:
	./scripts/test-runtime-guardrails.sh

test-runtime-foundation:
	./scripts/test-runtime-foundation.sh

test-runtime-foundation-runtime: build-ebpf
	./scripts/test-runtime-foundation-runtime.sh

test-runtime-foundation-validation-harness:
	./scripts/test-runtime-foundation-validation-harness.sh

test-runtime-foundation-runtime-registration:
	./scripts/test-runtime-foundation-runtime-registration.sh

test-runtime-foundation-runtime-adapters:
	./scripts/test-runtime-foundation-runtime-adapters.sh

test-runtime-foundation-runtime-adapter-matrix:
	./scripts/test-runtime-foundation-runtime-adapter-matrix.sh

test-runtime-foundation-recovery:
	./scripts/test-runtime-foundation-recovery.sh

test-runtime-foundation-performance:
	./scripts/test-runtime-foundation-performance.sh

test-runtime-foundation-visibility-reports:
	./scripts/test-runtime-foundation-visibility-reports.sh

test-runtime-foundation-production-qualification: test-runtime-foundation-recovery test-runtime-foundation-performance test-runtime-foundation-visibility-reports
