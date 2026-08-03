.PHONY: build test lint clean build-ebpf test-live quickstart test-quickstart \
	test-local-agent-command-attribution

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

# Quickstart smoke test — the one product-path gate run in CI (release-validation.yml).
test-quickstart:
	./scripts/test-quickstart.sh

test-local-agent-command-attribution:
	./scripts/test-local-agent-command-attribution.sh
