.PHONY: build test lint clean build-ebpf build-release-verifier test-live quickstart test-quickstart \
	test-local-agent-command-attribution test-qualification \
	test-release-artifacts verify-release-artifacts test-local-daemon-live-gate-contract \
	test-k1-deployment-contract test-k1-vke-contract qualify-k1-vke-live \
	qualify-runtime-binding-live qualify-private-containerd-live qualify-local-daemon-systemd \
	qualify-local-daemon-install qualify-live

.PHONY: test-bpf-relocation test-live-harness-intent test-live-reason-products \
	test-live-reason-summary test-live-reason-chat test-reason-summary-adapter \
	test-reason-chat test-harness-hooks test-native-observe

build: build-ebpf
	cargo build --workspace

test:
	cargo test --workspace
	$(MAKE) test-harness-hooks
	$(MAKE) test-reason-summary-adapter

test-harness-hooks:
	node --test hooks/tests/intent-bridges.test.mjs

test-reason-summary-adapter:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_live_reason_summary.py'

test-reason-chat:
	cargo test -p apolysis-cli chat:: --bin apolysis
	cargo test -p apolysis-cli --test chat

test-native-observe:
	cargo test -p apolysis-cli native:: --bin apolysis
	cargo test -p apolysis-cli --test native --test native_process

test-bpf-relocation:
	./scripts/test-bpf-relocation.sh

# Explicit provider and privileged eBPF gates; see each script's prerequisites.
test-live-harness-intent:
	cargo build -p apolysis-cli
	./scripts/test-live-harness-intent.sh

test-live-reason-products:
	python3 -u ./scripts/test-live-reason-products.py --require-all --shell-bridge /bin/bash

test-live-reason-summary:
	PYTHONDONTWRITEBYTECODE=1 python3 -u ./scripts/test-live-reason-summary.py --require-all

test-live-reason-chat:
	./scripts/test-live-reason-chat.sh --require-all

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

clean:
	cargo clean

build-ebpf:
	./scripts/build-ebpf.sh

build-release-verifier:
	cargo build --release -p apolysis-release-verifier

test-live: build-ebpf
	./scripts/test-live-observer.sh

# Zero-privilege trial: run the intent/side-effect accountability flow on the
# bundled Codex mismatch fixture (no root, no eBPF). See README.md.
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

test-qualification:
	./scripts/test-qualification-envelope.sh

test-release-artifacts: build-ebpf build-release-verifier
	bash ./scripts/test-release-artifacts.sh

verify-release-artifacts: build-release-verifier
	./scripts/verify-release-artifacts.sh

# Zero-privilege safety contract for the two opt-in local daemon live gates.
test-local-daemon-live-gate-contract:
	bash ./scripts/test-local-daemon-live-gate-contract.sh

# Zero-privilege static and disabled-path safety contract for the opt-in K1 VKE gate.
test-k1-deployment-contract:
	./scripts/test-k1-deployment-contract.sh

test-k1-vke-contract: test-k1-deployment-contract
	./scripts/test-k1-vke-contract.sh

# Explicit, privileged and non-CI. The gate additionally requires two
# operator-provided, digest-pinned product image trust inputs before cluster access.
qualify-k1-vke-live: test-k1-vke-contract
	APOLYSIS_K1_VKE_LIVE=1 ./scripts/qualify-k1-vke.sh

# Explicit, privileged and non-CI. Builds as the checkout owner, publishes a
# verified root-owned test-binary copy, and runs one exact Docker/eBPF gate.
qualify-runtime-binding-live:
	APOLYSIS_LIVE_DOCKER_EBPF=1 ./scripts/run-runtime-binding-live.sh

# Explicit, privileged and non-CI. Creates an isolated private containerd/CRI
# runtime and never restarts or reconfigures the host's shared runtime or CNI.
qualify-private-containerd-live:
	APOLYSIS_PRIVATE_CONTAINERD_LIVE=1 ./scripts/run-private-containerd-live.sh

# Explicit, privileged and non-CI. Uses transient systemd units and one bounded
# temporary state root; it never installs into /usr/local or /var/lib/apolysis.
qualify-local-daemon-systemd: test-local-daemon-live-gate-contract
	APOLYSIS_LIVE_SYSTEMD=1 ./scripts/test-local-daemon-systemd.sh

# Explicit, privileged and non-CI. Refuses any pre-existing managed path or
# state root, installs the real bundle, validates readiness/stop/uninstall, and
# removes only state and group objects created by the gate itself.
qualify-local-daemon-install: test-local-daemon-live-gate-contract build-release-verifier
	APOLYSIS_LIVE_SYSTEM_INSTALL=1 ./scripts/qualify-local-daemon-install.sh

# Privileged, explicit and non-CI. Produces paired raw evidence below
# target/qualification/ and remains non-zero while the profile is Candidate.
qualify-live:
	./scripts/capture-qualification-preflight.sh
