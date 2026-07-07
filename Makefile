.PHONY: build test lint clean build-ebpf test-live test-jsonl-schema-contract test-release-artifacts test-release-signing test-community-surface test-local-agent-command-attribution test-intent-correlation test-audit-write-budget test-offline-hash-chain-verify test-timeline-shipping test-runtime-foundation test-runtime-foundation-runtime test-runtime-foundation-validation-harness test-runtime-foundation-runtime-registration test-runtime-foundation-runtime-adapters test-runtime-foundation-runtime-adapter-matrix test-runtime-foundation-recovery test-runtime-foundation-performance test-runtime-foundation-visibility-reports test-runtime-foundation-production-qualification test-policy-guardrails test-policy-guardrails-bpf-lsm-live test-runtime-guardrails test-release-validation-handoff test-release-validation-preflight test-release-validation-ci test-production-hardening test-production-hardening-live-deployment test-production-hardening-supply-chain test-production-hardening-helm-production test-production-hardening-release-registry test-production-hardening-tenant-query-retention test-production-hardening-retention-enforcement test-production-hardening-release-promotion-policy test-production-hardening-registry-promotion-execution test-production-hardening-dockerhub-registry-promotion test-production-hardening-signing-profile test-production-hardening-signing-execution test-production-hardening-aws-kms-signing test-production-hardening-external-hsm-signing test-production-hardening-signing-provider-readiness test-production-hardening-aws-kms-signer-bootstrap test-production-hardening-aws-oidc-handoff test-production-hardening-worm-archive-policy test-production-hardening-worm-archive-execution test-production-hardening-service-mesh-live-evidence test-production-hardening-service-mesh-live-istio test-production-hardening-managed-cloud-service-mesh test-production-hardening-vke-cluster-readiness test-production-hardening-vke-service-mesh-provider test-production-hardening-operator-controller test-production-hardening-chaos-performance test-production-hardening-external-provider-qualification test-production-hardening-final-external-provider-bundle test-production-hardening-final-provider-readiness test-production-hardening-final-provider-readiness-contract test-production-hardening-final-provider-completion test-production-hardening-final-provider-bundle-env test-production-hardening-retained-provider-artifact-package test-production-hardening-provider-workflow-readiness test-production-hardening-provider-workflow-dispatch test-production-hardening-provider-workflow-artifact-import test-production-hardening-final-provider-closure test-regulated-release test-regulated-release-provider-execution-plan test-regulated-release-provider-artifact-import test-regulated-release-final-provider-closure test-regulated-release-signing-evidence test-regulated-release-evidence-package test-regulated-release-retained-evidence-package test-regulated-release-external-retention test-regulated-release-immutable-registry-retention test-regulated-release-managed-mesh-decision test-regulated-release-live-provider-readback test-regulated-release-final-release-signoff
.PHONY: test-codex-mismatch-demo
.PHONY: test-codex-live-demo-runbook
.PHONY: test-codex-live-demo-public-assets
.PHONY: test-codex-live-demo-launch-blog
.PHONY: test-release-artifact-dry-run
.PHONY: test-signed-release-artifact-dry-run
.PHONY: test-release-publication-readiness

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

test-jsonl-schema-contract:
	./scripts/test-jsonl-schema-contract.sh

test-release-artifacts:
	./scripts/test-release-artifacts.sh

test-release-signing:
	./scripts/test-release-signing.sh

test-release-artifact-dry-run:
	./scripts/test-release-artifact-dry-run.sh

test-signed-release-artifact-dry-run:
	./scripts/test-signed-release-artifact-dry-run.sh

test-release-publication-readiness:
	./scripts/test-release-publication-readiness.sh

test-community-surface:
	./scripts/test-community-surface.sh

test-codex-mismatch-demo:
	./scripts/test-codex-mismatch-demo.sh

test-codex-live-demo-runbook:
	./scripts/test-codex-live-demo-runbook.sh

test-codex-live-demo-public-assets:
	./scripts/test-codex-live-demo-public-assets.sh

test-codex-live-demo-launch-blog:
	./scripts/test-codex-live-demo-launch-blog.sh

test-local-agent-command-attribution:
	./scripts/test-local-agent-command-attribution.sh

test-intent-correlation:
	./scripts/test-intent-correlation.sh

test-audit-write-budget:
	./scripts/test-audit-write-budget.sh

test-offline-hash-chain-verify:
	./scripts/test-offline-hash-chain-verify.sh

test-timeline-shipping:
	./scripts/test-timeline-shipping.sh

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

test-policy-guardrails:
	./scripts/test-policy-guardrails.sh

test-policy-guardrails-bpf-lsm-live:
	./scripts/test-policy-guardrails-bpf-lsm-live.sh

test-runtime-guardrails:
	./scripts/test-runtime-guardrails.sh

test-release-validation-handoff:
	./scripts/test-release-validation-handoff.sh

test-release-validation-preflight:
	./scripts/test-release-validation-preflight.sh

test-release-validation-ci:
	./scripts/test-release-validation-ci.sh

test-production-hardening:
	./scripts/test-production-hardening.sh

test-production-hardening-live-deployment:
	./scripts/test-production-hardening-live-deployment.sh

test-production-hardening-supply-chain:
	./scripts/test-production-hardening-supply-chain.sh

test-production-hardening-helm-production:
	./scripts/test-production-hardening-helm-production.sh

test-production-hardening-release-registry:
	./scripts/test-production-hardening-release-registry.sh

test-production-hardening-tenant-query-retention:
	./scripts/test-production-hardening-tenant-query-retention.sh

test-production-hardening-retention-enforcement:
	./scripts/test-production-hardening-retention-enforcement.sh

test-production-hardening-release-promotion-policy:
	./scripts/test-production-hardening-release-promotion-policy.sh

test-production-hardening-registry-promotion-execution:
	./scripts/test-production-hardening-registry-promotion-execution.sh

test-production-hardening-dockerhub-registry-promotion:
	./scripts/test-production-hardening-dockerhub-registry-promotion.sh

test-production-hardening-signing-profile:
	./scripts/test-production-hardening-signing-profile.sh

test-production-hardening-signing-execution:
	./scripts/test-production-hardening-signing-execution.sh

test-production-hardening-aws-kms-signing:
	./scripts/test-production-hardening-aws-kms-signing.sh

test-production-hardening-external-hsm-signing:
	./scripts/test-production-hardening-external-hsm-signing.sh

test-production-hardening-signing-provider-readiness:
	./scripts/test-production-hardening-signing-provider-readiness.sh

test-production-hardening-aws-kms-signer-bootstrap:
	./scripts/test-production-hardening-aws-kms-signer-bootstrap.sh

test-production-hardening-aws-oidc-handoff:
	./scripts/test-production-hardening-aws-oidc-handoff.sh

test-production-hardening-worm-archive-policy:
	./scripts/test-production-hardening-worm-archive-policy.sh

test-production-hardening-worm-archive-execution:
	./scripts/test-production-hardening-worm-archive-execution.sh

test-production-hardening-service-mesh-live-evidence:
	./scripts/test-production-hardening-service-mesh-live-evidence.sh

test-production-hardening-service-mesh-live-istio:
	./scripts/test-production-hardening-service-mesh-live-istio.sh

test-production-hardening-managed-cloud-service-mesh:
	./scripts/test-production-hardening-managed-cloud-service-mesh.sh

test-production-hardening-vke-cluster-readiness:
	./scripts/test-production-hardening-vke-cluster-readiness.sh

test-production-hardening-vke-service-mesh-provider:
	./scripts/test-production-hardening-vke-service-mesh-provider.sh

test-production-hardening-operator-controller:
	./scripts/test-production-hardening-operator-controller.sh

test-production-hardening-chaos-performance:
	./scripts/test-production-hardening-chaos-performance.sh

test-production-hardening-external-provider-qualification:
	./scripts/test-production-hardening-external-provider-qualification.sh

test-production-hardening-final-external-provider-bundle:
	./scripts/test-production-hardening-final-external-provider-bundle.sh

test-production-hardening-final-provider-readiness:
	./scripts/test-production-hardening-final-provider-readiness.sh

test-production-hardening-final-provider-readiness-contract:
	./scripts/test-production-hardening-final-provider-readiness-contract.sh

test-production-hardening-final-provider-completion:
	./scripts/test-production-hardening-final-provider-completion.sh

test-production-hardening-final-provider-bundle-env:
	./scripts/prepare-production-hardening-final-provider-bundle-env.sh

test-production-hardening-retained-provider-artifact-package:
	./scripts/package-production-hardening-retained-provider-artifacts.sh

test-production-hardening-provider-workflow-readiness:
	./scripts/test-production-hardening-provider-workflow-readiness.sh

test-production-hardening-provider-workflow-dispatch:
	./scripts/test-production-hardening-provider-workflow-dispatch.sh

test-production-hardening-provider-workflow-artifact-import:
	./scripts/test-production-hardening-provider-workflow-artifact-import.sh

test-production-hardening-final-provider-closure:
	./scripts/test-production-hardening-final-provider-closure.sh

test-regulated-release:
	./scripts/test-regulated-release.sh

test-regulated-release-provider-execution-plan:
	./scripts/test-regulated-release-provider-execution-plan.sh

test-regulated-release-provider-artifact-import:
	./scripts/test-regulated-release-provider-artifact-import.sh

test-regulated-release-final-provider-closure:
	./scripts/test-regulated-release-final-provider-closure.sh

test-regulated-release-signing-evidence:
	./scripts/test-regulated-release-signing-evidence.sh

test-regulated-release-evidence-package:
	./scripts/test-regulated-release-evidence-package.sh

test-regulated-release-retained-evidence-package:
	./scripts/test-regulated-release-retained-evidence-package.sh

test-regulated-release-external-retention:
	./scripts/test-regulated-release-external-retention.sh

test-regulated-release-immutable-registry-retention:
	./scripts/test-regulated-release-immutable-registry-retention.sh

test-regulated-release-managed-mesh-decision:
	./scripts/test-regulated-release-managed-mesh-decision.sh

test-regulated-release-live-provider-readback:
	./scripts/test-regulated-release-live-provider-readback.sh

test-regulated-release-final-release-signoff:
	./scripts/test-regulated-release-final-release-signoff.sh
