.PHONY: build test lint clean build-ebpf test-live test-f2-foundation test-f2-runtime test-f2-validation-harness test-f2-runtime-registration test-f2-runtime-adapters test-f2-runtime-adapter-matrix test-f2-recovery test-f2-performance test-f2-visibility-reports test-f2-production-qualification test-f3-guardrails test-f3-bpf-lsm-live test-f4-runtime-guardrails test-f5-production-hardening test-f5-live-deployment test-f5-supply-chain test-f5-helm-production test-f5-release-registry test-f5-tenant-query-retention test-f5-retention-enforcement test-f5-release-promotion-policy test-f5-registry-promotion-execution test-f5-dockerhub-registry-promotion test-f5-signing-profile test-f5-signing-execution test-f5-aws-kms-signing test-f5-external-hsm-signing test-f5-signing-provider-readiness test-f5-aws-kms-signer-bootstrap test-f5-aws-oidc-handoff test-f5-worm-archive-policy test-f5-worm-archive-execution test-f5-service-mesh-live-evidence test-f5-service-mesh-live-istio test-f5-managed-cloud-service-mesh test-f5-vke-cluster-readiness test-f5-vke-service-mesh-provider test-f5-operator-controller test-f5-chaos-performance test-f5-external-provider-qualification test-f5-final-external-provider-bundle test-f5-final-provider-readiness test-f5-final-provider-readiness-contract test-f5-final-provider-completion test-f5-final-provider-bundle-env test-f5-retained-provider-artifact-package test-f5-provider-workflow-readiness test-f5-provider-workflow-dispatch test-f5-provider-workflow-artifact-import test-f5-final-provider-closure test-f6-regulated-release test-f6-provider-execution-plan test-f6-provider-artifact-import test-f6-final-provider-closure test-f6-signing-evidence test-f6-evidence-package test-f6-retained-evidence-package test-f6-external-retention test-f6-immutable-registry-retention test-f6-managed-mesh-decision

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

test-f5-registry-promotion-execution:
	./scripts/test-f5-registry-promotion-execution.sh

test-f5-dockerhub-registry-promotion:
	./scripts/test-f5-dockerhub-registry-promotion.sh

test-f5-signing-profile:
	./scripts/test-f5-signing-profile.sh

test-f5-signing-execution:
	./scripts/test-f5-signing-execution.sh

test-f5-aws-kms-signing:
	./scripts/test-f5-aws-kms-signing.sh

test-f5-external-hsm-signing:
	./scripts/test-f5-external-hsm-signing.sh

test-f5-signing-provider-readiness:
	./scripts/test-f5-signing-provider-readiness.sh

test-f5-aws-kms-signer-bootstrap:
	./scripts/test-f5-aws-kms-signer-bootstrap.sh

test-f5-aws-oidc-handoff:
	./scripts/test-f5-aws-oidc-handoff.sh

test-f5-worm-archive-policy:
	./scripts/test-f5-worm-archive-policy.sh

test-f5-worm-archive-execution:
	./scripts/test-f5-worm-archive-execution.sh

test-f5-service-mesh-live-evidence:
	./scripts/test-f5-service-mesh-live-evidence.sh

test-f5-service-mesh-live-istio:
	./scripts/test-f5-service-mesh-live-istio.sh

test-f5-managed-cloud-service-mesh:
	./scripts/test-f5-managed-cloud-service-mesh.sh

test-f5-vke-cluster-readiness:
	./scripts/test-f5-vke-cluster-readiness.sh

test-f5-vke-service-mesh-provider:
	./scripts/test-f5-vke-service-mesh-provider.sh

test-f5-operator-controller:
	./scripts/test-f5-operator-controller.sh

test-f5-chaos-performance:
	./scripts/test-f5-chaos-performance.sh

test-f5-external-provider-qualification:
	./scripts/test-f5-external-provider-qualification.sh

test-f5-final-external-provider-bundle:
	./scripts/test-f5-final-external-provider-bundle.sh

test-f5-final-provider-readiness:
	./scripts/test-f5-final-provider-readiness.sh

test-f5-final-provider-readiness-contract:
	./scripts/test-f5-final-provider-readiness-contract.sh

test-f5-final-provider-completion:
	./scripts/test-f5-final-provider-completion.sh

test-f5-final-provider-bundle-env:
	./scripts/prepare-f5-final-provider-bundle-env.sh

test-f5-retained-provider-artifact-package:
	./scripts/package-f5-retained-provider-artifacts.sh

test-f5-provider-workflow-readiness:
	./scripts/test-f5-provider-workflow-readiness.sh

test-f5-provider-workflow-dispatch:
	./scripts/test-f5-provider-workflow-dispatch.sh

test-f5-provider-workflow-artifact-import:
	./scripts/test-f5-provider-workflow-artifact-import.sh

test-f5-final-provider-closure:
	./scripts/test-f5-final-provider-closure.sh

test-f6-regulated-release:
	./scripts/test-f6-regulated-release.sh

test-f6-provider-execution-plan:
	./scripts/test-f6-provider-execution-plan.sh

test-f6-provider-artifact-import:
	./scripts/test-f6-provider-artifact-import.sh

test-f6-final-provider-closure:
	./scripts/test-f6-final-provider-closure.sh

test-f6-signing-evidence:
	./scripts/test-f6-signing-evidence.sh

test-f6-evidence-package:
	./scripts/test-f6-evidence-package.sh

test-f6-retained-evidence-package:
	./scripts/test-f6-retained-evidence-package.sh

test-f6-external-retention:
	./scripts/test-f6-external-retention.sh

test-f6-immutable-registry-retention:
	./scripts/test-f6-immutable-registry-retention.sh

test-f6-managed-mesh-decision:
	./scripts/test-f6-managed-mesh-decision.sh
