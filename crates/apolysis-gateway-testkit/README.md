# Apolysis Gateway testkit

This non-publishable crate runs the Execution Evidence Gateway repository
contract against any adapter without widening the production
`GatewayRepository::execute` seam.

An adapter test defines a `GatewayConformanceHarness` that creates isolated
state, returns the repository handle under test, registers trusted join
authorization through test-only administration, and reports the normalized
content-free `GatewayConformanceSnapshot`. It can then register the complete
suite with:

```rust,ignore
use apolysis_gateway_testkit::gateway_repository_conformance_tests;

gateway_repository_conformance_tests!(PostgresGatewayHarness);
```

Each generated test starts a fresh harness. Implementations backed by an
external database must therefore isolate scenarios even when the test runner
executes them concurrently. The shared suite currently contains 28 lifecycle,
idempotency, same-batch duplicate, authorization, atomicity, admission, expiry,
and finalization scenarios.

The snapshot is a testkit inspection shape, not a production repository API.
Each adapter harness owns its test-only inspection mechanism; adapters do not
need to expose snapshot or read access through `GatewayRepository`.
