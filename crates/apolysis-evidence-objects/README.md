# `apolysis-evidence-objects`

This crate owns the durable write-side lifecycle for explicitly authorized
large or binary evidence. It coordinates the PostgreSQL registry with an
S3-compatible provider without exposing bucket names, storage keys, provider
credentials, wrapped keys, or a source-authorized content-read method.
Because capture finalization performs a full authenticated read-back, this
version enforces a 64 MiB plaintext ceiling in both policy and request
validation and uses checked, fallible ciphertext allocation. Larger objects
require a future bounded streaming format rather than a larger policy value.

## Lifecycle

1. `begin_upload` revalidates current source authority and atomically reserves
   immutable metadata, organization quota/rate capacity, an outbox fact, and
   an audit fact.
2. `upload_pending` verifies caller bytes, envelope-encrypts them with a random
   per-object data key, and performs an idempotent conditional PUT.
3. `finalize_upload` performs a full authenticated GET, decrypts the result,
   and verifies exact SHA-256 and size before changing the registry state to
   `available`.
4. Gateway ingest binds a novel event and available object in one PostgreSQL
   transaction using the complete organization/run/source/capability/payload
   identity.
5. `request_delete` denies future use immediately. The reaper removes every
   prior ciphertext version and delete marker, verifies absence, waits for
   registered deletion consumers, removes encrypted storage material, and
   retains a minimal tombstone.

Served transactions install transaction-local PostgreSQL lock and statement
timeouts. Reaper claims follow organization-before-object lock order, take at
most one oldest candidate per selected organization in each pass, and fence
every post-provider database mutation with the exact worker/attempt token.
Expired overlapping attempts retain and reuse zero-byte purge barriers; missing
provider pagination, key, version, or size metadata fails closed.

An `EvidenceObjectRef` binds the expected identity, digest, and size only.
Possessing one never grants a read. A future Query service must make a fresh
operator and object authorization decision and record an audit event.

## Verification

Run local contract and cryptographic tests with:

```bash
cargo test -p apolysis-evidence-objects --all-targets
```

Run the explicit real-provider qualification gate with:

```bash
make test-evidence-objects-real
```

The provider gate requires Docker. It creates pinned PostgreSQL and SeaweedFS
containers on separate internal Docker bridges without publishing host ports,
mounts generated credentials and wrapping-key bytes from private files, enables
bucket versioning, exercises real encrypted object
I/O and anti-bypass constraints, provisions distinct SCRAM-authenticated
Gateway runtime, Gateway control, object runtime, object control, and
deletion-acknowledgement logins, and proves that the NOLOGIN schema owner cannot
be assumed by a served login. It rejects capability delegation, external
memberships, out-of-surface ACL/ownership drift, unsafe DDL and
replication-role authority, hostile deployment/temp search paths, and
replica-default served sessions before mutation. It also exercises real
deadlock and expired-claim races, kills application processes at durable saga
seams, restarts the storage provider from the same data directory, and scans
bounded artifacts for database, provider, wrapping-key, replay-key, and
role-password leakage.
It does not use a fake S3 server or an in-memory database.

## Non-claims

This crate is not the public Query/object-read API and does not authorize a
browser. The current wrapping key is a runtime input rather than a production
KMS integration. Explicit data-key and plaintext work buffers are zeroized,
but the current RustCrypto backend is not a cross-architecture guarantee that
all derived cipher-schedule/authenticator state is erased; caller-owned input
`Bytes` are also outside this crate's erasure boundary. That remains part of
production cryptographic-backend and key-custody qualification. The database
capability roles are process-plane separation, not tenant RLS. The
qualification environment is deliberately single-node;
AWS compatibility, TLS, replication, failover, point-in-time recovery,
multi-region durability, coordinated key rotation, and high availability
remain outside this slice.
