# Make evidence-object references non-authoritative

Status: accepted

Large or binary evidence is admitted only when the current organization,
source registration, credential, run, source stream, capability, privacy
profile, retention profile, and object policy all authorize the capture. The
client first reserves immutable metadata in PostgreSQL, then uploads through a
server-owned S3 client, and finally performs a bounded full read-back. The
object becomes available only after decryption, exact size checking, and
SHA-256 verification succeed. An `EvidenceObjectRef` is integrity metadata; it
is never a bearer capability and this write-side crate exposes no raw-object
read API. The first full-read implementation caps plaintext at 64 MiB in both
policy and request validation, checks the ciphertext-plus-tag allocation, and
fails fallibly before allocation; larger objects require a separately reviewed
bounded streaming format.

Object bytes live only in S3-compatible storage. Each object has a random data
key and content nonce. The data key is wrapped with a runtime-supplied
AES-256-GCM key, and authenticated data binds organization, object, run,
source, capability, payload, digest, size, and wrapping-key reference. The
lease digest and a keyed digest of the exact endpoint, region, bucket,
path-style mode, and logical backend identity are also bound. The
PostgreSQL registry separates immutable integrity/lifecycle facts from the
storage locator and encrypted-key material. Deletion removes ciphertext and
storage material before leaving a minimal database tombstone and a zero-byte
storage purge barrier. The first implementation accepts
a runtime wrapping key; production KMS custody and coordinated key rotation
remain a separate gate. Explicit data-key and plaintext work buffers are
zeroized, but this decision does not claim cross-architecture erasure of every
derived RustCrypto cipher-schedule/authenticator state or caller-owned input
buffer; production cryptographic-backend memory-lifecycle qualification is
also separate.

Reservation, quota accounting, a lifecycle outbox fact, and an audit fact
commit together. Database constraints bind an object to its real run profile,
source stream, capability, payload, and eventual evidence event. Triggers
enforce trusted database time, policy ceilings, organization-wide quota and
rate accounting with deferred aggregate checks, immutable metadata, legal
lifecycle revisions, and the presence of current outbox and audit records.
These checks defend against
alternate writers. Production deployment therefore uses a distinct NOLOGIN
schema owner plus separate Gateway runtime/control, object runtime/control,
and deletion-acknowledgement roles; the served runtime never performs
migrations or owns tables and cannot disable the guards.
`deploy/bootstrap_roles.sql` runs under a PostgreSQL superuser and establishes
restrictive defaults before the owner-scoped migration;
`deploy/privileges.sql` fails if the result is not owner-scoped, then seals it
before served logins start. Re-running the bootstrap after login provisioning
also rejects capability delegation, unrelated memberships, direct or
out-of-surface authority, DDL ownership, and any parameter grant or persistent
setting that could start a served session outside PostgreSQL's origin trigger
mode. Deployment artifacts and definer routines pin hostile search paths, and
served pools/transactions requalify origin mode before mutation. Fixed role
names require a dedicated
Apolysis PostgreSQL cluster; database markers reject accidental reuse in a
second database. This role split is not tenant RLS.

Deletion denies new resolution immediately and then proceeds asynchronously.
Every data PUT is conditional on key absence. The reaper first installs a
retained zero-byte barrier at that key, then enumerates and deletes every prior
ciphertext version and delete marker, verifies the exact barrier, removes the
locator and encrypted key, and waits for every
projection/cache/grant/export component registered at deletion-request time to
acknowledge the exact revision. Quota is released and the tombstone becomes
`deleted` only after both physical purge and propagation complete. A storage
outage therefore leaves content denied but quota reserved for a later retry.
Claims take organization locks before object locks and select at most one
oldest candidate per chosen organization. Provider failures retain a bounded
retry claim, while storage-purged objects with missing acknowledgements leave
the candidate set until the last acknowledgement arrives. Every database phase
after S3 verifies the exact worker and attempt timestamp. Concurrent expired
attempts retain zero-byte barriers, serial retries reuse the current exact
barrier, and incomplete provider pagination or version metadata fails closed.

The explicit provider gate uses pinned single-node PostgreSQL and SeaweedFS
containers, real credentials, real encrypted bytes, versioning, concurrent
same-identity writers, policy tightening, two-bucket binding, deletion
credential rotation, a conditional-late-PUT/purge race, process and provider
restarts, distinct non-owner database logins, migration continuity, forbidden
owner/DDL/credential paths, and crash seams around reserve and PUT. Passing it
qualifies this bounded S3-compatible lifecycle, not AWS S3 parity, replication,
failover, TLS, production KMS, point-in-time recovery, high availability, or
the future authenticated Query/object-read plane.
