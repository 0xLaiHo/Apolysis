# Offline Hash-Chain Verification

Apolysis daemon timelines are append-only hash-chain JSONL files. Use offline
verification after copying a session timeline out of a node, before importing it
into an evidence package, or before relying on a shipped timeline during release
or incident review.

```bash
./target/debug/apolysis verify hash-chain \
  --input /var/lib/apolysis/sessions/<session-id>/timeline.jsonl \
  --output target/hash-chain-verification/<session-id>.report.json
```

Exit codes:

- `0`: the timeline is fully valid.
- `1`: the report was written, but the timeline failed verification.
- `2`: the command could not run, for example because the input file could not
  be read or the arguments were invalid.

The verifier uses `HashChainStore::verify`, which is read-only. It does not
truncate the source timeline, write a quarantine file, or repair corrupted
content. That makes it safe to run against copied evidence and production
archives.

The JSON report contains:

- `path`: verified timeline path.
- `passed`: `true` only when every complete record verifies and there is no
  invalid or truncated tail.
- `record_count`: number of verified records.
- `last_sequence`: last verified hash-chain sequence number.
- `last_record_hash`: last verified record hash, or the zero hash for an empty
  timeline.
- `valid_bytes`: byte count covered by the valid prefix.
- `total_bytes`: source file byte count.
- `failure`: `null` for valid timelines, otherwise a fail-closed explanation.

The verifier preserves the existing hash-chain contract: each line stores a
record hash over the schema version, sequence, previous hash, and canonical JSON
payload. A middle corruption fails closed. A truncated or corrupt final tail is
reported as invalid without mutating the timeline.
