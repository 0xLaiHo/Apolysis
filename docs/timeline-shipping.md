# Timeline Shipping

Apolysis session timelines are newline-delimited JSON evidence files. JSONL remains the shipping contract for R3: every record is one JSON object on one line, and collectors should transport those lines without reshaping them.

Default daemon timelines live under:

```text
/var/lib/apolysis/sessions/*/timeline.jsonl
```

Use this path as a collection source for node-local agents such as Vector or
Fluent Bit. Keep generated collector buffers and copied evidence under
operator-owned storage, not in the source tree.

## Operator Rules

- Do not rewrite record payloads. Route, tag, buffer, compress, or encrypt
  outside the record body instead.
- Preserve the original line boundaries. Apolysis JSONL records do not require
  multiline joining; avoid collector multiline settings such as
  `multiline.mode = "halt_before"`.
- Run `apolysis verify hash-chain` before relying on a copied daemon timeline
  for incident replay, audit packages, or release evidence.
- Treat collector failures as an operations signal. Shipping does not replace
  the node-local timeline until the operator has verified downstream retention.
- OTLP is intentionally deferred. Add OTLP only after a real deployment needs
  it and can preserve the JSONL evidence contract.

## Vector

This minimal Vector source tails daemon timelines and forwards parsed JSON
records to an operator-managed sink. Replace the sink with the deployment's
existing log pipeline.

```toml
[sources.apolysis_timelines]
type = "file"
include = ["/var/lib/apolysis/sessions/*/timeline.jsonl"]
read_from = "beginning"

[transforms.apolysis_parse_json]
type = "remap"
inputs = ["apolysis_timelines"]
source = '''
. = parse_json!(.message)
.apolysis_collector = "vector"
'''

[sinks.apolysis_stdout]
type = "console"
inputs = ["apolysis_parse_json"]
encoding.codec = "json"
```

Keep backpressure, disk buffers, and retention policy in the sink
configuration. The Apolysis record payload should stay unchanged.

## Fluent Bit

This Fluent Bit example tails the same timeline path and parses each line as
JSON. Replace the output with the operator's existing destination.

```ini
[INPUT]
    Name tail
    Path /var/lib/apolysis/sessions/*/timeline.jsonl
    Parser json
    Tag apolysis.timeline
    DB /var/lib/apolysis/collectors/fluent-bit-apolysis.db
    Read_from_Head On

[PARSER]
    Name json
    Format json

[OUTPUT]
    Name stdout
    Match apolysis.timeline
```

Use a persistent tail database path outside the session directories so
collector state does not appear inside evidence folders.

## Verification Before Replay

For daemon hash-chain timelines, verify a copied file before using it as
evidence:

```bash
apolysis verify hash-chain \
  --input /var/lib/apolysis/sessions/<session-id>/timeline.jsonl \
  --output /tmp/apolysis-<session-id>-hash-chain-report.json
```

Exit code `0` means the timeline passed. Exit code `1` means Apolysis wrote a
report but found invalid or truncated evidence. Exit code `2` means the command
itself failed.

Do not run repair or cleanup steps against original timelines during shipping.
If verification fails, copy the report and preserve the source file for review.
