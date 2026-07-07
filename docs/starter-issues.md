# Starter Issue Set

These are small, labeled starter issues that fit the current Apolysis direction.
They are safe entry points because they improve adoption without expanding the
product beyond runtime accountability.

## Runtime evidence fixtures

Labels: `good first issue`, `help wanted`, `enhancement`

Add one small fixture timeline that demonstrates a local agent workload opening
a file under the workspace and a redacted credential-looking path outside the
workspace. The fixture should include the expected canonical event output and
must not contain private host paths or secrets.

Suggested verification:

```bash
cargo test --workspace
```

## Release artifact verification

Labels: `good first issue`, `help wanted`, `documentation`

Document one manual verification path for downloaded release artifacts using
`sha256sum -c`, `tar -tzf`, and `apolysis --help` or the current usage output.
Keep the docs focused on the attached CLI and CO-RE BPF object.

Suggested verification:

```bash
make quickstart
```

## Timeline shipping documentation

Labels: `good first issue`, `help wanted`, `documentation`

Add a short documentation note showing how an operator can ship JSONL timelines
with Vector or Fluent Bit while preserving Apolysis as the schema owner and the
external log system as the query plane. Do not add a new exporter until a real
deployment asks for it.

Suggested verification:

```bash
make test
```
