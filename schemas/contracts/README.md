# Generated Production Contracts

The `v0.1` JSON Schema files are generated from the public Rust wire roots in
`apolysis-contracts`. Do not edit generated schema files by hand.

```bash
cargo run -p apolysis-contracts --bin export_schemas
cargo test -p apolysis-contracts --test schema_snapshots
```

An incompatible change after the W1–W2 gate requires a new contract version,
updated positive and negative fixtures, and the corresponding contract-document
change in the same Pull Request.
