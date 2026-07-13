# Keep production contracts independent from legacy JSONL

Status: accepted

The `apolysis-contracts` crate is the single dependency-light seam for
versioned Gateway, record, coverage, and Query types and their generated
schemas. Legacy `apolysis-core` JSONL v1 remains a compatible edge adapter
format rather than becoming the remote Gateway or Query schema, because its
local event and transport assumptions cannot safely express authenticated
organization scope, source identity, replay, gaps, projections, or independent
coverage. This choice adds an explicit adapter and schema-generation boundary,
but prevents daemon, storage, transport, and browser concerns from redefining
the production evidence contract.
