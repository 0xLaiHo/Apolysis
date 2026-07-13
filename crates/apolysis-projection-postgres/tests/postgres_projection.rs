// SPDX-License-Identifier: Apache-2.0

//! Explicit, destructive integration gate over a genuine Gateway ledger and PostgreSQL.

mod support;

#[path = "postgres_projection/bounded_pagination.rs"]
mod bounded_pagination;
#[path = "postgres_projection/commit_ambiguity.rs"]
mod commit_ambiguity;
#[path = "postgres_projection/initialization_lock_order.rs"]
mod initialization_lock_order;
#[path = "postgres_projection/lifecycle_projection.rs"]
mod lifecycle_projection;
#[path = "postgres_projection/logical_input_size.rs"]
mod logical_input_size;
#[path = "postgres_projection/rls_scope.rs"]
mod rls_scope;
#[path = "postgres_projection/schema_invariants.rs"]
mod schema_invariants;
#[path = "postgres_projection/workers_rebuild_and_failures.rs"]
mod workers_rebuild_and_failures;
