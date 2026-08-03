# Focus Apolysis on eBPF Agent runtime observability

Status: accepted

Apolysis previously expanded toward a cross-provider Agent evidence and policy
plane with authenticated Gateway, PostgreSQL projections, evidence-object
storage, semantic adapters, outcome verification, and a multi-user Console.
That direction made the eBPF collector optional and committed the project to
several independent products before the runtime observation workflow had been
validated.

Apolysis now focuses on Agent runtime observability in operator-controlled
Linux environments. Its eBPF collector is a required primary source, and its
product aggregate is the Agent Observation Record: one run-scoped account of
supported process, file, network, and credential-related observations,
runtime attribution, collector health, findings, and explicit gaps. Local
Linux and container workloads are the first stable environments; Kubernetes
node observation follows as a bounded beta. A local operator viewer completes
the active product workflow.

Cross-provider semantic ingestion, provider hooks, remote export and outcome
verification, synchronous policy enforcement, a multi-tenant evidence Gateway,
PostgreSQL/S3 custody, and provider-managed environments without a
customer-controlled kernel are no longer active roadmap scope. Existing
prototypes remain recoverable in Git
history and are removed from the active workspace in a separate change. Any
future central evidence plane requires demonstrated user demand and a new ADR.
This decision supersedes ADR-0001, ADR-0002, and ADR-0003 as active product
architecture decisions; those documents remain as history for the prototypes
that implemented them.
