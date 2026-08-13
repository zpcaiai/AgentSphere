# CN standard adapter version-package upgrade

No authoritative domestic standard content is bundled in this repository. The adapter therefore
implements a schema-driven skeleton and must not be described as fully compatible until the user or
official source supplies the exact schema, examples, publication date, license and digest.

Import procedure: verify source and license; compute root-schema and canonical bundle hashes; run
schema examples and mapping coverage; review security-critical loss; register enterprise extension
namespaces; activate the immutable version. Identifiers remain discovery attributes, never
authentication. Extensions cannot override tenant, trust, authorization, resource or policy fields.

For upgrades, run old and new bundles in parallel, generate the compatibility matrix, replay
conformance and policy tests, canary by tenant, and retain the prior immutable bundle. Rollback selects
the prior version; it never rewrites the current package. Cross-standard MCP/A2A comparison is a
mapping report, not evidence of authorization.
