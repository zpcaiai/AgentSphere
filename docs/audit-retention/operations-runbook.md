# Audit retention operations

Batch 19 stores tenant-scoped signed chain heads, retention policies, Legal Holds, exports, and deletion evidence. Ingestion rejects sequence gaps, duplicate identifiers with different content, and capacity overflow. Queries require a tenant and are themselves audited.

Managed evidence storage must enable S3 versioning and Object Lock in
`COMPLIANCE` mode. Verify a deployment-owned protected object version without
mutating or deleting it:

```sh
AGENTTRUST_S3_ACCESS='deployment-injected' \
AGENTTRUST_S3_SECRET='deployment-injected' \
python3 -m python.production_gates.object_store_retention \
  --endpoint https://s3.example --region eu-west-1 \
  --bucket agenttrust-evidence --object-key releases/RELEASE/evidence.json \
  --version-id OPAQUE_VERSION --access-key-env AGENTTRUST_S3_ACCESS \
  --secret-key-env AGENTTRUST_S3_SECRET --minimum-remaining-days 30 \
  --output /absolute/new/object-lock.json
```

The gate verifies the bucket default, versioning, the exact version's retention
deadline and readability. It never attempts deletion and returns only digests.
A multi-zone restore and an independently witnessed deletion-denial exercise
remain part of the production HA/DR assurance.

## Production procedure

1. Verify the active signing key and retention-policy digest before enabling writers.
2. Monitor chain-head lag, rejected batches, hold count, export verification failures, and deletion backlog.
3. Before deletion, resolve active Legal Holds. A hold release requires a distinct releasing principal and a recorded reason.
4. Export a self-contained manifest, artifacts, chain head, schema version, key ID, and signature. Run offline verification before transfer.
5. Restore into an isolated database and object namespace. Recompute every artifact digest and chain link, reconcile record counts, then emit a recovery report.

Do not treat the in-memory unit tests as object-store durability, WORM, disaster recovery, or regulatory evidence. Those gates remain `NOT_RUN` in Batch 19 status.
