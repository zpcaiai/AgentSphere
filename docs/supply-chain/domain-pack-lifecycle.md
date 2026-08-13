# Supply chain and Domain Pack lifecycle

All executable extensions—Rust/Python/Java/npm artifacts, containers, adapters, policies, prompts, evaluators, models, and Domain Packs—must enter through the Batch 20 verifier. It validates artifact digest, publisher trust, signature, SBOM, provenance, vulnerability policy, permission declaration, and revocation freshness.

Pack lifecycle is `publish -> scan/verify -> permission diff -> approval -> sandbox test -> install -> environment activation`. New network, data, effect, or irreversible capabilities invalidate prior approval. Batch 28 keeps the prior version for rollback and propagates revocation to installations.

The scaffold command is:

```sh
python3 -m python.pack_cli.cli new example-pack --publisher publisher:example --root /safe/output
python3 -m python.pack_cli.cli verify /safe/output/example-pack/pack.json
```

The generated pack is default-deny. A CLI digest is not a production certificate; external PKI, registry, scanner, sandbox, and signing pipeline evidence are separate gates.
