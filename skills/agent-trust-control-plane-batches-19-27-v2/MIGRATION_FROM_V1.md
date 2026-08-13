# Migration from the 28-Batch v1 package

- Corrected Batch 01/02/03/05/06/07 titles in README and manifest.
- Added explicit dependency semantics and removed semantic cycles between Batch 15/18 and Batch 16/24.
- Added SignedGoal, PlanManifest, DelegationEnvelope and AuthorizationLease to Batch 01.
- Changed Action IR to common envelope + typed domain payload.
- Added Minimal Approval Kernel to Batch 06; Batch 17 now owns enterprise approval governance only.
- Separated workload identity (Batch 04) from target credentials (Batch 08).
- Added evaluator calibration and independent judge governance to Batch 10.
- Moved Domain Pack SDK foundation to Batch 20; Batch 28 now owns marketplace lifecycle only.
- Renamed Batch 22 to Release Gate Engine; only Batch 36 can issue final Production Closure.
- Added Batch 29—36 for durable orchestration, agent inventory, policy lifecycle, context provenance, red-team evaluation, SRE/DR, enterprise console and final closure.
- Added global dependency, threat-control, control-evidence, end-to-end and NFR matrices.
