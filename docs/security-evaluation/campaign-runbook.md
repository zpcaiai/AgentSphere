# Security evaluation campaign runbook

Attack scenarios declare a versioned target, preconditions, deterministic seed, attack steps, expected controls, success and failure criteria, and cleanup. Compile them with:

```sh
python3 -m python.security_campaign.campaign --compile-only datasets/security-evaluation/v1/prompt-injection.json
```

Execution must occur in a disposable isolated environment without production credentials. Pin policy, pack, prompt, model, and scenario digests. Record prevention, detection, containment, recovery, cleanup, confidence interval, and latency. A cleanup failure fails the campaign. Findings link evidence, owner, remediation, and a retest.

Local deterministic tests exercise the compiler and Rust runner contracts; they are not a production red-team campaign.
