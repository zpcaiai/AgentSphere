# Sandbox threat model

The runtime assumes Agent and tool inputs are hostile. It validates signed authorization before filesystem or credential allocation; uses fixed executor templates without shell; clears inherited environment; bounds CPU/memory/PID/disk/output/time declarations; defaults network off; and controls the process group outside the Agent. Authorization replay, digest drift, dangerous loader variables, weak profiles, traversal cleanup, and unbounded output fail closed.

The dispatcher spool is not Evidence authority. Independent PEP, registry, runtime and
host-receipt key usages prevent one compromised signing role from fabricating the entire
chain. The worker measures the root-owned runsc file before admission and the command
builder measures it again before invocation. Replay, state and result directories are
worker-only; the receipt private key is a systemd encrypted credential unavailable to the
dispatcher. Docker/Podman sockets, host-root mounts and nested runsc are forbidden.
