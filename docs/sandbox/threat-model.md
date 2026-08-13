# Sandbox threat model

The runtime assumes Agent and tool inputs are hostile. It validates signed authorization before filesystem or credential allocation; uses fixed executor templates without shell; clears inherited environment; bounds CPU/memory/PID/disk/output/time declarations; defaults network off; and controls the process group outside the Agent. Authorization replay, digest drift, dangerous loader variables, weak profiles, traversal cleanup, and unbounded output fail closed.

