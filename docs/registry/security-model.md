# Registry security model

Unregistered, ambiguous, inactive, tenant-hidden, revoked, or digest-drifted tools fail closed. Input and output schemas use Draft 2020-12, reject remote/file references and require closed object roots. Capability discovery always returns `discovery_only=true` and `authorization_required=true`. High-risk execution performs online revocation checks; write actions never rely on a stale cache.

