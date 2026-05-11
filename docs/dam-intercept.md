# dam-intercept

`dam-intercept` is the guarded TLS interception activation contract for transparent AI protection.

It does not decrypt traffic, run a TLS proxy, install routes, or generate certificates. It combines `dam-net` routing readiness with `dam-trust` TLS readiness and explicit user consent, then reports whether a TLS interception adapter may activate for an AI route from the effective traffic profile registry. `dam-proxy` now provides the first daemon-gated HTTP/1.1 adapter runtime; this crate remains the shared activation gate.

## Current Contract

Readiness states:

```text
not_transparent_mode  route capture is inactive for this mode
needs_routing         system proxy or TUN routing is not active
needs_user_consent    interception was not explicitly approved
needs_trust           local TLS trust prerequisites are not ready
needs_adapter         the TLS interception runtime is not available
ready                 routing, consent, trust, and adapter runtime are all ready
```

Activation is fail-closed. `TlsInterceptionAdapter::activate` returns an error unless readiness is exactly `ready`.

## Current Consumers

- `dam-daemon` records per-route interception readiness for active traffic profile routes in `daemon.json`.
- `dam status` and `damctl daemon inspect` show interception readiness next to routing and trust readiness.
- `dam-proxy` uses the same readiness result before accepting transparent CONNECT/TLS traffic in daemon transparent mode.

## Boundaries

`dam-intercept` owns:

- the final transparent-interception activation gate;
- the ordered prerequisite checks: routing, consent, trust, adapter runtime;
- adapter activation result and fail-closed error shape.

`dam-intercept` does not own:

- OS routing;
- local CA generation or system trust mutation;
- TLS MITM implementation details;
- provider request/response parsing;
- detection, policy, consent storage, vault, logging, or redaction.

Those remain in `dam-net`, `dam-trust`, platform network modules, `dam-proxy`, provider adapters, and the spine modules.

## Tests

```bash
cargo test -p dam-intercept
```
