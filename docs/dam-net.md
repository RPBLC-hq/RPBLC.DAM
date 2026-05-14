# dam-net

`dam-net` defines the first network-control contracts for DAM's local traffic mediation path.

It does not install system proxy settings, create a TUN device, intercept TLS, forward packets, or inspect traffic. It is a small control-plane crate used to keep daemon, UI, CLI, and future native network modules aligned on the same vocabulary.

DAM network control must remain portable across macOS, Linux, and Windows. Platform-specific implementations such as `dam-net-macos` live behind shared capture-mode, readiness, and routing-failure-policy contracts; missing or partial platform support must stay tracked in `docs/parking-lot.md` or the module parking lot until it is implemented and tested.

The architecture is not AI-only. The bundled LLM targets are the MVP traffic profile; future profiles can describe WebSocket chats, email, uploads, media/control protocols, or other application traffic as adapters become available.

## Current Contracts

Capture modes:

```text
explicit_proxy  implemented routing for clients explicitly configured to use DAM as a local endpoint or HTTP(S) proxy
system_proxy    OS proxy routing mode for proxy-capable HTTP/HTTPS traffic
tun             platform capture backend mode; macOS uses Network Extension
```

`CapturePlan::for_mode` reports whether a mode is implemented, whether it requires admin/system permission, whether it installs system routes, and what TLS visibility is available.

`TransparentRouteCaptureReadiness` reports per configured-profile-route routing readiness for capture modes:

```text
not_transparent_mode         route capture is inactive for this mode
needs_system_proxy_install   system proxy routing is not active
needs_tun_install            TUN routing is not active
ready                        routing is active for the route
```

Current implementation status:

- `explicit_proxy`: implemented for local base-URL traffic and HTTP(S) proxy traffic from configured clients. HTTPS body protection for configured hosts still requires local CA trust and the CONNECT/TLS adapter.
- `system_proxy`: macOS PAC routing is implemented in `dam-net-macos` for proxy-capable HTTP/HTTPS traffic. Unknown/non-configured hosts pass through DAM untouched; HTTPS body visibility for configured hosts still requires TLS trust and interception.
- `tun`: platform capture backend mode. macOS Network Extension control-plane support is implemented in `dam-net-macos`; activation requires the signed native helper/app bundle. Linux and Windows have distinct onboarding contracts under the same setup-plan vocabulary, but their transparent routing backends are still planned and currently direct users to explicit proxy mode.

Protocol adapters are reported separately from capture. HTTP is implemented for the first bidirectional protected LLM traffic, and the Codex ChatGPT-login WebSocket MVP protects unfragmented client and server text frames on protected connections. gRPC, email, media/audio, and other chat protocols are profile-level adapter kinds with planned runtime support.

## Full-Traffic Mediation

The macOS `system_proxy` implementation routes proxy-capable HTTP and HTTPS traffic to DAM. DAM's default host policy is conservative:

```text
unknown host                 -> pass through without TLS decrypt, body reads, or redaction
active profile match + inspect -> protect when routing, trust, consent, and adapter readiness pass
active profile match + paused  -> pass through without redaction
active profile match + not ready -> fail according to the configured failure behavior
```

PAC routing is not true packet-level full-device capture. `tun`/Network Extension is the primary full-device path: it can classify TCP flows by destination and hand active profile matches to the protected proxy runtime. Unsupported protocols or encrypted bodies still require protocol-specific adapters before DAM can inspect payloads.

Failure behavior is a platform-neutral policy:

- `fail_open` is the consumer default: when DAM is off, paused, unhealthy, unreachable, or not ready for a configured route, traffic passes outside DAM and surfaces as unprotected.
- `fail_closed` is explicit user/admin or managed-install behavior: configured traffic is blocked when DAM cannot verify protection.

Platform capture backends must apply the policy to new flows and to already-captured flows. Runtime app enablement narrows the active traffic profile; an explicit empty enabled-app selection means no configured flows should be mediated, so platform capture must pass traffic through instead of falling back to bundled defaults. On macOS Network Extension capture, the provider caches local proxy health/routing state for new-flow decisions and closes active configured flows when the local proxy stops reporting `protected`; the client then reconnects through the current policy instead of staying pinned through DAM while it is paused or unhealthy.

## Traffic Profiles

`dam-net` owns a generic traffic profile contract. A profile is JSON data with app entries, not provider-specific code. Each app entry can define:

- match rules: domains, IPs, URL prefixes, ports, protocols, and process names;
- action: `inspect`, `bypass`, `block`, or `log_metadata`;
- adapter kind: `http`, `web_socket`, `grpc`, `email_imap`, `email_smtp`, `media`, or `unknown`;
- outbound filter policy and inbound policy, including reference restoration and explicit raw-value protection;
- ordered pipeline step names such as detect, consent, tokenize, and resolve;
- optional provider/upstream target metadata for current proxy routing.

The bundled MVP profile lives at `crates/dam-net/profiles/llm-mvp.json`. Its active app IDs are:

```text
openai-api       -> api.openai.com / HTTP
anthropic-api    -> api.anthropic.com / HTTP
chatgpt-codex    -> chatgpt.com, ab.chatgpt.com / WebSocket
```

Inbound HTTP response mutation is explicit per traffic app. `inbound.resolve_references` controls local restoration of existing DAM references, and `inbound.protect_sensitive_data` controls whether raw inbound response text is redetected/tokenized when no reference resolves. The bundled OpenAI API and Anthropic API apps opt into raw inbound protection; the ChatGPT Codex app does not opt into HTTP inbound protection because its `chatgpt.com` bootstrap and web backend responses are not safe to rewrite generically. WebSocket text-frame protection is handled by the WebSocket adapter's per-connection protection snapshot.

`known_ai_routes()` is now a compatibility view derived from the bundled traffic profile. New mediated services, including private OpenAI-compatible and Anthropic-compatible endpoints, must be added as traffic profile JSON app entries. User-authored profile create/import/export is parked; when it returns, new services should still be validated JSON profile data rather than provider-specific Rust code.

For TLS traffic, classification can identify that traffic matches a configured profile, but it cannot protect request bodies without `dam-trust` readiness and a later TLS interception implementation. The explicit decision shape for the bundled LLM MVP is:

```text
configured LLM + HTTPS/WSS -> requires TLS interception before body protection
configured LLM + HTTP/WS   -> protectable without TLS
unknown/non-configured host -> pass-through traffic
```

This keeps the future transparent proxy honest: host routing alone is not data protection for encrypted provider requests.

## Current Consumers

- `dam-daemon` stores the selected `network_mode` in `daemon.json`.
- `dam-daemon` stores the effective traffic-profile-derived route registry in non-sensitive daemon state for UI/CLI/status consumers.
- `dam-daemon` stores per-route routing readiness in `daemon.json`.
- `dam status` prints `network_mode` when a daemon is connected or stale.
- `dam-net-macos` installs/removes macOS PAC routing for proxy-capable HTTP/HTTPS traffic and writes rollback state.
- `dam-net-macos` plans/records macOS Network Extension capture for `tun`; source builds require `DAM_MACOS_NE_HELPER`, while signed releases provide the helper from the app bundle.
- `dam-trust` consumes transparent route decisions when reporting future TLS interception readiness.
- `dam-intercept` consumes route readiness as the first gate before TLS interception may activate.

## Boundaries

`dam-net` owns:

- network capture-mode vocabulary;
- generic traffic profile JSON contracts and runtime app filtering;
- traffic profile route registry helpers and host classification;
- transparent route readiness reporting;
- non-TLS route-readiness decisions.

`dam-net` does not own:

- process lifecycle;
- OS proxy/TUN installation;
- TLS trust roots or certificates;
- HTTP forwarding;
- provider request/response adapters;
- detection, policy, vault, consent, logging, or redaction.

Those stay in `dam-daemon`, future platform-specific network modules, `dam-trust`, `dam-proxy`, provider adapters, and `dam-pipeline`.
