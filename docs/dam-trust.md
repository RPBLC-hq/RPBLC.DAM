# dam-trust

`dam-trust` defines the TLS trust contracts and local CA handling for DAM's future transparent protection path.

It can generate and delete local DAM CA certificate/key artifacts under the DAM state directory. On macOS, it can also preview, install, and remove that CA in the current user's login keychain when the caller gives explicit approval. This avoids the System keychain administrator-authorization path for the local desktop UX. It can issue per-host leaf certificates from the local CA for the guarded `dam-proxy` transparent runtime. It does not route traffic, intercept TLS, or decrypt traffic by itself.

## Current Contracts

Trust modes:

```text
disabled   current default; no TLS trust changes
local_ca   planned local DAM CA mode for future transparent HTTPS/WSS protection
```

Platform trust stores:

```text
macos_keychain
windows_root_store
linux_nss_or_system_store
unknown
```

Trust actions:

```text
inspect           implemented; reports trust metadata without system changes
install_local_ca  implemented on macOS; planned elsewhere; requires explicit user consent
remove_local_ca   implemented on macOS; planned elsewhere; removes recorded DAM trust material
```

On macOS, `install_local_ca` and `remove_local_ca` use `/usr/bin/security` against `$HOME/Library/Keychains/login.keychain-db` or the legacy `login.keychain` path. Failed keychain writes leave the local manifest unchanged.

`TrustActionPlan` reports whether an action is implemented, requires admin rights, changes local trust, needs user consent, and requires rollback support.

Local CA artifact files:

```text
$DAM_STATE_DIR/trust/local-ca/manifest.json
$DAM_STATE_DIR/trust/local-ca/ca.pem
$DAM_STATE_DIR/trust/local-ca/ca-key.pem
```

When `DAM_STATE_DIR` is unset, `$HOME/.dam` is the state directory. On Unix platforms, the artifact directory is set to `0700`, the private key and manifest are written as `0600`, and the certificate is written as `0644`. Writes are atomic, and generation refuses to overwrite existing DAM CA material.

Trust commands are previewed by default through `dam trust install-local-ca` and `dam trust remove-local-ca`. The commands mutate macOS user trust only when the caller passes `--yes`. Installation marks the manifest with `installed_at_unix` after the Keychain command succeeds. Removal clears that marker only after the Keychain removal command succeeds.

`issue_local_ca_leaf_certificate` reads the local CA artifact and issues an in-memory server certificate/key for a normalized host. Leaf certificates are used by the daemon-gated transparent CONNECT runtime and are not written to daemon state.

## TLS Readiness

`dam-trust` combines a `dam-net` transparent route decision with local trust state:

```text
non-AI traffic              -> not in scope
HTTP/WS AI-route traffic    -> TLS trust not required
HTTPS/WSS AI-route traffic  -> needs trust checks
```

For encrypted AI traffic, readiness is explicit:

```text
disabled            TLS interception is disabled
host_not_allowed    host is outside the trusted AI host scope
needs_user_consent  user has not approved interception for this scope
needs_local_ca      local DAM CA is not installed
ready               host is allowed, user consented, local CA installed
```

The default trusted AI host scope comes from `dam-net`:

```text
api.openai.com
api.anthropic.com
api.x.ai
chatgpt.com
```

When the daemon loads the effective `[traffic]` profile, it extends the in-memory trusted host scope for transparent readiness with those route hosts. This keeps local CA readiness aligned with the same profile-derived route registry used by routing and transparent proxy activation.

This list is a transparent-protection scope, not an egress policy allowlist.

## Current Consumers

- `dam-daemon` stores `trust.mode`, platform store metadata, and trusted AI host scope in `daemon.json`.
- `dam-daemon` stores per-route trust readiness for active traffic profile routes in `daemon.json`.
- `dam connect --trust-mode disabled|local_ca` records the selected trust mode for future UI/status flows.
- `dam trust generate-local-ca` creates local CA artifacts without installing trust.
- `dam trust delete-local-ca` deletes uninstalled DAM CA artifacts without changing local trust.
- `dam trust install-local-ca` previews by default and installs the CA into macOS user trust only with `--yes`.
- `dam trust remove-local-ca` previews by default and removes the recorded CA from macOS user trust only with `--yes`.
- `dam status` prints `trust_mode` and per-route trust readiness when daemon state exists.
- `damctl trust inspect` prints read-only trust readiness, local CA artifact metadata, and trust action plans.
- `damctl daemon inspect` prints trust mode, platform store, local CA installed state, and trusted AI host count.

## Boundaries

`dam-trust` owns:

- trust-mode vocabulary;
- local CA metadata shape;
- local CA artifact generation, inspection, and deletion;
- local CA leaf certificate issuance for approved transparent runtime use;
- local CA system-trust action planning;
- macOS user login-keychain install/remove execution for DAM-managed CA artifacts;
- platform trust-store tags;
- trusted AI host scope;
- TLS interception readiness decisions.

`dam-trust` does not own:

- routing, TLS interception, or decrypted traffic handling;
- packet or proxy routing;
- provider request/response handling;
- detection, policy, consent, vault, logging, or redaction.

Those stay in future platform trust installers for Windows/Linux, `dam-net`, `dam-proxy`, provider adapters, and the spine modules.

## Tests

```bash
cargo test -p dam-trust
```
