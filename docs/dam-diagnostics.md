# dam-diagnostics

Status: implemented first extraction.

`dam-diagnostics` owns shared local readiness checks for user-facing status surfaces. It exists so `damctl doctor` and `dam-web /doctor` do not invent separate interpretations of whether DAM is ready to protect local AI traffic.

## Responsibilities

`config_report` emits a side-effect-free `dam-api::HealthReport` for config shape and current implementation compatibility.

`doctor_report` emits a fuller `dam-api::HealthReport` for local readiness. It includes:

- config loading state;
- vault, consent, and log backend compatibility;
- failure-mode strictness and reduced-protection warnings;
- SQLite runtime open checks for local vault, consent, and log stores;
- router target/provider/auth/failure-mode decisions;
- proxy runtime `/health` reachability when proxy is enabled;
- a read-only setup plan summary for the default local proxy/interception path;
- enabled integration profile selection for route scoping.

`setup_plan` emits a side-effect-free setup checklist for the local "connect" UX. It evaluates:

- startup choice readiness for platform setup flows that need the app to return after reboot;
- system-proxy routing readiness when requested;
- platform `tun` routing readiness when requested:
  macOS emits System Extension approval, reboot, Network Extension manager configuration, manager enablement, and manager connection as separate steps;
  Linux emits a Linux transparent routing step and currently blocks to explicit proxy mode until that backend lands;
  Windows emits a Windows Filtering Platform step and currently blocks to explicit proxy mode until that backend lands;
- local CA trust readiness when requested;
- daemon lifecycle readiness for the requested network/trust modes.

The plan states are:

- `ready`: no setup action is needed.
- `needs_action`: DAM can continue after the listed next command or user confirmation.
- `blocked`: setup needs review before the local connect flow should continue.

Each setup step reports `kind`, `status`, `message`, optional `command`, `requires_confirmation`, and `changes_system`. Step messages are English diagnostic/support text; UI surfaces map stable step ids to localized English and French labels.

## Boundaries

The crate does not:

- start or stop `dam-proxy`;
- mutate policy, vault entries, log entries, or consent grants;
- call real model providers;
- inspect request bodies;
- own CLI or HTML rendering.

Those concerns stay in `damctl`, `dam-web`, `dam-proxy`, and future daemon/integration modules.

`damctl doctor` may add CLI-local integration profile summaries after consuming `doctor_report`. Those summaries use `dam-integrations` inspection data and are not currently part of the shared web `/doctor` report. The CLI can pass a non-default state directory so tests and support sessions do not accidentally read the live user daemon/integration state.

## Current Consumers

- `damctl config check`
- `damctl doctor`
- `damctl setup plan`
- `dam-web /doctor`

## Testing

Run:

```bash
cargo test -p dam-diagnostics
```
