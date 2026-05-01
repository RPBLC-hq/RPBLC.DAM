use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInterceptionReadiness {
    NotTransparentMode,
    NeedsRouting,
    NeedsUserConsent,
    NeedsTrust,
    NeedsAdapter,
    Ready,
}

impl TlsInterceptionReadiness {
    pub fn tag(self) -> &'static str {
        match self {
            Self::NotTransparentMode => "not_transparent_mode",
            Self::NeedsRouting => "needs_routing",
            Self::NeedsUserConsent => "needs_user_consent",
            Self::NeedsTrust => "needs_trust",
            Self::NeedsAdapter => "needs_adapter",
            Self::Ready => "ready",
        }
    }
}

impl fmt::Display for TlsInterceptionReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTlsInterceptionReadiness {
    pub route: dam_net::AiRoute,
    pub protocol: dam_net::TrafficProtocol,
    pub network_mode: dam_net::CaptureMode,
    pub routing_readiness: dam_net::RouteCaptureReadiness,
    pub trust_readiness: dam_trust::TlsInterceptionReadiness,
    pub user_consented: bool,
    pub adapter_available: bool,
    pub readiness: TlsInterceptionReadiness,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInterceptionActivationState {
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInterceptionActivation {
    pub state: TlsInterceptionActivationState,
    pub route: dam_net::AiRoute,
    pub network_mode: dam_net::CaptureMode,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsInterceptionError {
    #[error("TLS interception is not ready for {target}: {reason}")]
    NotReady { target: String, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsInterceptionAdapter {
    adapter_available: bool,
}

impl TlsInterceptionAdapter {
    pub fn new(adapter_available: bool) -> Self {
        Self { adapter_available }
    }

    pub fn unavailable() -> Self {
        Self::new(false)
    }

    pub fn adapter_available(self) -> bool {
        self.adapter_available
    }

    pub fn activate(
        self,
        readiness: &RouteTlsInterceptionReadiness,
    ) -> Result<TlsInterceptionActivation, TlsInterceptionError> {
        if !self.adapter_available {
            return Err(TlsInterceptionError::NotReady {
                target: readiness.route.target_name.clone(),
                reason: "TLS interception adapter runtime is not available".to_string(),
            });
        }
        if readiness.readiness != TlsInterceptionReadiness::Ready {
            return Err(TlsInterceptionError::NotReady {
                target: readiness.route.target_name.clone(),
                reason: readiness.message.clone(),
            });
        }

        Ok(TlsInterceptionActivation {
            state: TlsInterceptionActivationState::Active,
            route: readiness.route.clone(),
            network_mode: readiness.network_mode,
            message: format!(
                "TLS interception adapter active for {}",
                readiness.route.target_name
            ),
        })
    }
}

pub fn readiness_for_known_ai_routes(
    network_mode: dam_net::CaptureMode,
    system_proxy_active: bool,
    tun_active: bool,
    trust: &dam_trust::TrustState,
    user_consented: bool,
    adapter: TlsInterceptionAdapter,
) -> Vec<RouteTlsInterceptionReadiness> {
    readiness_for_ai_routes(
        &dam_net::known_ai_routes(),
        network_mode,
        system_proxy_active,
        tun_active,
        trust,
        user_consented,
        adapter,
    )
}

pub fn readiness_for_ai_routes(
    routes: &[dam_net::AiRoute],
    network_mode: dam_net::CaptureMode,
    system_proxy_active: bool,
    tun_active: bool,
    trust: &dam_trust::TrustState,
    user_consented: bool,
    adapter: TlsInterceptionAdapter,
) -> Vec<RouteTlsInterceptionReadiness> {
    let routing = dam_net::transparent_capture_readiness_for_ai_routes(
        routes,
        network_mode,
        system_proxy_active,
        tun_active,
    );
    let trust = dam_trust::readiness_for_ai_routes(routes, trust, user_consented);

    routing
        .iter()
        .zip(trust.iter())
        .map(|(routing, trust)| readiness_for_route(routing, trust, user_consented, adapter))
        .collect()
}

pub fn readiness_for_route(
    routing: &dam_net::TransparentRouteCaptureReadiness,
    trust: &dam_trust::RouteTrustReadiness,
    user_consented: bool,
    adapter: TlsInterceptionAdapter,
) -> RouteTlsInterceptionReadiness {
    let (readiness, message) =
        if routing.readiness == dam_net::RouteCaptureReadiness::NotTransparentMode {
            (
                TlsInterceptionReadiness::NotTransparentMode,
                "transparent interception is inactive in explicit proxy mode".to_string(),
            )
        } else if routing.readiness != dam_net::RouteCaptureReadiness::Ready {
            (
                TlsInterceptionReadiness::NeedsRouting,
                routing.message.clone(),
            )
        } else if !user_consented {
            (
                TlsInterceptionReadiness::NeedsUserConsent,
                "TLS interception requires explicit user approval".to_string(),
            )
        } else if trust.readiness != dam_trust::TlsInterceptionReadiness::Ready {
            (TlsInterceptionReadiness::NeedsTrust, trust.message.clone())
        } else if !adapter.adapter_available() {
            (
                TlsInterceptionReadiness::NeedsAdapter,
                "TLS interception adapter runtime is not available".to_string(),
            )
        } else {
            (
                TlsInterceptionReadiness::Ready,
                format!(
                    "{} traffic is ready for guarded TLS interception",
                    routing.route.target_name
                ),
            )
        };

    RouteTlsInterceptionReadiness {
        route: routing.route.clone(),
        protocol: routing.protocol,
        network_mode: routing.mode,
        routing_readiness: routing.readiness,
        trust_readiness: trust.readiness,
        user_consented,
        adapter_available: adapter.adapter_available(),
        readiness,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed_trust_state() -> dam_trust::TrustState {
        dam_trust::TrustState {
            mode: dam_trust::TrustMode::LocalCa,
            local_ca: Some(dam_trust::LocalCaRecord {
                id: "dam-local-ca-test".to_string(),
                label: "DAM Local CA".to_string(),
                fingerprint_sha256: "a".repeat(64),
                fingerprint_sha1: Some("b".repeat(40)),
                created_at_unix: 1,
                installed_at_unix: Some(2),
            }),
            ..dam_trust::TrustState::default()
        }
    }

    #[test]
    fn explicit_proxy_does_not_activate_transparent_interception() {
        let readiness = readiness_for_known_ai_routes(
            dam_net::CaptureMode::ExplicitProxy,
            false,
            false,
            &installed_trust_state(),
            true,
            TlsInterceptionAdapter::new(true),
        );

        assert!(
            readiness
                .iter()
                .all(|route| route.readiness == TlsInterceptionReadiness::NotTransparentMode)
        );
        assert!(
            TlsInterceptionAdapter::new(true)
                .activate(&readiness[0])
                .is_err()
        );
    }

    #[test]
    fn routing_is_required_before_trust_or_adapter_activation() {
        let readiness = readiness_for_known_ai_routes(
            dam_net::CaptureMode::SystemProxy,
            false,
            false,
            &installed_trust_state(),
            true,
            TlsInterceptionAdapter::new(true),
        );

        assert!(
            readiness
                .iter()
                .all(|route| route.readiness == TlsInterceptionReadiness::NeedsRouting)
        );
    }

    #[test]
    fn consent_and_trust_gate_adapter_activation_after_routing() {
        let no_consent = readiness_for_known_ai_routes(
            dam_net::CaptureMode::SystemProxy,
            true,
            false,
            &installed_trust_state(),
            false,
            TlsInterceptionAdapter::new(true),
        );
        let no_trust = readiness_for_known_ai_routes(
            dam_net::CaptureMode::SystemProxy,
            true,
            false,
            &dam_trust::TrustState {
                mode: dam_trust::TrustMode::LocalCa,
                ..dam_trust::TrustState::default()
            },
            true,
            TlsInterceptionAdapter::new(true),
        );

        assert_eq!(
            no_consent[0].readiness,
            TlsInterceptionReadiness::NeedsUserConsent
        );
        assert_eq!(no_trust[0].readiness, TlsInterceptionReadiness::NeedsTrust);
    }

    #[test]
    fn adapter_only_activates_when_every_gate_is_ready() {
        let adapter = TlsInterceptionAdapter::new(true);
        let readiness = readiness_for_known_ai_routes(
            dam_net::CaptureMode::SystemProxy,
            true,
            false,
            &installed_trust_state(),
            true,
            adapter,
        );

        assert!(
            readiness
                .iter()
                .all(|route| route.readiness == TlsInterceptionReadiness::Ready)
        );
        let activation = adapter.activate(&readiness[0]).unwrap();
        assert_eq!(activation.state, TlsInterceptionActivationState::Active);
    }

    #[test]
    fn unavailable_adapter_stays_inactive_even_after_prerequisites() {
        let readiness = readiness_for_known_ai_routes(
            dam_net::CaptureMode::Tun,
            false,
            true,
            &installed_trust_state(),
            true,
            TlsInterceptionAdapter::unavailable(),
        );

        assert_eq!(
            readiness[0].readiness,
            TlsInterceptionReadiness::NeedsAdapter
        );
    }

    #[test]
    fn unavailable_adapter_handle_cannot_activate_stale_ready_readiness() {
        let ready_adapter = TlsInterceptionAdapter::new(true);
        let readiness = readiness_for_known_ai_routes(
            dam_net::CaptureMode::SystemProxy,
            true,
            false,
            &installed_trust_state(),
            true,
            ready_adapter,
        );

        assert_eq!(readiness[0].readiness, TlsInterceptionReadiness::Ready);
        assert!(
            TlsInterceptionAdapter::unavailable()
                .activate(&readiness[0])
                .is_err()
        );
    }
}
