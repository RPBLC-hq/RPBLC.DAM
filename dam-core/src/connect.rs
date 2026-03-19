use std::convert::Infallible;
use std::sync::Arc;

use axum::body::Body;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::destination::Destination;
use crate::proxy::ProxyState;

/// Handle a CONNECT request. Spawns a task for the tunnel, returns 200 immediately.
pub(crate) async fn handle_connect(
    req: Request<hyper::body::Incoming>,
    state: &ProxyState,
) -> Result<hyper::Response<Body>, Infallible> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let (host, port) = parse_host_port(&authority);

    tracing::debug!(host = %host, port = port, "CONNECT");

    let state = state.clone();

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = handle_tunnel(upgraded, &host, port, &state).await {
                    tracing::error!(error = %e, host = %host, "tunnel error");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "CONNECT upgrade failed");
            }
        }
    });

    Ok(hyper::Response::new(Body::empty()))
}

async fn handle_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: u16,
    state: &ProxyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let should_intercept = state.tls.is_some() && Destination::from_host(host).is_llm();

    if !should_intercept {
        // Blind tunnel: bidirectional byte forwarding, no inspection
        let mut client = TokioIo::new(upgraded);
        let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        return Ok(());
    }

    let tls = state.tls.as_ref().unwrap();
    let intercept_cert = tls.get_cert(host)?;

    // Build TLS server config with the generated cert for this host
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        intercept_cert.cert_chain.clone(),
        intercept_cert.key_der.clone_key(),
    )?;

    // TLS handshake with client (DAM presents as the target host)
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let client_io = TokioIo::new(upgraded);
    let tls_stream = match acceptor.accept(client_io).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                host = %host,
                "TLS handshake failed — is the CA trusted? Run: dam trust"
            );
            return Err(e.into());
        }
    };

    tracing::debug!(host = %host, "TLS intercepting");

    // Run an HTTP/1.1 server on the decrypted stream.
    // Each request inside the tunnel gets the full DAM pipeline.
    let hyper_io = TokioIo::new(tls_stream);
    let host = host.to_string();
    let state = state.clone();

    http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(
            hyper_io,
            service_fn(move |req: Request<hyper::body::Incoming>| {
                let host = host.clone();
                let state = state.clone();
                async move { handle_intercepted_request(req, &host, port, &state).await }
            }),
        )
        .with_upgrades()
        .await?;

    Ok(())
}

/// Process a single HTTP request from inside an intercepted TLS tunnel.
async fn handle_intercepted_request(
    req: Request<hyper::body::Incoming>,
    host: &str,
    port: u16,
    state: &ProxyState,
) -> Result<hyper::Response<Body>, Infallible> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = req.headers().clone();

    let upstream_url = if port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{port}{path}")
    };

    // Read the request body
    let body_bytes = match http_body_util::BodyExt::collect(req.into_body()).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return Ok(hyper::Response::builder()
                .status(502)
                .body(Body::from(format!("Failed to read request: {e}")))
                .unwrap());
        }
    };

    tracing::debug!(method = %method, url = %upstream_url, body_len = body_bytes.len(), "intercepted");

    // Delegate to the shared proxy pipeline
    Ok(crate::proxy::process_request(state, method, &upstream_url, &headers, body_bytes).await)
}

fn parse_host_port(authority: &str) -> (String, u16) {
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (authority.to_string(), 443)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = parse_host_port("api.openai.com:443");
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_custom() {
        let (host, port) = parse_host_port("example.com:8443");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_host_port_no_port() {
        let (host, port) = parse_host_port("api.anthropic.com");
        assert_eq!(host, "api.anthropic.com");
        assert_eq!(port, 443);
    }
}
