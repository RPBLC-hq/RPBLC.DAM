use std::convert::Infallible;
use std::sync::Arc;

use axum::body::Body;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
                    tracing::debug!(error = %e, host = %host, "tunnel ended");
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

    // WebSocket upgrade: relay directly, skip DAM pipeline
    let is_ws = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    if is_ws {
        tracing::debug!(url = %upstream_url, "WebSocket relay");
        return relay_websocket(req, host, port, &headers, &path).await;
    }

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

/// Connect to upstream host via TLS using system root certificates.
async fn connect_upstream_tls(
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>>
{
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let tcp = TcpStream::connect(format!("{host}:{port}")).await?;
    Ok(connector.connect(server_name, tcp).await?)
}

/// Relay a WebSocket upgrade to the real upstream without DAM pipeline processing.
async fn relay_websocket(
    req: Request<hyper::body::Incoming>,
    host: &str,
    port: u16,
    headers: &axum::http::HeaderMap,
    path: &str,
) -> Result<hyper::Response<Body>, Infallible> {
    // Connect to real upstream via TLS
    let upstream_tls = match connect_upstream_tls(host, port).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, host = %host, "WS: upstream TLS failed");
            return Ok(hyper::Response::builder()
                .status(502)
                .body(Body::from(format!("WebSocket upstream failed: {e}")))
                .unwrap());
        }
    };

    // Reconstruct raw HTTP upgrade request
    let mut raw_req = format!("GET {path} HTTP/1.1\r\n");
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            raw_req.push_str(&format!("{}: {v}\r\n", name.as_str()));
        }
    }
    if !headers.contains_key("host") {
        raw_req.push_str(&format!("Host: {host}\r\n"));
    }
    raw_req.push_str("\r\n");

    // Send upgrade request to upstream, read response
    let (mut ur, mut uw) = tokio::io::split(upstream_tls);
    if let Err(e) = uw.write_all(raw_req.as_bytes()).await {
        return Ok(hyper::Response::builder()
            .status(502)
            .body(Body::from(format!("WS write failed: {e}")))
            .unwrap());
    }

    let mut buf = vec![0u8; 8192];
    let n = match ur.read(&mut buf).await {
        Ok(0) => {
            return Ok(hyper::Response::builder()
                .status(502)
                .body(Body::from("WS: upstream closed"))
                .unwrap())
        }
        Ok(n) => n,
        Err(e) => {
            return Ok(hyper::Response::builder()
                .status(502)
                .body(Body::from(format!("WS read failed: {e}")))
                .unwrap())
        }
    };

    let resp_str = String::from_utf8_lossy(&buf[..n]);

    // Parse status code from HTTP response line
    let status_code = resp_str
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    if status_code != 101 {
        tracing::debug!(status = status_code, "WS: upgrade rejected by upstream");
        return Ok(hyper::Response::builder()
            .status(status_code)
            .body(Body::from("WebSocket upgrade rejected"))
            .unwrap());
    }

    // Parse response headers from upstream's 101
    let mut resp_builder = hyper::Response::builder().status(101);
    for line in resp_str.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            resp_builder = resp_builder.header(name.trim(), value.trim());
        }
    }

    // Any bytes after headers are the start of WebSocket frames
    let header_end = buf[..n]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(n);
    let extra_data: Vec<u8> = buf[header_end..n].to_vec();

    // Spawn bidirectional relay
    let host_owned = host.to_string();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                // Forward any extra bytes from the response buffer
                if !extra_data.is_empty() {
                    let _ = client.write_all(&extra_data).await;
                }
                let mut upstream = ur.unsplit(uw);
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                tracing::debug!(host = %host_owned, "WS relay ended");
            }
            Err(e) => tracing::debug!(error = %e, "WS client upgrade failed"),
        }
    });

    Ok(resp_builder.body(Body::empty()).unwrap())
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
