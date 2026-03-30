use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn parse_status_code(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

async fn probe(path: &str, port: u16) -> Result<u16> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    Ok(parse_status_code(&text))
}

pub async fn run(port: u16, json: bool) -> Result<()> {
    let healthz = probe("/healthz", port).await.unwrap_or(0);
    let readyz = probe("/readyz", port).await.unwrap_or(0);
    let ok = healthz == 200 && readyz == 200;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": ok,
                "port": port,
                "healthz": healthz,
                "readyz": readyz,
            })
        );
    } else {
        println!("healthz: {healthz}");
        println!("readyz: {readyz}");
    }

    if ok {
        Ok(())
    } else {
        anyhow::bail!("health check failed")
    }
}

#[cfg(test)]
mod tests {
    use super::parse_status_code;

    #[test]
    fn parses_valid_status_line() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok";
        assert_eq!(parse_status_code(resp), 200);
    }

    #[test]
    fn returns_zero_on_invalid_response() {
        assert_eq!(parse_status_code("not-http"), 0);
        assert_eq!(parse_status_code("HTTP/1.1 XYZ Nope"), 0);
    }
}
