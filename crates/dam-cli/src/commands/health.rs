use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn probe(path: &str, port: u16) -> Result<u16> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(status)
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
