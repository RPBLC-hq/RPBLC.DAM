use anyhow::{Context, Result};
use clap::Subcommand;
use dam_core::config::DamConfig;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum DaemonAction {
    /// Register DAM as an OS service and start it
    Install {
        /// Port to listen on
        #[arg(long, default_value = "7828")]
        port: u16,
    },
    /// Stop and remove the OS service
    Uninstall,
    /// Start the registered service
    Start,
    /// Stop the running service
    Stop,
    /// Show service status
    Status,
}

pub async fn run(action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Install { port } => install(port).await,
        DaemonAction::Uninstall => uninstall().await,
        DaemonAction::Start => start().await,
        DaemonAction::Stop => stop().await,
        DaemonAction::Status => status().await,
    }
}

use super::read_pid;

/// Resolve the path to the current `dam` binary.
fn dam_exe_path() -> Result<PathBuf> {
    std::env::current_exe().context("could not determine dam binary path")
}

/// Check whether a process with the given PID is running.
fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Check /proc/<pid> existence on Linux, fall back to `kill -0` via command
        let proc_path = format!("/proc/{pid}");
        if std::path::Path::new(&proc_path).exists() {
            return true;
        }
        // macOS doesn't have /proc — use kill -0
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains(&pid.to_string())
            })
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Poll /healthz until it returns 200 or timeout.
async fn wait_for_healthy(port: u16, timeout_secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(status) = probe_health(port).await
            && status == 200
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    false
}

/// Quick TCP health probe matching health.rs approach.
async fn probe_health(port: u16) -> Result<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let req = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
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

// ─── Platform: Linux (systemd) ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::process::Command;

    const SERVICE_NAME: &str = "dam";

    fn service_file_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("systemd/user/dam.service")
    }

    pub fn generate_unit(exe: &str, port: u16) -> String {
        format!(
            "[Unit]\n\
             Description=DAM — PII firewall for AI agents\n\
             After=default.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe} serve --port {port}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             # Override with: systemctl --user edit dam → [Service] Environment=RUST_LOG=debug\n\
             Environment=RUST_LOG=warn\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        )
    }

    pub fn install(exe: &str, port: u16) -> Result<()> {
        let path = service_file_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let unit = generate_unit(exe, port);
        std::fs::write(&path, unit)?;
        eprintln!("  Wrote {}", path.display());

        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", SERVICE_NAME])?;
        systemctl(&["start", SERVICE_NAME])?;

        // Check linger
        let user = std::env::var("USER").unwrap_or_default();
        if !user.is_empty() {
            let linger_path = format!("/var/lib/systemd/linger/{user}");
            if !std::path::Path::new(&linger_path).exists() {
                eprintln!();
                eprintln!("  Warning: linger not enabled. The service may not start on boot.");
                eprintln!("  Run: loginctl enable-linger {user}");
            }
        }

        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let _ = systemctl(&["stop", SERVICE_NAME]);
        let _ = systemctl(&["disable", SERVICE_NAME]);
        let path = service_file_path();
        if path.exists() {
            std::fs::remove_file(&path)?;
            eprintln!("  Removed {}", path.display());
        }
        systemctl(&["daemon-reload"])?;
        Ok(())
    }

    pub fn start() -> Result<()> {
        systemctl(&["start", SERVICE_NAME])
    }

    pub fn stop() -> Result<()> {
        systemctl(&["stop", SERVICE_NAME])
    }

    pub fn is_installed() -> bool {
        service_file_path().exists()
    }

    pub fn service_pid() -> Option<u32> {
        Command::new("systemctl")
            .args(["--user", "show", SERVICE_NAME, "-p", "MainPID", "--value"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                let pid: u32 = s.trim().parse().ok()?;
                if pid > 0 { Some(pid) } else { None }
            })
    }

    pub fn is_active() -> bool {
        Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", SERVICE_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn systemctl(args: &[&str]) -> Result<()> {
        let mut cmd_args = vec!["--user"];
        cmd_args.extend_from_slice(args);
        let status = Command::new("systemctl").args(&cmd_args).status()?;
        if !status.success() {
            anyhow::bail!("systemctl {} failed", args.join(" "));
        }
        Ok(())
    }
}

// ─── Platform: macOS (launchd) ───────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::process::Command;

    const LABEL: &str = "dev.rpblc.dam";

    fn plist_path() -> PathBuf {
        dirs::home_dir()
            .expect("Failed to determine home directory for launchd plist")
            .join("Library/LaunchAgents/dev.rpblc.dam.plist")
    }

    pub fn generate_plist(exe: &str, port: u16) -> String {
        let home = DamConfig::default_home();
        let stdout_log = home.join("dam.stdout.log");
        let stderr_log = home.join("dam.stderr.log");
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>serve</string>
        <string>--port</string>
        <string>{port}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>
"#,
            stdout = stdout_log.display(),
            stderr = stderr_log.display(),
        )
    }

    pub fn install(exe: &str, port: u16) -> Result<()> {
        let path = plist_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let plist = generate_plist(exe, port);
        std::fs::write(&path, plist)?;
        eprintln!("  Wrote {}", path.display());

        let status = Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&path)
            .status()?;
        if !status.success() {
            anyhow::bail!(
                "launchctl load failed — check the plist at {}",
                path.display()
            );
        }
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let path = plist_path();
        if path.exists() {
            let _ = Command::new("launchctl").arg("unload").arg(&path).status();
            std::fs::remove_file(&path)?;
            eprintln!("  Removed {}", path.display());
        }
        Ok(())
    }

    pub fn start() -> Result<()> {
        let status = Command::new("launchctl").args(["start", LABEL]).status()?;
        if !status.success() {
            anyhow::bail!("launchctl start failed");
        }
        Ok(())
    }

    pub fn stop() -> Result<()> {
        let status = Command::new("launchctl").args(["stop", LABEL]).status()?;
        if !status.success() {
            anyhow::bail!("launchctl stop failed");
        }
        Ok(())
    }

    pub fn is_installed() -> bool {
        plist_path().exists()
    }

    pub fn service_pid() -> Option<u32> {
        let output = Command::new("launchctl")
            .args(["list", LABEL])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        // First line of `launchctl list <label>` output: PID\tStatus\tLabel
        // or the PID column in the table
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(LABEL) {
                // Format: "PID\tStatus\tLabel" or "-\tStatus\tLabel"
                let pid_str = line.split('\t').next()?;
                if pid_str != "-" {
                    return pid_str.trim().parse().ok();
                }
            }
        }
        // Also check PID key from detailed output
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("\"PID\"") || trimmed.starts_with("PID") {
                // "PID" = 12345;
                return trimmed
                    .split('=')
                    .nth(1)
                    .and_then(|s| s.trim().trim_end_matches(';').trim().parse().ok());
            }
        }
        None
    }

    pub fn is_active() -> bool {
        service_pid().is_some()
    }
}

// ─── Platform: Windows (Registry Run key + detached process) ─────────────────

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use crate::commands::pid_file_path;
    use std::process::Command;

    const REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const REG_VALUE: &str = "DAM";

    pub fn install(exe: &str, port: u16) -> Result<()> {
        // Add to registry for auto-start on login
        let cmd_line = format!("\"{exe}\" serve --port {port}");
        let status = Command::new("reg")
            .args([
                "add", REG_KEY, "/v", REG_VALUE, "/t", "REG_SZ", "/d", &cmd_line, "/f",
            ])
            .status()?;
        if !status.success() {
            anyhow::bail!("failed to add registry entry");
        }
        eprintln!("  Registered auto-start in {REG_KEY}");

        // Spawn detached process
        spawn_detached(exe, port)?;
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        // Stop running instance
        let _ = stop_process();

        // Remove registry entry
        let _ = Command::new("reg")
            .args(["delete", REG_KEY, "/v", REG_VALUE, "/f"])
            .status();
        eprintln!("  Removed auto-start from registry");
        Ok(())
    }

    pub fn start() -> Result<()> {
        // Prefer current_exe (we are the same binary), fall back to registry
        let exe = std::env::current_exe()
            .ok()
            .map(|p| p.display().to_string())
            .or_else(read_exe_from_registry)
            .unwrap_or_else(|| "dam".to_string());
        let port = read_port_from_registry().unwrap_or_else(|| {
            eprintln!("  Warning: could not read port from registry, using default 7828");
            7828
        });
        spawn_detached(&exe, port)
    }

    pub fn stop() -> Result<()> {
        stop_process()
    }

    pub fn is_installed() -> bool {
        Command::new("reg")
            .args(["query", REG_KEY, "/v", REG_VALUE])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn service_pid() -> Option<u32> {
        read_pid()
    }

    pub fn is_active() -> bool {
        read_pid().map(is_process_running).unwrap_or(false)
    }

    fn spawn_detached(exe: &str, port: u16) -> Result<()> {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        Command::new(exe)
            .args(["serve", "--port", &port.to_string()])
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .context("failed to spawn detached dam process")?;

        // Wait briefly for the child to write its PID file so that
        // subsequent status checks can find it immediately.
        for _ in 0..10 {
            if pid_file_path().exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        Ok(())
    }

    /// Check whether the given PID belongs to a dam process.
    fn is_dam_process(pid: u32) -> bool {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                // CSV output: "dam.exe","<pid>",... — verify it's actually dam
                stdout.contains("dam.exe") || stdout.contains("dam\"")
            })
            .unwrap_or(false)
    }

    fn stop_process() -> Result<()> {
        if let Some(pid) = read_pid() {
            if !is_dam_process(pid) {
                eprintln!("  PID {pid} is not a dam process (stale PID file). Cleaning up.");
                let _ = std::fs::remove_file(pid_file_path());
                return Ok(());
            }
            let status = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .status()?;
            if !status.success() {
                anyhow::bail!("taskkill failed for PID {pid}");
            }
            // Clean up PID file
            let _ = std::fs::remove_file(pid_file_path());
        } else {
            eprintln!("  No PID file found; service may not be running.");
        }
        Ok(())
    }

    /// Parse the registry value from `reg query` output.
    /// Format: `    DAM    REG_SZ    "C:\path\dam.exe" serve --port 7828`
    /// Whitespace between fields is variable (spaces or tabs).
    fn read_reg_value() -> Option<String> {
        let output = Command::new("reg")
            .args(["query", REG_KEY, "/v", REG_VALUE])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Find the line containing "REG_SZ" — that's the data line
            if let Some(pos) = line.find("REG_SZ") {
                let after = &line[pos + "REG_SZ".len()..];
                return Some(after.trim().to_string());
            }
        }
        None
    }

    fn read_exe_from_registry() -> Option<String> {
        let val = read_reg_value()?;
        // Value is: "C:\path\dam.exe" serve --port 7828
        if val.starts_with('"') {
            val.strip_prefix('"')
                .and_then(|s| s.split('"').next())
                .map(String::from)
        } else {
            val.split_whitespace().next().map(String::from)
        }
    }

    fn read_port_from_registry() -> Option<u16> {
        let val = read_reg_value()?;
        // Handle quoted exe paths: "C:\Program Files\dam.exe" serve --port 7828
        // Skip past the closing quote to get the arguments portion.
        let args_portion = if let Some(after_open) = val.strip_prefix('"') {
            match after_open.find('"') {
                Some(close) => &after_open[close + 1..],
                None => val.as_str(),
            }
        } else {
            val.as_str()
        };
        let parts: Vec<&str> = args_portion.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if part == &"--port" {
                return parts.get(i + 1).and_then(|s| s.parse().ok());
            }
        }
        None
    }
}

// ─── Unsupported platform stub ───────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::*;

    pub fn install(_exe: &str, _port: u16) -> Result<()> {
        anyhow::bail!("daemon management is not supported on this platform")
    }
    pub fn uninstall() -> Result<()> {
        anyhow::bail!("daemon management is not supported on this platform")
    }
    pub fn start() -> Result<()> {
        anyhow::bail!("daemon management is not supported on this platform")
    }
    pub fn stop() -> Result<()> {
        anyhow::bail!("daemon management is not supported on this platform")
    }
    pub fn is_installed() -> bool {
        false
    }
    pub fn service_pid() -> Option<u32> {
        None
    }
    pub fn is_active() -> bool {
        false
    }
}

// ─── Top-level command implementations ───────────────────────────────────────

async fn install(port: u16) -> Result<()> {
    let exe = dam_exe_path()?;
    let exe_str = exe.display().to_string();

    // Ensure config exists and persist the port so `daemon status` reads the right value
    let (mut config, _) = super::load_config_auto_init()?;
    if config.server.http_port != port {
        config.server.http_port = port;
        let config_path = DamConfig::default_config_path();
        config.save(&config_path)?;
    }

    eprintln!("Installing DAM daemon...");
    platform::install(&exe_str, port)?;

    // Verify health
    eprintln!();
    eprint!("  Waiting for health check...");
    if wait_for_healthy(port, 5).await {
        eprintln!(" ok");
        eprintln!();
        eprintln!("DAM daemon installed and running on port {port}.");
        eprintln!();
        eprintln!("  Set your API base URL:");
        eprintln!("    export OPENAI_BASE_URL=http://127.0.0.1:{port}/v1");
        eprintln!("    export ANTHROPIC_BASE_URL=http://127.0.0.1:{port}");
    } else {
        eprintln!(" failed");
        eprintln!();
        eprintln!("Service was registered but health check did not pass.");
        eprintln!("Check logs with `dam daemon status` or run `dam serve` manually to debug.");
    }

    Ok(())
}

async fn uninstall() -> Result<()> {
    eprintln!("Uninstalling DAM daemon...");
    platform::uninstall()?;
    eprintln!("DAM daemon uninstalled.");
    Ok(())
}

async fn start() -> Result<()> {
    eprintln!("Starting DAM daemon...");
    platform::start()?;
    eprintln!("DAM daemon started.");
    Ok(())
}

async fn stop() -> Result<()> {
    eprintln!("Stopping DAM daemon...");
    platform::stop()?;
    eprintln!("DAM daemon stopped.");
    Ok(())
}

async fn status() -> Result<()> {
    let installed = platform::is_installed();
    let pid = if installed {
        platform::service_pid().or_else(read_pid)
    } else {
        read_pid()
    };
    let running = if installed {
        platform::is_active() || pid.map(is_process_running).unwrap_or(false)
    } else {
        pid.map(is_process_running).unwrap_or(false)
    };

    // Try to detect port from config
    let port = super::load_config()
        .map(|c| c.server.http_port)
        .unwrap_or(7828);

    let health = if running {
        match probe_health(port).await {
            Ok(200) => "ok",
            Ok(_) => "unhealthy",
            Err(_) => "unreachable",
        }
    } else {
        "n/a"
    };

    eprintln!("DAM daemon:");
    eprintln!("  Installed:  {}", if installed { "yes" } else { "no" });
    if running {
        if let Some(p) = pid {
            eprintln!("  Running:    yes (PID {p})");
        } else {
            eprintln!("  Running:    yes");
        }
    } else {
        eprintln!("  Running:    no");
    }
    eprintln!("  Port:       {port}");
    eprintln!("  Health:     {health}");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn generate_systemd_unit() {
        #[cfg(target_os = "linux")]
        {
            let unit = super::platform::generate_unit("/usr/local/bin/dam", 7828);
            assert!(unit.contains("ExecStart=/usr/local/bin/dam serve --port 7828"));
            assert!(unit.contains("Restart=on-failure"));
            assert!(unit.contains("[Install]"));
        }
    }

    #[test]
    fn generate_launchd_plist() {
        #[cfg(target_os = "macos")]
        {
            let plist = super::platform::generate_plist("/usr/local/bin/dam", 7828);
            assert!(plist.contains("<string>/usr/local/bin/dam</string>"));
            assert!(plist.contains("<string>7828</string>"));
            assert!(plist.contains("dev.rpblc.dam"));
            assert!(plist.contains("KeepAlive"));
        }
    }
}
