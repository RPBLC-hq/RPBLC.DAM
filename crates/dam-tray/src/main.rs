use std::{
    env,
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
mod macos_system_extension;

const DEFAULT_WEB_PORT: u16 = 2896;
const DEFAULT_WEB_PORT_MAX: u16 = 2916;
const DEFAULT_MACOS_NE_BUNDLE_ID: &str = "com.rpblc.dam.network-extension";
const DAM_BIN_ENV: &str = "DAM_BIN";
const DAM_WEB_BIN_ENV: &str = "DAM_WEB_BIN";
const DAM_STATE_DIR_ENV: &str = "DAM_STATE_DIR";
const DAM_CONSENT_PATH_ENV: &str = "DAM_CONSENT_PATH";
const DAM_WEB_SHELL_ENV: &str = "DAM_WEB_SHELL";
const DAM_WEB_SHELL_TRAY: &str = "tray";
const DAM_WEB_TRAY_POST_TOKEN_ENV: &str = "DAM_WEB_TRAY_POST_TOKEN";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    addr: Option<String>,
    dam_bin: Option<PathBuf>,
    dam_web_bin: Option<PathBuf>,
    config_path: Option<PathBuf>,
    db_path: Option<PathBuf>,
    log_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DataPaths {
    state_dir: PathBuf,
    vault_path: PathBuf,
    log_path: PathBuf,
    consent_path: PathBuf,
}

fn main() {
    let cli = match parse_args(env::args().skip(1)) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };

    if let Err(error) = run(cli) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn run(cli: CliArgs) -> Result<(), String> {
    macos::run(cli)
}

#[cfg(not(target_os = "macos"))]
fn run(_cli: CliArgs) -> Result<(), String> {
    Err(
        "dam-tray currently ships a macOS native shell first; use `dam-web` for this platform"
            .to_string(),
    )
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<CliArgs, String> {
    let mut cli = CliArgs {
        addr: None,
        dam_bin: None,
        dam_web_bin: None,
        config_path: None,
        db_path: None,
        log_path: None,
    };

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => cli.addr = Some(required_value(&mut args, "--addr")?),
            "--dam-bin" => {
                cli.dam_bin = Some(PathBuf::from(required_value(&mut args, "--dam-bin")?))
            }
            "--dam-web-bin" => {
                cli.dam_web_bin = Some(PathBuf::from(required_value(&mut args, "--dam-web-bin")?))
            }
            "--config" => {
                cli.config_path = Some(PathBuf::from(required_value(&mut args, "--config")?))
            }
            "--db" => cli.db_path = Some(PathBuf::from(required_value(&mut args, "--db")?)),
            "--log" => cli.log_path = Some(PathBuf::from(required_value(&mut args, "--log")?)),
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(cli)
}

fn required_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn usage() -> &'static str {
    "Usage: dam-tray [--addr 127.0.0.1:2896] [--config dam.toml] [--db vault.db] [--log log.db] [--dam-bin /path/to/dam] [--dam-web-bin /path/to/dam-web]"
}

fn choose_web_addr(explicit: Option<&str>) -> Result<String, String> {
    if let Some(addr) = explicit {
        validate_addr(addr)?;
        ensure_addr_available(addr)?;
        return Ok(addr.to_string());
    }

    for port in DEFAULT_WEB_PORT..=DEFAULT_WEB_PORT_MAX {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpListener::bind(addr).is_ok() {
            return Ok(addr.to_string());
        }
    }

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|error| format!("failed to reserve a local web port: {error}"))?;
    listener
        .local_addr()
        .map(|addr| addr.to_string())
        .map_err(|error| format!("failed to read reserved local web port: {error}"))
}

fn validate_addr(addr: &str) -> Result<(), String> {
    let parsed = addr
        .parse::<SocketAddr>()
        .map_err(|_| format!("invalid web address: {addr}"))?;
    if !parsed.ip().is_loopback() {
        return Err(format!("dam-tray web address must be loopback: {addr}"));
    }
    Ok(())
}

fn ensure_addr_available(addr: &str) -> Result<(), String> {
    let parsed = addr
        .parse::<SocketAddr>()
        .map_err(|_| format!("invalid web address: {addr}"))?;
    TcpListener::bind(parsed)
        .map(|_| ())
        .map_err(|error| format!("web address is already in use or unavailable: {addr}: {error}"))
}

fn data_paths(cli: &CliArgs) -> Result<DataPaths, String> {
    let state_dir = state_dir()?;
    Ok(DataPaths {
        vault_path: cli
            .db_path
            .clone()
            .unwrap_or_else(|| state_dir.join("vault.db")),
        log_path: cli
            .log_path
            .clone()
            .unwrap_or_else(|| state_dir.join("log.db")),
        consent_path: state_dir.join("consent.db"),
        state_dir,
    })
}

fn state_dir() -> Result<PathBuf, String> {
    if let Some(value) = env::var_os(DAM_STATE_DIR_ENV)
        && !value.is_empty()
    {
        return Ok(PathBuf::from(value));
    }

    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(".dam"))
        .ok_or_else(|| format!("{DAM_STATE_DIR_ENV} or HOME is required to locate DAM app state"))
}

fn connect_url(addr: &str) -> String {
    format!("http://{addr}/connect")
}

fn sibling_or_path(explicit: Option<PathBuf>, env_name: &str, binary_name: &str) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }
    if let Some(path) = env::var_os(env_name)
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    if let Some(path) = sibling_binary(binary_name)
        && path.is_file()
    {
        return path;
    }
    PathBuf::from(binary_name)
}

fn sibling_binary(binary_name: &str) -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let dir = exe.parent()?;
    #[cfg(windows)]
    let binary_name = format!("{binary_name}.exe");
    Some(dir.join(binary_name))
}

fn wait_for_tcp(addr: &str, timeout: Duration) -> Result<(), String> {
    let addr = addr
        .parse::<SocketAddr>()
        .map_err(|_| format!("invalid web address: {addr}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for dam-web at {addr}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::{
        fs,
        process::{Child, Command, Stdio},
    };

    use tao::{
        dpi::{LogicalSize, PhysicalPosition},
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        platform::macos::{ActivationPolicy, EventLoopExtMacOS, WindowBuilderExtMacOS},
        window::{Window, WindowBuilder},
    };
    use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use wry::{NewWindowResponse, WebViewBuilder};

    const POPOVER_WIDTH: f64 = 430.0;
    const POPOVER_HEIGHT: f64 = 720.0;
    const POPOVER_MARGIN: f64 = 8.0;
    const RPBLC_HOME_URL: &str = "https://rpblc.com";
    const TRAY_OPEN_RPBLC_MESSAGE: &str = "dam-tray:open-rpblc";
    const TRAY_CONNECT_MESSAGE: &str = "dam-tray:connect";
    const TRAY_QUIT_MESSAGE: &str = "dam-tray:quit";

    #[derive(Debug)]
    enum UserEvent {
        TrayIcon(TrayIconEvent),
        OpenRpblc,
        ConnectRequested,
        QuitRequested,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct PhysicalFrame {
        x: f64,
        y: f64,
        width: f64,
        height: f64,
    }

    pub(super) fn run(cli: CliArgs) -> Result<(), String> {
        let addr = choose_web_addr(cli.addr.as_deref())?;
        let url = connect_url(&addr);
        let data_paths = data_paths(&cli)?;
        fs::create_dir_all(&data_paths.state_dir).map_err(|error| {
            format!(
                "failed to create DAM state directory {}: {error}",
                data_paths.state_dir.display()
            )
        })?;

        let dam_bin = sibling_or_path(cli.dam_bin.clone(), DAM_BIN_ENV, "dam");
        let dam_web_bin = sibling_or_path(cli.dam_web_bin.clone(), DAM_WEB_BIN_ENV, "dam-web");
        let tray_post_token = generate_tray_post_token()?;
        let mut web_child = WebChild::spawn(
            &dam_web_bin,
            &dam_bin,
            &addr,
            &data_paths,
            cli.config_path.as_ref(),
            &tray_post_token,
        )?;
        wait_for_tcp(&addr, Duration::from_secs(8))?;

        let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
        event_loop.set_dock_visibility(false);
        let proxy = event_loop.create_proxy();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::TrayIcon(event));
        }));
        let ipc_proxy = event_loop.create_proxy();
        let navigation_authority = addr.clone();
        let ipc_authority = addr.clone();

        let window = WindowBuilder::new()
            .with_title("DAM")
            .with_inner_size(LogicalSize::new(POPOVER_WIDTH, POPOVER_HEIGHT))
            .with_min_inner_size(LogicalSize::new(POPOVER_WIDTH, POPOVER_HEIGHT))
            .with_max_inner_size(LogicalSize::new(POPOVER_WIDTH, POPOVER_HEIGHT))
            .with_resizable(false)
            .with_minimizable(false)
            .with_maximizable(false)
            .with_closable(false)
            .with_visible(false)
            .with_focused(false)
            .with_decorations(false)
            .with_always_on_top(true)
            .with_visible_on_all_workspaces(true)
            .with_has_shadow(true)
            .build(&event_loop)
            .map_err(|error| format!("failed to create DAM window: {error}"))?;

        let webview = WebViewBuilder::new()
            .with_url(&url)
            .with_navigation_handler(move |target| {
                url_has_local_origin(&target, &navigation_authority)
            })
            .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
            .with_ipc_handler(move |request| {
                if !url_has_local_origin(&request.uri().to_string(), &ipc_authority) {
                    return;
                }
                match request.body().trim() {
                    TRAY_OPEN_RPBLC_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::OpenRpblc);
                    }
                    TRAY_CONNECT_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::ConnectRequested);
                    }
                    TRAY_QUIT_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::QuitRequested);
                    }
                    _ => {}
                }
            })
            .build(&window)
            .map_err(|error| format!("failed to create DAM webview: {error}"))?;

        let mut tray_icon = None;
        let dam_bin_for_connect = dam_bin.clone();
        let data_paths_for_connect = data_paths.clone();
        let config_path_for_connect = cli.config_path.clone();
        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;

            match event {
                Event::NewEvents(StartCause::Init) => {
                    if tray_icon.is_none() {
                        match build_tray() {
                            Ok(icon) => {
                                tray_icon = Some(icon);
                            }
                            Err(error) => {
                                eprintln!("{error}");
                                web_child.stop();
                                *control_flow = ControlFlow::Exit;
                            }
                        }
                    }
                }
                Event::UserEvent(UserEvent::TrayIcon(TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                })) => {
                    if let Some(icon) = tray_icon.as_ref() {
                        show_popover(&window, icon);
                    }
                }
                Event::UserEvent(UserEvent::TrayIcon(_)) => {}
                Event::UserEvent(UserEvent::OpenRpblc) => {
                    if let Err(error) = open_in_browser(RPBLC_HOME_URL) {
                        eprintln!("{error}");
                    }
                }
                Event::UserEvent(UserEvent::ConnectRequested) => {
                    let redirect = connect_result_redirect(connect_dam(
                        &dam_bin_for_connect,
                        &data_paths_for_connect,
                        config_path_for_connect.as_ref(),
                    ));
                    let script = format!("window.location.href = {}", js_string_literal(&redirect));
                    if let Err(error) = webview.evaluate_script(&script) {
                        eprintln!("failed to refresh DAM tray view: {error}");
                    }
                }
                Event::UserEvent(UserEvent::QuitRequested) => {
                    web_child.stop();
                    *control_flow = ControlFlow::Exit;
                }
                Event::WindowEvent {
                    event: WindowEvent::Focused(false),
                    ..
                } => {
                    window.set_visible(false);
                }
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                } => {
                    window.set_visible(false);
                }
                _ => {}
            }
        });
    }

    fn connect_result_redirect(result: Result<(), String>) -> String {
        match result {
            Ok(()) => format!(
                "/connect?notice={}",
                form_url_encode_component("DAM connected")
            ),
            Err(error) => {
                eprintln!("{error}");
                let message = connect_error_message(&error);
                format!("/connect?error={}", form_url_encode_component(&message))
            }
        }
    }

    fn connect_error_message(error: &str) -> String {
        approval_instruction(error)
            .map(|message| format!("Action required: {message}"))
            .unwrap_or_else(|| format!("Connect failed: {error}"))
    }

    fn approval_instruction(error: &str) -> Option<&str> {
        if let Some(message) = error.strip_prefix("action required: ") {
            return Some(message);
        }
        error
            .find("approve DAM Network Protection")
            .map(|index| &error[index..])
    }

    fn build_tray() -> Result<tray_icon::TrayIcon, String> {
        TrayIconBuilder::new()
            .with_tooltip("DAM")
            .with_title("[R:]")
            .build()
            .map_err(|error| format!("failed to create tray icon: {error}"))
    }

    fn show_popover(window: &Window, tray_icon: &tray_icon::TrayIcon) {
        position_popover(window, tray_icon.rect());
        window.set_visible(true);
        window.set_focus();
    }

    fn position_popover(window: &Window, tray_rect: Option<tray_icon::Rect>) {
        let monitor = tray_rect
            .and_then(|rect| window.monitor_from_point(rect.position.x, rect.position.y))
            .or_else(|| window.current_monitor())
            .or_else(|| window.primary_monitor());
        let scale = monitor
            .as_ref()
            .map(|monitor| monitor.scale_factor())
            .unwrap_or_else(|| window.scale_factor());
        let monitor_frame = monitor
            .map(|monitor| {
                let position = monitor.position();
                let size = monitor.size();
                PhysicalFrame {
                    x: position.x as f64,
                    y: position.y as f64,
                    width: size.width as f64,
                    height: size.height as f64,
                }
            })
            .unwrap_or(PhysicalFrame {
                x: 0.0,
                y: 0.0,
                width: POPOVER_WIDTH * scale,
                height: POPOVER_HEIGHT * scale,
            });
        let anchor = tray_rect.map(|rect| PhysicalFrame {
            x: rect.position.x,
            y: rect.position.y,
            width: rect.size.width as f64,
            height: rect.size.height as f64,
        });
        let position = popover_origin(
            anchor,
            monitor_frame,
            POPOVER_WIDTH * scale,
            POPOVER_HEIGHT * scale,
            POPOVER_MARGIN * scale,
        );
        window.set_outer_position(position);
    }

    fn popover_origin(
        anchor: Option<PhysicalFrame>,
        monitor: PhysicalFrame,
        popover_width: f64,
        popover_height: f64,
        margin: f64,
    ) -> PhysicalPosition<i32> {
        let anchor_center_x = anchor
            .map(|anchor| anchor.x + (anchor.width / 2.0))
            .unwrap_or(monitor.x + monitor.width - margin - (popover_width / 2.0));
        let anchor_bottom_y = anchor
            .map(|anchor| anchor.y + anchor.height)
            .unwrap_or(monitor.y + margin);
        let min_x = monitor.x + margin;
        let max_x = monitor.x + monitor.width - popover_width - margin;
        let min_y = monitor.y + margin;
        let max_y = monitor.y + monitor.height - popover_height - margin;

        PhysicalPosition::new(
            clamp_to_range(anchor_center_x - (popover_width / 2.0), min_x, max_x).round() as i32,
            clamp_to_range(anchor_bottom_y, min_y, max_y).round() as i32,
        )
    }

    fn clamp_to_range(value: f64, min: f64, max: f64) -> f64 {
        if max < min {
            min
        } else {
            value.clamp(min, max)
        }
    }

    fn open_in_browser(url: &str) -> Result<(), String> {
        let status = Command::new("open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("failed to open {url}: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "failed to open {url}: command exited with {status}"
            ))
        }
    }

    fn connect_dam(
        dam_bin: &PathBuf,
        data_paths: &DataPaths,
        config_path: Option<&PathBuf>,
    ) -> Result<(), String> {
        activate_system_extension_from_app()?;
        run_dam_command(
            dam_bin,
            data_paths,
            &network_install_args(config_path),
            "install Network Extension routing",
        )?;
        run_dam_command(
            dam_bin,
            data_paths,
            &[
                "trust".to_string(),
                "install-local-ca".to_string(),
                "--yes".to_string(),
            ],
            "install local trust",
        )?;
        let has_active_profile = enabled_profile_selected(dam_bin, data_paths)?;
        run_dam_command(
            dam_bin,
            data_paths,
            &connect_args(data_paths, config_path, has_active_profile),
            "connect DAM",
        )
    }

    fn activate_system_extension_from_app() -> Result<(), String> {
        let bundle_identifier = env::var("DAM_MACOS_NE_BUNDLE_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_MACOS_NE_BUNDLE_ID.to_string());
        match crate::macos_system_extension::activate(&bundle_identifier, Duration::from_secs(20)) {
            Ok(crate::macos_system_extension::ActivationOutcome::Ready(_)) => Ok(()),
            Ok(crate::macos_system_extension::ActivationOutcome::NeedsApproval(message)) => {
                Err(format!("action required: {message}"))
            }
            Err(error) => Err(format!("activate DAM Network Protection: {error}")),
        }
    }

    fn network_install_args(config_path: Option<&PathBuf>) -> Vec<String> {
        let mut args = vec![
            "network".to_string(),
            "install-network-extension".to_string(),
            "--yes".to_string(),
        ];
        if let Some(config_path) = config_path {
            args.extend(["--config".to_string(), config_path.display().to_string()]);
        }
        args
    }

    fn connect_args(
        data_paths: &DataPaths,
        config_path: Option<&PathBuf>,
        has_active_profile: bool,
    ) -> Vec<String> {
        let mut args = vec!["connect".to_string()];
        if has_active_profile {
            args.push("--apply".to_string());
        }
        if let Some(config_path) = config_path {
            args.extend(["--config".to_string(), config_path.display().to_string()]);
        }
        args.extend([
            "--db".to_string(),
            data_paths.vault_path.display().to_string(),
            "--log".to_string(),
            data_paths.log_path.display().to_string(),
            "--consent-db".to_string(),
            data_paths.consent_path.display().to_string(),
            "--network-mode".to_string(),
            "tun".to_string(),
            "--trust-mode".to_string(),
            "local_ca".to_string(),
        ]);
        args
    }

    fn enabled_profile_selected(dam_bin: &PathBuf, data_paths: &DataPaths) -> Result<bool, String> {
        let output = Command::new(dam_bin)
            .arg("profile")
            .arg("status")
            .env(DAM_STATE_DIR_ENV, &data_paths.state_dir)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("failed to inspect active profile: {error}"))?;
        if !output.status.success() {
            return Err(command_error(
                "inspect active profile",
                &["profile".to_string(), "status".to_string()],
                &output,
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(profile_status_has_enabled_profile(&stdout))
    }

    fn profile_status_has_enabled_profile(output: &str) -> bool {
        output
            .lines()
            .find_map(|line| line.strip_prefix("enabled_profiles: "))
            .map(|profiles| profiles.trim() != "none")
            .unwrap_or_else(|| {
                output
                    .lines()
                    .find_map(|line| line.strip_prefix("active_profile: "))
                    .map(|profile| profile.trim() != "none")
                    .unwrap_or(false)
            })
    }

    fn run_dam_command(
        dam_bin: &PathBuf,
        data_paths: &DataPaths,
        args: &[String],
        label: &str,
    ) -> Result<(), String> {
        let output = Command::new(dam_bin)
            .args(args)
            .env(DAM_STATE_DIR_ENV, &data_paths.state_dir)
            .env(DAM_CONSENT_PATH_ENV, &data_paths.consent_path)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("failed to {label}: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(command_error(label, args, &output))
        }
    }

    fn command_error(label: &str, args: &[String], output: &std::process::Output) -> String {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = dam_command_failure_message(&stdout, &stderr);
        if message.is_empty() {
            format!(
                "failed to {label}: dam {} exited with {}",
                args.join(" "),
                output.status
            )
        } else {
            format!("failed to {label}: {message}")
        }
    }

    fn dam_command_failure_message(stdout: &str, stderr: &str) -> String {
        let stderr = stderr.trim();
        if !stderr.is_empty() {
            return stderr.to_string();
        }

        for prefix in ["approval: ", "message: "] {
            if let Some(message) = stdout
                .lines()
                .find_map(|line| line.strip_prefix(prefix).map(str::trim))
                .filter(|line| !line.is_empty())
            {
                return message.to_string();
            }
        }

        stdout.trim().to_string()
    }

    fn form_url_encode_component(value: &str) -> String {
        let mut encoded = String::new();
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    encoded.push(byte as char)
                }
                b' ' => encoded.push('+'),
                _ => encoded.push_str(&format!("%{byte:02X}")),
            }
        }
        encoded
    }

    fn js_string_literal(value: &str) -> String {
        let mut escaped = String::with_capacity(value.len() + 2);
        escaped.push('"');
        for ch in value.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '<' => escaped.push_str("\\u003c"),
                '>' => escaped.push_str("\\u003e"),
                '&' => escaped.push_str("\\u0026"),
                _ => escaped.push(ch),
            }
        }
        escaped.push('"');
        escaped
    }

    fn url_has_local_origin(candidate: &str, allowed_authority: &str) -> bool {
        let Some(rest) = candidate.strip_prefix("http://") else {
            return false;
        };
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .filter(|authority| !authority.is_empty());
        authority == Some(allowed_authority)
    }

    fn generate_tray_post_token() -> Result<String, String> {
        use std::io::Read as _;

        let mut bytes = [0_u8; 24];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|error| format!("failed to generate tray session token: {error}"))?;
        Ok(hex_encode(&bytes))
    }

    pub(super) fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    struct WebChild {
        child: Option<Child>,
    }

    impl WebChild {
        fn spawn(
            dam_web_bin: &PathBuf,
            dam_bin: &PathBuf,
            addr: &str,
            data_paths: &DataPaths,
            config_path: Option<&PathBuf>,
            tray_post_token: &str,
        ) -> Result<Self, String> {
            let mut command = Command::new(dam_web_bin);
            if let Some(path) = config_path {
                command.arg("--config").arg(path);
            }
            command
                .arg("--addr")
                .arg(addr)
                .arg("--db")
                .arg(&data_paths.vault_path)
                .arg("--log")
                .arg(&data_paths.log_path)
                .env(DAM_BIN_ENV, dam_bin)
                .env(DAM_STATE_DIR_ENV, &data_paths.state_dir)
                .env(DAM_CONSENT_PATH_ENV, &data_paths.consent_path)
                .env(DAM_WEB_SHELL_ENV, DAM_WEB_SHELL_TRAY)
                .env(DAM_WEB_TRAY_POST_TOKEN_ENV, tray_post_token)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            let child = command.spawn().map_err(|error| {
                format!(
                    "failed to start dam-web from {}: {error}",
                    dam_web_bin.display()
                )
            })?;
            Ok(Self { child: Some(child) })
        }

        fn stop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    impl Drop for WebChild {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn popover_origin_centers_under_tray_anchor() {
            let monitor = PhysicalFrame {
                x: 0.0,
                y: 0.0,
                width: 1440.0,
                height: 900.0,
            };
            let anchor = PhysicalFrame {
                x: 980.0,
                y: 0.0,
                width: 80.0,
                height: 24.0,
            };

            let origin = popover_origin(Some(anchor), monitor, 430.0, 720.0, 8.0);

            assert_eq!(origin.x, 805);
            assert_eq!(origin.y, 24);
        }

        #[test]
        fn popover_origin_clamps_to_monitor_edges() {
            let monitor = PhysicalFrame {
                x: 0.0,
                y: 0.0,
                width: 1440.0,
                height: 900.0,
            };
            let anchor = PhysicalFrame {
                x: 1410.0,
                y: 0.0,
                width: 60.0,
                height: 24.0,
            };

            let origin = popover_origin(Some(anchor), monitor, 430.0, 720.0, 8.0);

            assert_eq!(origin.x, 1002);
            assert_eq!(origin.y, 24);
        }

        #[test]
        fn webview_origin_check_allows_only_local_http_authority() {
            assert!(url_has_local_origin(
                "http://127.0.0.1:2896/connect",
                "127.0.0.1:2896"
            ));
            assert!(!url_has_local_origin(
                "http://127.0.0.1:28960/connect",
                "127.0.0.1:2896"
            ));
            assert!(!url_has_local_origin("https://rpblc.com", "127.0.0.1:2896"));
        }

        #[test]
        fn native_connect_args_include_state_paths_and_transparent_modes() {
            let data_paths = DataPaths {
                state_dir: PathBuf::from("/tmp/dam-state"),
                vault_path: PathBuf::from("/tmp/dam-state/vault.db"),
                log_path: PathBuf::from("/tmp/dam-state/log.db"),
                consent_path: PathBuf::from("/tmp/dam-state/consent.db"),
            };
            let args = connect_args(&data_paths, Some(&PathBuf::from("dam.toml")), true);

            assert!(args.contains(&"--apply".to_string()));
            assert!(arg_pair_exists(&args, "--config", "dam.toml"));
            assert!(arg_pair_exists(&args, "--db", "/tmp/dam-state/vault.db"));
            assert!(arg_pair_exists(&args, "--log", "/tmp/dam-state/log.db"));
            assert!(arg_pair_exists(
                &args,
                "--consent-db",
                "/tmp/dam-state/consent.db"
            ));
            assert!(arg_pair_exists(&args, "--network-mode", "tun"));
            assert!(arg_pair_exists(&args, "--trust-mode", "local_ca"));
        }

        #[test]
        fn native_connect_notice_encoding_is_url_and_js_safe() {
            assert_eq!(
                form_url_encode_component("Connect failed: local trust"),
                "Connect+failed%3A+local+trust"
            );
            assert_eq!(js_string_literal("\"<&"), "\"\\\"\\u003c\\u0026\"");
        }

        #[test]
        fn native_connect_failure_redirect_uses_error_banner_param() {
            assert_eq!(
                connect_result_redirect(Ok(())),
                "/connect?notice=DAM+connected"
            );
            assert_eq!(
                connect_result_redirect(Err("local trust".to_string())),
                "/connect?error=Connect+failed%3A+local+trust"
            );
            assert_eq!(
                connect_result_redirect(Err(
                    "action required: approve DAM Network Protection in System Settings, then click Connect/Resume again"
                        .to_string()
                )),
                "/connect?error=Action+required%3A+approve+DAM+Network+Protection+in+System+Settings%2C+then+click+Connect%2FResume+again"
            );
        }

        #[test]
        fn native_command_error_prefers_actionable_approval_line() {
            let stdout = concat!(
                "state: needs_approval\n",
                "message: raw helper state\n",
                "approval: approve DAM Network Protection in System Settings, then click Connect/Resume again\n",
            );

            assert_eq!(
                dam_command_failure_message(stdout, ""),
                "approve DAM Network Protection in System Settings, then click Connect/Resume again"
            );
            assert_eq!(
                dam_command_failure_message(stdout, "explicit failure"),
                "explicit failure"
            );
        }

        fn arg_pair_exists(args: &[String], name: &str, value: &str) -> bool {
            args.windows(2)
                .any(|pair| pair[0] == name && pair[1] == value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tray_args() {
        let args = parse_args([
            "--addr".to_string(),
            "127.0.0.1:3000".to_string(),
            "--dam-bin".to_string(),
            "/tmp/dam".to_string(),
            "--dam-web-bin".to_string(),
            "/tmp/dam-web".to_string(),
            "--config".to_string(),
            "dam.toml".to_string(),
            "--db".to_string(),
            "vault.db".to_string(),
            "--log".to_string(),
            "log.db".to_string(),
        ])
        .unwrap();

        assert_eq!(args.addr.as_deref(), Some("127.0.0.1:3000"));
        assert_eq!(args.dam_bin, Some(PathBuf::from("/tmp/dam")));
        assert_eq!(args.dam_web_bin, Some(PathBuf::from("/tmp/dam-web")));
        assert_eq!(args.config_path, Some(PathBuf::from("dam.toml")));
        assert_eq!(args.db_path, Some(PathBuf::from("vault.db")));
        assert_eq!(args.log_path, Some(PathBuf::from("log.db")));
    }

    #[test]
    fn rejects_non_loopback_web_addr() {
        let error = choose_web_addr(Some("0.0.0.0:2896")).unwrap_err();

        assert!(error.contains("loopback"));
    }

    #[test]
    fn rejects_occupied_explicit_web_addr() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let error = choose_web_addr(Some(&addr)).unwrap_err();

        assert!(error.contains("already in use"));
    }

    #[test]
    fn builds_connect_url() {
        assert_eq!(
            connect_url("127.0.0.1:2896"),
            "http://127.0.0.1:2896/connect"
        );
    }

    #[test]
    fn hex_encode_uses_lowercase_pairs() {
        assert_eq!(macos::hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
