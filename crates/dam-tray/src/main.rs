use std::{
    env,
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

const DEFAULT_WEB_PORT: u16 = 2896;
const DEFAULT_WEB_PORT_MAX: u16 = 2916;
const DAM_BIN_ENV: &str = "DAM_BIN";
const DAM_WEB_BIN_ENV: &str = "DAM_WEB_BIN";
const DAM_STATE_DIR_ENV: &str = "DAM_STATE_DIR";
const DAM_CONSENT_PATH_ENV: &str = "DAM_CONSENT_PATH";
const DAM_WEB_SHELL_ENV: &str = "DAM_WEB_SHELL";
const DAM_WEB_SHELL_TRAY: &str = "tray";

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
    const TRAY_QUIT_MESSAGE: &str = "dam-tray:quit";

    #[derive(Debug)]
    enum UserEvent {
        TrayIcon(TrayIconEvent),
        OpenRpblc,
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
        let mut web_child = WebChild::spawn(
            &dam_web_bin,
            &dam_bin,
            &addr,
            &data_paths,
            cli.config_path.as_ref(),
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

        let _webview = WebViewBuilder::new()
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
                    TRAY_QUIT_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::QuitRequested);
                    }
                    _ => {}
                }
            })
            .build(&window)
            .map_err(|error| format!("failed to create DAM webview: {error}"))?;

        let mut tray_icon = None;
        let dam_bin_for_quit = dam_bin.clone();
        let state_dir_for_quit = data_paths.state_dir.clone();

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
                Event::UserEvent(UserEvent::QuitRequested) => {
                    if let Err(error) = disconnect_dam(&dam_bin_for_quit, &state_dir_for_quit) {
                        eprintln!("{error}");
                    }
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

    fn disconnect_dam(dam_bin: &PathBuf, state_dir: &PathBuf) -> Result<(), String> {
        let status = Command::new(dam_bin)
            .arg("disconnect")
            .env(DAM_STATE_DIR_ENV, state_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| format!("failed to run `dam disconnect`: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("`dam disconnect` exited with {status}"))
        }
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
}
