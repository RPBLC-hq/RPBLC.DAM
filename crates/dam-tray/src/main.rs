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
        dpi::LogicalSize,
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        window::WindowBuilder,
    };
    use tray_icon::{
        Icon, TrayIconBuilder, TrayIconEvent,
        menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
    };
    use wry::WebViewBuilder;

    const SHOW_ITEM_ID: &str = "show";
    const RELOAD_ITEM_ID: &str = "reload";
    const BROWSER_ITEM_ID: &str = "browser";
    const QUIT_ITEM_ID: &str = "quit";

    #[derive(Debug)]
    enum UserEvent {
        TrayIcon(TrayIconEvent),
        Menu(MenuEvent),
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

        let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        let proxy = event_loop.create_proxy();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::TrayIcon(event));
        }));
        let proxy = event_loop.create_proxy();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::Menu(event));
        }));

        let window = WindowBuilder::new()
            .with_title("DAM")
            .with_inner_size(LogicalSize::new(430.0, 760.0))
            .with_min_inner_size(LogicalSize::new(380.0, 620.0))
            .with_resizable(true)
            .build(&event_loop)
            .map_err(|error| format!("failed to create DAM window: {error}"))?;

        let webview = WebViewBuilder::new()
            .with_url(&url)
            .build(&window)
            .map_err(|error| format!("failed to create DAM webview: {error}"))?;

        let mut tray_icon = None;

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;

            match event {
                Event::NewEvents(StartCause::Init) => {
                    if tray_icon.is_none() {
                        match build_tray() {
                            Ok(icon) => tray_icon = Some(icon),
                            Err(error) => {
                                eprintln!("{error}");
                                web_child.stop();
                                *control_flow = ControlFlow::Exit;
                                return;
                            }
                        }
                    }
                    window.set_visible(true);
                    window.set_focus();
                }
                Event::UserEvent(UserEvent::TrayIcon(TrayIconEvent::Click { .. }))
                | Event::UserEvent(UserEvent::TrayIcon(TrayIconEvent::DoubleClick { .. })) => {
                    show_window(&window);
                }
                Event::UserEvent(UserEvent::TrayIcon(_)) => {}
                Event::UserEvent(UserEvent::Menu(event)) if event.id() == SHOW_ITEM_ID => {
                    show_window(&window);
                }
                Event::UserEvent(UserEvent::Menu(event)) if event.id() == RELOAD_ITEM_ID => {
                    let _ = webview.load_url(&url);
                    show_window(&window);
                }
                Event::UserEvent(UserEvent::Menu(event)) if event.id() == BROWSER_ITEM_ID => {
                    let _ = open_in_browser(&url);
                }
                Event::UserEvent(UserEvent::Menu(event)) if event.id() == QUIT_ITEM_ID => {
                    web_child.stop();
                    *control_flow = ControlFlow::Exit;
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
        let show = MenuItem::with_id(MenuId::new(SHOW_ITEM_ID), "Open DAM", true, None);
        let reload = MenuItem::with_id(MenuId::new(RELOAD_ITEM_ID), "Reload", true, None);
        let browser =
            MenuItem::with_id(MenuId::new(BROWSER_ITEM_ID), "Open in Browser", true, None);
        let quit = MenuItem::with_id(MenuId::new(QUIT_ITEM_ID), "Quit DAM", true, None);
        let separator = PredefinedMenuItem::separator();
        let menu = Menu::new();
        menu.append_items(&[&show, &reload, &browser, &separator, &quit])
            .map_err(|error| format!("failed to build tray menu: {error}"))?;

        TrayIconBuilder::new()
            .with_tooltip("DAM")
            .with_title("DAM")
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(true)
            .with_icon(tray_icon()?)
            .with_icon_as_template(true)
            .build()
            .map_err(|error| format!("failed to create tray icon: {error}"))
    }

    fn show_window(window: &tao::window::Window) {
        window.set_visible(true);
        window.set_focus();
    }

    fn open_in_browser(url: &str) -> Result<(), String> {
        let status = Command::new("open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("failed to open browser: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "failed to open browser: command exited with {status}"
            ))
        }
    }

    fn tray_icon() -> Result<Icon, String> {
        let size = 32usize;
        let mut rgba = vec![0u8; size * size * 4];
        for y in 0..size {
            for x in 0..size {
                let cx = x as f32 - 15.5;
                let cy = y as f32 - 15.5;
                let radius = (cx * cx + cy * cy).sqrt();
                let mut alpha = 0u8;

                if (10.5..=13.5).contains(&radius) {
                    alpha = 255;
                }
                if (9..=20).contains(&x) && (8..=11).contains(&y) {
                    alpha = 255;
                }
                if (9..=12).contains(&x) && (8..=24).contains(&y) {
                    alpha = 255;
                }
                if (12..=19).contains(&x) && (15..=18).contains(&y) {
                    alpha = 255;
                }
                if x >= 16 && y >= 18 && x <= 23 && y <= 25 && (x as isize - y as isize).abs() <= 2
                {
                    alpha = 255;
                }

                let offset = (y * size + x) * 4;
                rgba[offset] = 255;
                rgba[offset + 1] = 255;
                rgba[offset + 2] = 255;
                rgba[offset + 3] = alpha;
            }
        }

        Icon::from_rgba(rgba, size as u32, size as u32)
            .map_err(|error| format!("failed to create tray icon: {error}"))
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
