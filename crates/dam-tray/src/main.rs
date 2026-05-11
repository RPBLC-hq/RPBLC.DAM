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
    deactivate_system_extension: Option<String>,
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
        deactivate_system_extension: None,
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
            "--deactivate-system-extension" => {
                cli.deactivate_system_extension =
                    Some(required_value(&mut args, "--deactivate-system-extension")?)
            }
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
    "Usage: dam-tray [--addr 127.0.0.1:2896] [--config dam.toml] [--db vault.db] [--log log.db] [--dam-bin /path/to/dam] [--dam-web-bin /path/to/dam-web] [--deactivate-system-extension BUNDLE_ID]"
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
        ffi::CStr,
        fs,
        os::raw::c_char,
        process::{Child, Command, Stdio},
    };

    use muda::{Menu, MenuEvent, MenuItem};
    use tao::{
        dpi::{LogicalSize, PhysicalPosition},
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        platform::macos::{ActivationPolicy, EventLoopExtMacOS, WindowBuilderExtMacOS},
        window::{Window, WindowBuilder},
    };
    use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use wry::{NewWindowResponse, WebViewBuilder};

    const INITIAL_POPOVER_WIDTH: f64 = 430.0;
    const INITIAL_POPOVER_HEIGHT: f64 = 720.0;
    const POPOVER_MARGIN: f64 = 8.0;
    const RPBLC_HOME_URL: &str = "https://rpblc.com";
    const MACOS_NETWORK_EXTENSION_SETTINGS_URL: &str = "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point";
    const MACOS_EXTENSION_ITEMS_SETTINGS_URL: &str =
        "x-apple.systempreferences:com.apple.LoginItems-Settings.extension?ExtensionItems";
    const MACOS_LOGIN_ITEMS_SETTINGS_URL: &str =
        "x-apple.systempreferences:com.apple.LoginItems-Settings.extension";
    const TRAY_OPEN_RPBLC_MESSAGE: &str = "dam-tray:open-rpblc";
    const TRAY_OPEN_DAM_WEB_MESSAGE: &str = "dam-tray:open-dam-web";
    const TRAY_CONNECT_MESSAGE: &str = "dam-tray:connect";
    const TRAY_QUIT_MESSAGE: &str = "dam-tray:quit";
    const TRAY_RESTART_MESSAGE: &str = "dam-tray:restart-macos";
    const TRAY_REGISTER_LOGIN_MESSAGE: &str = "dam-tray:register-launch-at-login";
    const TRAY_SKIP_LOGIN_MESSAGE: &str = "dam-tray:skip-launch-at-login";

    const LAUNCH_AGENT_PLIST_RELPATH: &str = "Library/LaunchAgents/com.rpblc.dam-tray.plist";
    const LOGIN_ITEM_MARKER_RELPATH: &str = "startup/login-item.txt";
    const LOGIN_ITEM_SKIP_MARKER_RELPATH: &str = "startup/login-item-skipped.txt";

    // Bundled-build env hint forwarded to dam-web. Set when dam-tray
    // is running from inside a `.app/Contents/MacOS/` location, where
    // the macOS Network Extension can actually host. In dev (`cargo
    // run` against `target/debug/`), the env stays unset and dam-web
    // falls back to `ExplicitProxy + Disabled`, skipping the NE +
    // local-CA setup steps that can't complete without a code-signed
    // bundle.
    const DAM_TRAY_BUNDLED_ENV: &str = "DAM_TRAY_BUNDLED";

    #[derive(Debug)]
    enum UserEvent {
        TrayIcon(TrayIconEvent),
        Menu(MenuEvent),
        OpenRpblc,
        OpenDamWeb,
        ConnectRequested,
        QuitRequested,
        RestartMacOSRequested,
        RegisterLaunchAtLoginRequested,
        SkipLaunchAtLoginRequested,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct PhysicalFrame {
        x: f64,
        y: f64,
        width: f64,
        height: f64,
    }

    pub(super) fn run(cli: CliArgs) -> Result<(), String> {
        if let Some(bundle_identifier) = cli.deactivate_system_extension.as_deref() {
            let outcome = crate::macos_system_extension::deactivate(
                bundle_identifier,
                Duration::from_secs(20),
            )?;
            match outcome {
                crate::macos_system_extension::DeactivationOutcome::Removed(message)
                | crate::macos_system_extension::DeactivationOutcome::NeedsApproval(message)
                | crate::macos_system_extension::DeactivationOutcome::NeedsReboot(message) => {
                    println!("{message}");
                }
            }
            return Ok(());
        }

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

        // Auto-resume on launch when there's evidence the user has
        // already set DAM up in a prior session. Without this,
        // launch-at-login would bring the menu-bar app back after a
        // reboot but leave the protection daemon down — the user would
        // open the popover and find DAM "disconnected" again, even
        // though they'd already done the setup work.
        //
        // We trigger when:
        //   - a daemon state file exists (Stale = pid gone after
        //     reboot, Connected = somehow already up), OR
        //   - the macOS Network Extension record exists (active or
        //     pending_reboot — both mean the user got past the NE
        //     install step).
        //
        // Otherwise we leave the user in the disconnected welcome
        // state. Auto-running `connect_dam` on a fresh install would
        // pop the macOS NE-approval prompt before the user has even
        // seen the welcome tile — too aggressive.
        //
        // `connect_dam` is idempotent: if NE is Ready it cleans the
        // pending-reboot record and re-spawns the daemon; if NE is
        // still NeedsReboot or NeedsApproval it halts and leaves the
        // appropriate step current for the popover to show. All
        // failures are swallowed — the popover is still useful, and
        // the user can retry from the welcome checklist.
        let should_auto_resume =
            matches!(
                dam_daemon::daemon_status(),
                Ok(dam_daemon::DaemonStatus::Stale(_) | dam_daemon::DaemonStatus::Connected(_))
            ) || dam_net_macos::network_extension_active(&data_paths.state_dir)
                || dam_net_macos::network_extension_pending_reboot(&data_paths.state_dir);

        if should_auto_resume {
            let _ = connect_dam(&dam_bin, &data_paths, cli.config_path.as_ref());
        }

        let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
        event_loop.set_dock_visibility(false);
        let proxy = event_loop.create_proxy();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::TrayIcon(event));
        }));
        // Forward menu activations (Quit, future items) into the same
        // event loop so the existing UserEvent path drives shutdown.
        let menu_proxy = event_loop.create_proxy();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = menu_proxy.send_event(UserEvent::Menu(event));
        }));
        let ipc_proxy = event_loop.create_proxy();
        let navigation_authority = addr.clone();
        let ipc_authority = addr.clone();
        let web_home_url = format!("http://{addr}/");

        let window = WindowBuilder::new()
            .with_title("DAM")
            .with_inner_size(LogicalSize::new(
                INITIAL_POPOVER_WIDTH,
                INITIAL_POPOVER_HEIGHT,
            ))
            .with_resizable(true)
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
                    TRAY_OPEN_DAM_WEB_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::OpenDamWeb);
                    }
                    TRAY_CONNECT_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::ConnectRequested);
                    }
                    TRAY_QUIT_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::QuitRequested);
                    }
                    TRAY_RESTART_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::RestartMacOSRequested);
                    }
                    TRAY_REGISTER_LOGIN_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::RegisterLaunchAtLoginRequested);
                    }
                    TRAY_SKIP_LOGIN_MESSAGE => {
                        let _ = ipc_proxy.send_event(UserEvent::SkipLaunchAtLoginRequested);
                    }
                    _ => {}
                }
            })
            .build(&window)
            .map_err(|error| format!("failed to create DAM webview: {error}"))?;

        let mut tray_icon = None;
        // The Quit item lives on the tray icon's right-click menu so the
        // user can exit DAM without going through the SPA. The id is
        // stable so the dispatch below can match against it. See
        // `RPBLC.Architecture/dam/web/specs/tray-shell.md` § Dismiss.
        let quit_item = MenuItem::with_id("dam-tray.quit", "Quit DAM", true, None);
        let quit_item_id = quit_item.id().clone();
        let tray_menu = Menu::new();
        if let Err(error) = tray_menu.append(&quit_item) {
            eprintln!("failed to build tray menu: {error}");
        }
        let dam_bin_for_connect = dam_bin.clone();
        let data_paths_for_connect = data_paths.clone();
        let data_paths_for_login = data_paths.clone();
        let config_path_for_connect = cli.config_path.clone();
        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;

            match event {
                Event::NewEvents(StartCause::Init) => {
                    if tray_icon.is_none() {
                        match build_tray(tray_menu.clone()) {
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
                Event::UserEvent(UserEvent::Menu(event)) => {
                    if event.id == quit_item_id {
                        web_child.stop();
                        *control_flow = ControlFlow::Exit;
                    }
                }
                Event::UserEvent(UserEvent::OpenRpblc) => {
                    if let Err(error) = open_in_browser(RPBLC_HOME_URL) {
                        eprintln!("{error}");
                    }
                }
                Event::UserEvent(UserEvent::OpenDamWeb) => {
                    if let Err(error) = open_in_browser(&web_home_url) {
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
                Event::UserEvent(UserEvent::RestartMacOSRequested) => {
                    if let Err(error) = request_macos_restart() {
                        eprintln!("dam-tray: macOS restart request failed: {error}");
                    }
                }
                Event::UserEvent(UserEvent::RegisterLaunchAtLoginRequested) => {
                    let result = register_launch_at_login(&data_paths_for_login);
                    let redirect = match result {
                        Ok(()) => "/connect".to_string(),
                        Err(error) => {
                            eprintln!("dam-tray: register-launch-at-login failed: {error}");
                            format!(
                                "/connect?error={}",
                                form_url_encode_component(&format!(
                                    "Couldn't add DAM to your login items: {error}"
                                ))
                            )
                        }
                    };
                    let script = format!("window.location.href = {}", js_string_literal(&redirect));
                    if let Err(error) = webview.evaluate_script(&script) {
                        eprintln!("dam-tray: failed to refresh tray view: {error}");
                    }
                }
                Event::UserEvent(UserEvent::SkipLaunchAtLoginRequested) => {
                    let result = write_login_item_skip_marker(&data_paths_for_login);
                    let redirect = match result {
                        Ok(()) => "/connect".to_string(),
                        Err(error) => {
                            eprintln!("dam-tray: skip-launch-at-login failed: {error}");
                            format!(
                                "/connect?error={}",
                                form_url_encode_component(&format!(
                                    "Couldn't save the startup choice: {error}"
                                ))
                            )
                        }
                    };
                    let script = format!("window.location.href = {}", js_string_literal(&redirect));
                    if let Err(error) = webview.evaluate_script(&script) {
                        eprintln!("dam-tray: failed to refresh tray view: {error}");
                    }
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

    fn connect_result_redirect(result: Result<ConnectOutcome, String>) -> String {
        match result {
            Ok(ConnectOutcome::Connected) => format!(
                "/connect?notice={}",
                form_url_encode_component("DAM connected")
            ),
            // Reboot / approval are not errors — they are step
            // transitions. Plain `/connect` triggers a fresh setup_plan
            // fetch; the diagnostics layer now emits the reboot step
            // (or the approval-pending state) and the SPA's checklist
            // moves the user along. No banner needed; the new step
            // *is* the message.
            Ok(ConnectOutcome::AdvancedSetup)
            | Ok(ConnectOutcome::NeedsApproval)
            | Ok(ConnectOutcome::NeedsReboot) => "/connect".to_string(),
            Err(error) => {
                eprintln!("{error}");
                let message = connect_error_message(&error);
                format!("/connect?error={}", form_url_encode_component(&message))
            }
        }
    }

    fn connect_error_message(error: &str) -> String {
        if let Some(message) = network_protection_start_failure(error) {
            return message.to_string();
        }
        approval_instruction(error)
            .map(|message| format!("Action required: {message}"))
            .unwrap_or_else(|| format!("Connect failed: {error}"))
    }

    fn network_protection_start_failure(error: &str) -> Option<&str> {
        let index = error.find("DAM Network Protection is enabled but")?;
        Some(error[index..].trim())
    }

    fn approval_instruction(error: &str) -> Option<&str> {
        if let Some(message) = error.strip_prefix("action required: ") {
            return Some(message);
        }
        error
            .find("approve DAM Network Protection")
            .map(|index| &error[index..])
    }

    /// True when this dam-tray binary is running from inside a
    /// `.app/Contents/MacOS/` bundle. Used to gate setup steps that
    /// require code-signed bundle hosting (macOS Network Extension,
    /// trust-root install). Dev runs (`cargo run`, screen/tmux from
    /// `target/debug/`) report false and dam-web falls back to a
    /// no-bundle-required setup default.
    fn is_bundled() -> bool {
        env::current_exe()
            .ok()
            .as_ref()
            .and_then(|path| path.to_str())
            .map(|path| path.contains(".app/Contents/MacOS/"))
            .unwrap_or(false)
    }

    fn build_tray(menu: muda::Menu) -> Result<tray_icon::TrayIcon, String> {
        // Text title `[R:]` (the canonical RPBLC bracket mark) over a
        // raster icon. The favicon SVG, pre-rendered at 44px, lost its
        // glyph against the menu bar background and read as a blank
        // square — the brand mark needs deliberate icon-format tuning
        // (template image, single colour, OS-specific dark/light
        // variants) before it works as a system icon. Until that asset
        // lands in `RPBLC.Design`, the text title renders the mark
        // crisply and inherits the menu bar's tint, so it adapts to
        // light/dark modes for free.
        TrayIconBuilder::new()
            .with_tooltip("DAM")
            .with_title("[R:]")
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
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
                width: f64::from(window.outer_size().width),
                height: f64::from(window.outer_size().height),
            });
        let popover_size = window.outer_size();
        let anchor = tray_rect.map(|rect| PhysicalFrame {
            x: rect.position.x,
            y: rect.position.y,
            width: rect.size.width as f64,
            height: rect.size.height as f64,
        });
        let position = popover_origin(
            anchor,
            monitor_frame,
            f64::from(popover_size.width),
            f64::from(popover_size.height),
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

    /// Outcome of a connect attempt. NeedsApproval / NeedsReboot are
    /// not errors — the user has done their part, the system needs
    /// follow-up. The SPA's setup checklist surfaces them as the next
    /// step instead of as a hard failure on the install click.
    enum ConnectOutcome {
        Connected,
        AdvancedSetup,
        NeedsApproval,
        NeedsReboot,
    }

    fn connect_dam(
        dam_bin: &PathBuf,
        data_paths: &DataPaths,
        config_path: Option<&PathBuf>,
    ) -> Result<ConnectOutcome, String> {
        let setup_plan = tray_setup_plan(data_paths, config_path)?;
        if let Some(step) = setup_plan.steps.iter().find(|step| {
            matches!(
                step.status,
                dam_diagnostics::SetupStepStatus::Needed
                    | dam_diagnostics::SetupStepStatus::Blocked
            )
        }) {
            if step.status == dam_diagnostics::SetupStepStatus::Blocked {
                return Err(format!("DAM setup is blocked: {}", step.message));
            }
            return run_setup_step(dam_bin, data_paths, config_path, step.kind);
        }

        let has_active_profile = enabled_profile_selected(dam_bin, data_paths)?;
        run_dam_command(
            dam_bin,
            data_paths,
            &connect_args(data_paths, config_path, has_active_profile),
            "connect DAM",
        )?;
        Ok(ConnectOutcome::Connected)
    }

    fn tray_setup_plan(
        data_paths: &DataPaths,
        config_path: Option<&PathBuf>,
    ) -> Result<dam_diagnostics::SetupPlan, String> {
        let config = dam_config::load(&dam_config::ConfigOverrides {
            config_path: config_path.cloned(),
            ..dam_config::ConfigOverrides::default()
        })
        .map_err(|error| format!("load DAM config for setup plan: {error}"))?;
        let (network_mode, trust_mode) = if is_bundled() {
            (dam_net::CaptureMode::Tun, dam_trust::TrustMode::LocalCa)
        } else {
            (
                dam_net::CaptureMode::ExplicitProxy,
                dam_trust::TrustMode::Disabled,
            )
        };
        dam_diagnostics::setup_plan(
            &config,
            &dam_diagnostics::SetupPlanOptions {
                state_dir: Some(data_paths.state_dir.clone()),
                config_path: config_path.cloned(),
                proxy_url: None,
                network_mode,
                trust_mode,
            },
        )
    }

    fn run_setup_step(
        dam_bin: &PathBuf,
        data_paths: &DataPaths,
        config_path: Option<&PathBuf>,
        kind: dam_diagnostics::SetupStepKind,
    ) -> Result<ConnectOutcome, String> {
        match kind {
            dam_diagnostics::SetupStepKind::LaunchAtLogin => Ok(ConnectOutcome::AdvancedSetup),
            dam_diagnostics::SetupStepKind::NetworkExtension => {
                match activate_system_extension_from_app(data_paths)? {
                    SystemExtensionActivation::Ready => Ok(ConnectOutcome::AdvancedSetup),
                    SystemExtensionActivation::NeedsApproval => Ok(ConnectOutcome::NeedsApproval),
                    SystemExtensionActivation::NeedsReboot => Ok(ConnectOutcome::NeedsReboot),
                }
            }
            dam_diagnostics::SetupStepKind::NetworkExtensionReboot => {
                Ok(ConnectOutcome::NeedsReboot)
            }
            dam_diagnostics::SetupStepKind::NetworkExtensionConfiguration => {
                match run_dam_command(
                    dam_bin,
                    data_paths,
                    &network_install_args(config_path),
                    "install Network Extension routing",
                ) {
                    Ok(()) => Ok(ConnectOutcome::AdvancedSetup),
                    Err(error) if approval_instruction(&error).is_some() => {
                        Ok(ConnectOutcome::AdvancedSetup)
                    }
                    Err(error) => Err(error),
                }
            }
            dam_diagnostics::SetupStepKind::NetworkExtensionEnable
            | dam_diagnostics::SetupStepKind::NetworkExtensionStart => {
                match run_dam_command(
                    dam_bin,
                    data_paths,
                    &network_install_args(config_path),
                    "install Network Extension routing",
                ) {
                    Ok(()) => Ok(ConnectOutcome::AdvancedSetup),
                    Err(error) if approval_instruction(&error).is_some() => {
                        open_network_extension_approval_settings();
                        Ok(ConnectOutcome::NeedsApproval)
                    }
                    Err(error) => Err(error),
                }
            }
            dam_diagnostics::SetupStepKind::LocalCa => {
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
                Ok(ConnectOutcome::AdvancedSetup)
            }
            dam_diagnostics::SetupStepKind::ProfileApply
            | dam_diagnostics::SetupStepKind::Daemon => {
                let has_active_profile = enabled_profile_selected(dam_bin, data_paths)?;
                run_dam_command(
                    dam_bin,
                    data_paths,
                    &connect_args(data_paths, config_path, has_active_profile),
                    "connect DAM",
                )?;
                Ok(ConnectOutcome::Connected)
            }
            dam_diagnostics::SetupStepKind::SystemProxy => {
                run_dam_command(
                    dam_bin,
                    data_paths,
                    &system_proxy_install_args(config_path),
                    "install system proxy routing",
                )?;
                Ok(ConnectOutcome::AdvancedSetup)
            }
            dam_diagnostics::SetupStepKind::LinuxTransparentProxy
            | dam_diagnostics::SetupStepKind::WindowsFilteringPlatform => {
                Err("this DAM tray build cannot perform that platform setup step".to_string())
            }
        }
    }

    enum SystemExtensionActivation {
        Ready,
        NeedsApproval,
        NeedsReboot,
    }

    const LOGIN_ITEM_REGISTERED: i32 = 0;
    const LOGIN_ITEM_FAILED: i32 = 1;
    const LOGIN_ITEM_REQUIRES_APPROVAL: i32 = 2;
    const LOGIN_ITEM_UNSUPPORTED: i32 = 3;

    unsafe extern "C" {
        fn dam_tray_register_login_item(
            message_buffer: *mut c_char,
            message_buffer_len: usize,
        ) -> i32;
    }

    fn activate_system_extension_from_app(
        data_paths: &DataPaths,
    ) -> Result<SystemExtensionActivation, String> {
        let bundle_identifier = env::var("DAM_MACOS_NE_BUNDLE_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_MACOS_NE_BUNDLE_ID.to_string());
        match crate::macos_system_extension::activate(&bundle_identifier, Duration::from_secs(20)) {
            Ok(crate::macos_system_extension::ActivationOutcome::Ready(_)) => {
                // System Extension activation is only the native
                // host becoming available. The helper still has to
                // configure and verify NETransparentProxyManager
                // before DAM can mark capture active.
                let _ = dam_net_macos::record_system_extension_ready(
                    &data_paths.state_dir,
                    bundle_identifier,
                    None,
                    Vec::new(),
                );
                Ok(SystemExtensionActivation::Ready)
            }
            Ok(crate::macos_system_extension::ActivationOutcome::NeedsApproval(_)) => {
                let _ = dam_net_macos::record_system_extension_needs_approval(
                    &data_paths.state_dir,
                    bundle_identifier,
                    None,
                    Vec::new(),
                );
                open_network_extension_approval_settings();
                Ok(SystemExtensionActivation::NeedsApproval)
            }
            Ok(crate::macos_system_extension::ActivationOutcome::NeedsReboot(_)) => {
                // Persist a generic pending-reboot transition so the
                // SPA surfaces restart as its own step. After reboot,
                // DAM re-checks the prior setup steps from live system
                // state before continuing.
                let _ = dam_net_macos::record_pending_reboot(
                    &data_paths.state_dir,
                    bundle_identifier,
                    None,
                    Vec::new(),
                );
                Ok(SystemExtensionActivation::NeedsReboot)
            }
            Err(error) => Err(format!("activate DAM Network Protection: {error}")),
        }
    }

    /// Register the installed app with macOS Login Items. This uses
    /// `SMAppService.mainApp`, so the user sees DAM under System
    /// Settings > General > Login Items > Open at Login instead of the
    /// legacy background-items bucket used by LaunchAgents.
    fn register_launch_at_login(data_paths: &DataPaths) -> Result<(), String> {
        let mut message = vec![0 as c_char; 2048];
        let status = unsafe { dam_tray_register_login_item(message.as_mut_ptr(), message.len()) };
        let message = unsafe { CStr::from_ptr(message.as_ptr()) }
            .to_string_lossy()
            .trim()
            .to_string();

        match status {
            LOGIN_ITEM_REGISTERED => {
                remove_legacy_launch_agent();
                write_login_item_marker(data_paths)?;
                Ok(())
            }
            LOGIN_ITEM_REQUIRES_APPROVAL => Err(non_empty_login_message(
                message,
                "approve DAM in System Settings > General > Login Items, then continue setup",
            )),
            LOGIN_ITEM_UNSUPPORTED => Err(non_empty_login_message(
                message,
                "this macOS version does not support SMAppService login items",
            )),
            LOGIN_ITEM_FAILED => Err(non_empty_login_message(
                message,
                "failed to register DAM as a login item",
            )),
            _ => Err(non_empty_login_message(
                message,
                "DAM login item registration returned an unknown result",
            )),
        }
    }

    fn write_login_item_marker(data_paths: &DataPaths) -> Result<(), String> {
        let executable = env::current_exe()
            .map_err(|error| format!("can't locate dam-tray executable: {error}"))?;
        let marker_path = data_paths.state_dir.join(LOGIN_ITEM_MARKER_RELPATH);
        if let Some(parent) = marker_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create startup marker dir: {error}"))?;
        }
        let marker = format!("registered\n{}\n", executable.display());
        fs::write(&marker_path, marker)
            .map_err(|error| format!("write {}: {error}", marker_path.display()))?;
        let _ = fs::remove_file(data_paths.state_dir.join(LOGIN_ITEM_SKIP_MARKER_RELPATH));
        Ok(())
    }

    fn write_login_item_skip_marker(data_paths: &DataPaths) -> Result<(), String> {
        let marker_path = data_paths.state_dir.join(LOGIN_ITEM_SKIP_MARKER_RELPATH);
        if let Some(parent) = marker_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create startup marker dir: {error}"))?;
        }
        fs::write(&marker_path, "skipped\n")
            .map_err(|error| format!("write {}: {error}", marker_path.display()))?;
        Ok(())
    }

    fn remove_legacy_launch_agent() {
        let Some(home) = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
        else {
            return;
        };
        let _ = fs::remove_file(home.join(LAUNCH_AGENT_PLIST_RELPATH));
    }

    fn non_empty_login_message(message: String, fallback: &str) -> String {
        if message.is_empty() {
            fallback.to_string()
        } else {
            message
        }
    }

    /// Hand the user the standard macOS restart confirmation dialog.
    /// The AppleScript event `aevtrrst` ("restart") sent to
    /// `loginwindow` opens the system "Are you sure you want to
    /// restart your computer now?" prompt — the user confirms,
    /// macOS handles the restart. DAM never reboots anything itself.
    fn request_macos_restart() -> Result<(), String> {
        let status = Command::new("/usr/bin/osascript")
            .args(["-e", "tell application \"loginwindow\" to «event aevtrrst»"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("failed to invoke osascript: {error}"))?;
        if !status.success() {
            return Err(format!("osascript exited with status {status}"));
        }
        Ok(())
    }

    fn open_network_extension_approval_settings() {
        for url in network_extension_approval_settings_urls() {
            if open_in_browser(url).is_ok() {
                return;
            }
        }
        let _ = Command::new("open")
            .arg("-b")
            .arg("com.apple.systempreferences")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    fn network_extension_approval_settings_urls() -> [&'static str; 3] {
        [
            MACOS_NETWORK_EXTENSION_SETTINGS_URL,
            MACOS_EXTENSION_ITEMS_SETTINGS_URL,
            MACOS_LOGIN_ITEMS_SETTINGS_URL,
        ]
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

    fn system_proxy_install_args(config_path: Option<&PathBuf>) -> Vec<String> {
        let mut args = vec![
            "network".to_string(),
            "install-system-proxy".to_string(),
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
        ]);
        // Network and trust modes are bundle-dependent. The macOS
        // Network Extension (`tun` capture) and the local-CA trust
        // chain both need a code-signed `.app` host; running from
        // `target/debug/dam-tray` returns NeedsApproval forever
        // because there's no extension to activate. So in dev we
        // default to `explicit_proxy + disabled`, which routes via
        // an explicit proxy URL the user sets on the AI client and
        // skips the macOS-bundle-only setup steps. Production
        // bundles set `DAM_TRAY_BUNDLED=1` and get the real
        // `tun + local_ca` flow.
        if is_bundled() {
            args.extend([
                "--network-mode".to_string(),
                "tun".to_string(),
                "--trust-mode".to_string(),
                "local_ca".to_string(),
            ]);
        } else {
            args.extend([
                "--network-mode".to_string(),
                "explicit_proxy".to_string(),
                "--trust-mode".to_string(),
                "disabled".to_string(),
            ]);
        }
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
            if let Some(message) = stderr.strip_prefix("dam-macos-ne-helper: ") {
                return message.trim().to_string();
            }
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

            if is_bundled() {
                command.env(DAM_TRAY_BUNDLED_ENV, "1");
            }

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
        fn native_connect_args_include_state_paths_and_dev_modes() {
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
            assert!(arg_pair_exists(&args, "--network-mode", "explicit_proxy"));
            assert!(arg_pair_exists(&args, "--trust-mode", "disabled"));
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
                connect_result_redirect(Ok(ConnectOutcome::Connected)),
                "/connect?notice=DAM+connected"
            );
            assert_eq!(
                connect_result_redirect(Ok(ConnectOutcome::NeedsApproval)),
                "/connect"
            );
            assert_eq!(
                connect_result_redirect(Ok(ConnectOutcome::AdvancedSetup)),
                "/connect"
            );
            assert_eq!(
                connect_result_redirect(Ok(ConnectOutcome::NeedsReboot)),
                "/connect"
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
            assert_eq!(
                connect_result_redirect(Err(
                    "failed to install Network Extension routing: DAM Network Protection is enabled but did not connect: timeout"
                        .to_string()
                )),
                "/connect?error=DAM+Network+Protection+is+enabled+but+did+not+connect%3A+timeout"
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
            assert_eq!(
                dam_command_failure_message(
                    "",
                    "dam-macos-ne-helper: DAM Network Protection is enabled but did not connect: timeout"
                ),
                "DAM Network Protection is enabled but did not connect: timeout"
            );
        }

        #[test]
        fn network_extension_settings_urls_prefer_specific_extension_section() {
            assert_eq!(
                network_extension_approval_settings_urls(),
                [
                    "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point",
                    "x-apple.systempreferences:com.apple.LoginItems-Settings.extension?ExtensionItems",
                    "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
                ]
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
            "--deactivate-system-extension".to_string(),
            "com.rpblc.dam.network-extension".to_string(),
        ])
        .unwrap();

        assert_eq!(args.addr.as_deref(), Some("127.0.0.1:3000"));
        assert_eq!(args.dam_bin, Some(PathBuf::from("/tmp/dam")));
        assert_eq!(args.dam_web_bin, Some(PathBuf::from("/tmp/dam-web")));
        assert_eq!(args.config_path, Some(PathBuf::from("dam.toml")));
        assert_eq!(args.db_path, Some(PathBuf::from("vault.db")));
        assert_eq!(args.log_path, Some(PathBuf::from("log.db")));
        assert_eq!(
            args.deactivate_system_extension.as_deref(),
            Some("com.rpblc.dam.network-extension")
        );
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
