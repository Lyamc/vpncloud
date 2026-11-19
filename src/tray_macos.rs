// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! macOS menu bar (tray) application.
//!
//! A status-bar item with a configuration context menu. It can either run the
//! VPN itself (`--tray`) or act as the user-facing companion of the launchd
//! service installed by `vpncloud install` (`--tray --tray-controls-service`).
//! In the latter case the privileged daemon lives in the system domain and the
//! menu controls it through `launchctl` (prompting for administrator rights).

use std::{
    cell::RefCell,
    env,
    ffi::c_void,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    thread::{self, JoinHandle}
};

use objc2::{
    define_class, msg_send,
    rc::Retained,
    runtime::{AnyObject, NSObject},
    AnyThread, ClassType
};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSImage, NSMenu, NSMenuItem, NSStatusBar, NSStatusItem, NSWorkspace
};
use objc2_foundation::{MainThreadMarker, NSData, NSString, NSURL};

use crate::{config::Config, svc, util::CtrlC};

const TRAY_ICON: &[u8] = include_bytes!("../assets/tray-icon.png");

struct TrayState {
    config: Config,
    worker: Option<JoinHandle<()>>,
    controls_service: bool
}

static STATE: Mutex<Option<TrayState>> = Mutex::new(None);
static CONFIG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
thread_local! {
    static TARGET: RefCell<Option<Retained<TrayTarget>>> = const { RefCell::new(None) };
    // AppKit objects are main-thread only and are not `Send`, so they live in
    // thread-local storage instead of the shared `Mutex`.
    static STATUS_ITEM: RefCell<Option<Retained<NSStatusItem>>> = const { RefCell::new(None) };
    static STATUS_MENU: RefCell<Option<Retained<NSMenu>>> = const { RefCell::new(None) };
}

define_class!(
    /// Objective-C target for the menu item actions. Actions with an explicit
    /// target are delivered straight to these methods on the main run loop.
    #[unsafe(super(NSObject))]
    #[name = "VpnCloudTrayTarget"]
    struct TrayTarget;

    impl TrayTarget {
        /// Target for the disabled status line item; never actually invoked.
        #[unsafe(method(noOp))]
        fn no_op(&self) {}

        #[unsafe(method(vpnToggle))]
        fn vpn_toggle(&self) {
            toggle_vpn();
        }

        #[unsafe(method(vpnRestart))]
        fn vpn_restart(&self) {
            restart_vpn();
        }

        #[unsafe(method(openConfigFolder))]
        fn open_config_folder(&self) {
            let path = config_dir();
            open_path(&path);
        }

        #[unsafe(method(editConfig))]
        fn edit_config(&self) {
            let path = config_file();
            open_path(&path);
        }

        #[unsafe(method(openSettings))]
        fn open_settings(&self) {
            open_settings_window();
        }

        #[unsafe(method(reloadConfig))]
        fn reload_config(&self) {
            if controls_service() {
                // The daemon is a separate process: setting our own reload
                // flag never reaches it. Kickstarting forces it to re-read its
                // config file, which is the effective equivalent of a reload.
                run_launchctl("kickstart -k");
                info!("Tray: service kickstarted to reload config");
            } else {
                crate::util::CtrlC::request_reload();
                info!("Tray: config reload requested");
            }
        }

        #[unsafe(method(quitApp))]
        fn quit_app(&self) {
            CtrlC::request_stop();
            let mtm = MainThreadMarker::new().expect("menu actions run on the main thread");
            NSApplication::sharedApplication(mtm).terminate(None);
        }
    }
);

impl TrayTarget {
    fn new() -> Retained<Self> {
        // +[NSObject new] allocates and initializes; every defined class
        // inherits it.
        unsafe { Retained::from_raw(msg_send![Self::class(), new]) }.expect("create tray target")
    }

    /// Menu items take `&AnyObject`; every Objective-C object is pointer
    /// compatible with `AnyObject`.
    fn as_object(&self) -> &AnyObject {
        unsafe { &*((self as *const Self) as *const AnyObject) }
    }
}

fn spawn_worker(config: Config) -> JoinHandle<()> {
    CtrlC::clear_stop();
    thread::Builder::new()
        .name("vpncloud".into())
        .spawn(move || crate::engine::run_vpn_worker(config))
        .expect("spawn vpn worker")
}

fn controls_service() -> bool {
    STATE.lock().map(|s| s.as_ref().map(|s| s.controls_service).unwrap_or(false)).unwrap_or(false)
}

/// Wrap a shell command in an AppleScript that asks for administrator rights.
/// Used for controlling the system LaunchDaemon from a user-session tray app.
fn admin_script(script: &str) -> String {
    let escaped = script.replace('\\', "\\\\").replace('"', "\\\"");
    format!("do shell script \"{}\" with administrator privileges", escaped)
}

fn launchctl(action: &str) -> Command {
    let mut cmd = Command::new("osascript");
    cmd.arg("-e").arg(admin_script(&format!("launchctl {} system/{}", action, svc::MAC_LABEL)));
    cmd
}

fn run_launchctl(action: &str) {
    match launchctl(action).status() {
        Ok(s) if s.success() => info!("Tray: launchctl {} succeeded", action),
        Ok(s) => warn!("Tray: launchctl {} exited with {}", action, s),
        Err(e) => error!("Tray: failed to run launchctl {}: {}", action, e)
    }
}

/// Run a compound launchctl script with administrator privileges. Disabling a
/// job before stopping it prevents KeepAlive from bringing the daemon straight
/// back; enabling it again restores normal crash recovery.
fn run_admin_script(script: &str) {
    match Command::new("osascript").arg("-e").arg(admin_script(script)).status() {
        Ok(s) if s.success() => info!("Tray: service command succeeded"),
        Ok(s) => warn!("Tray: service command exited with {}", s),
        Err(e) => error!("Tray: failed to run service command: {}", e)
    }
}

fn service_is_enabled() -> bool {
    // Read-only query: no administrator prompt just to show the menu. When
    // the daemon is not installed or not readable this simply reports stopped.
    Command::new("launchctl")
        .args(["print", &format!("system/{}", svc::MAC_LABEL)])
        .output()
        .map(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            out.status.success() && text.contains("state = running")
        })
        .unwrap_or(false)
}

fn toggle_vpn() {
    if controls_service() {
        let label = svc::MAC_LABEL;
        if service_is_enabled() {
            run_admin_script(&format!("launchctl stop system/{0}; launchctl disable system/{0}", label));
        } else {
            run_admin_script(&format!("launchctl enable system/{0}; launchctl start system/{0}", label));
        }
    } else {
        let paused = !CtrlC::is_paused();
        CtrlC::set_paused(paused);
        info!("Tray: VPN {}", if paused { "disabled" } else { "enabled" });
    }
    refresh_status_item();
}

fn restart_vpn() {
    if controls_service() {
        run_launchctl("kickstart -k");
        return;
    }
    {
        let mut guard = match STATE.lock() {
            Ok(s) => s,
            Err(_) => return
        };
        let Some(state) = guard.as_mut() else {
            return;
        };
        if let Some(worker) = state.worker.take() {
            CtrlC::request_stop();
            let _ = worker.join();
        }
        state.worker = Some(spawn_worker(state.config.clone()));
    }
    info!("Tray: VPN restarted");
    refresh_status_item();
}

fn refresh_status_item() {
    let paused = !controls_service() && CtrlC::is_paused();
    let tip = if controls_service() {
        "VpnCloud (service)".to_string()
    } else if paused {
        "VpnCloud (disabled)".to_string()
    } else {
        "VpnCloud (enabled)".to_string()
    };
    STATUS_ITEM.with(|cell| {
        let title = NSString::from_str(if paused { "VpnCloud (off)" } else { "VpnCloud" });
        let mtm = MainThreadMarker::new().expect("status item runs on the main thread");
        if let Some(item) = cell.borrow().as_ref() {
            if let Some(button) = item.button(mtm) {
                button.setTitle(&title);
                button.setToolTip(Some(&NSString::from_str(&tip)));
            }
        }
    });
}

fn cli_config_path() -> Option<PathBuf> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            if let Some(value) = args.next() {
                return Some(PathBuf::from(value));
            }
        } else if let Some(value) = arg.strip_prefix("--config=") {
            return Some(PathBuf::from(value));
        }
    }
    None
}

fn config_file() -> PathBuf {
    if let Some(path) = CONFIG_PATH.lock().ok().and_then(|p| p.clone()) {
        return path;
    }
    if let Ok(path) = env::var("VPNCLOUD_CONFIG") {
        return PathBuf::from(path);
    }
    PathBuf::from(crate::config::system_config_dir()).join("vpncloud.yaml")
}

fn config_dir() -> PathBuf {
    config_file()
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn open_path(path: &Path) {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(path)
    };
    let url = NSURL::fileURLWithPath(&NSString::from_str(&path.display().to_string()));
    let ws = NSWorkspace::sharedWorkspace();
    if !ws.openURL(&url) {
        warn!("Tray: could not open {}", path.display());
    }
}

fn open_settings_window() {
    let exe = env::current_exe().ok();
    let sibling = exe.as_ref().and_then(|p| p.parent()).map(|dir| dir.join("vpncloud-gui"));
    let program = sibling.filter(|p| p.is_file()).unwrap_or_else(|| PathBuf::from("vpncloud-gui"));
    let config = config_file();
    match Command::new(&program).arg(config).spawn() {
        Ok(_) => info!("Tray: opened settings window ({})", program.display()),
        Err(e) => {
            warn!("Tray: could not open settings window ({}): {}", program.display(), e);
            // Show a visible alert; the tray has no console for the warning.
            let script = "display alert \"VpnCloud settings app not found\" message \"Install vpncloud-gui to edit settings from the tray.\"";
            let _ = Command::new("osascript").args(["-e", script]).spawn();
        }
    }
}

fn make_status_item(mtm: MainThreadMarker, target: &TrayTarget) -> Retained<NSStatusItem> {
    let bar = NSStatusBar::systemStatusBar();
    let item = bar.statusItemWithLength(-1.0);
    if let Some(button) = item.button(mtm) {
        let data = unsafe { NSData::dataWithBytes_length(TRAY_ICON.as_ptr() as *const c_void, TRAY_ICON.len()) };
        if let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) {
            image.setTemplate(true);
            button.setImage(Some(&image));
        }
        button.setToolTip(Some(&NSString::from_str("VpnCloud")));
    }

    let menu = NSMenu::new(mtm);
    let add = |title: &str, action: objc2::runtime::Sel, enabled: bool| {
        let entry = NSMenuItem::new(mtm);
        entry.setTitle(&NSString::from_str(title));
        unsafe { entry.setAction(Some(action)) };
        unsafe { entry.setTarget(Some(target.as_object())) };
        entry.setEnabled(enabled);
        menu.addItem(&entry);
    };
    add("VpnCloud", objc2::sel!(noOp), false);
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Enable / Disable VPN", objc2::sel!(vpnToggle), true);
    add("Restart VPN", objc2::sel!(vpnRestart), true);
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Open config folder", objc2::sel!(openConfigFolder), true);
    add("Edit configuration", objc2::sel!(editConfig), true);
    add("Reload config", objc2::sel!(reloadConfig), true);
    add("Settings…", objc2::sel!(openSettings), true);
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Quit", objc2::sel!(quitApp), true);
    item.setMenu(Some(&menu));
    STATUS_MENU.with(|cell| *cell.borrow_mut() = Some(menu));
    item
}

/// Block on the macOS menu bar event loop. The VPN worker runs on a thread
/// unless this instance controls the launchd service instead.
pub fn run(config: Config) {
    let controls_service = config.tray_controls_service;
    info!("Starting macOS menu bar tray (Enable / Disable / config menu / Quit)");

    let worker = if controls_service { None } else { Some(spawn_worker(config.clone())) };
    *CONFIG_PATH.lock().expect("tray config path") = cli_config_path();
    *STATE.lock().expect("tray runtime") = Some(TrayState { config, worker, controls_service });

    let mtm = MainThreadMarker::new().expect("the macOS tray must run on the main thread");
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    let target = TrayTarget::new();
    TARGET.with(|cell| *cell.borrow_mut() = Some(target.clone()));
    STATUS_ITEM.with(|cell| *cell.borrow_mut() = Some(make_status_item(mtm, &target)));
    refresh_status_item();

    app.run();

    CtrlC::request_stop();
    let mut state = STATE.lock().expect("tray runtime");
    if let Some(state) = state.take() {
        if let Some(worker) = state.worker {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_script_escapes_quotes() {
        let script = admin_script("launchctl stop system/ca.witherow.vpncloud");
        assert!(script.contains("with administrator privileges"));
        assert!(script.contains("launchctl stop system/ca.witherow.vpncloud"));
        let quoted = admin_script("echo \"hi\"");
        assert!(quoted.contains("\\\"hi\\\""));
    }

    #[test]
    fn tray_icon_is_png() {
        assert_eq!(&TRAY_ICON[..4], b"\x89PNG");
    }
}
