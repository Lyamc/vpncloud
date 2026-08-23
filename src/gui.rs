// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Desktop settings window (Iced, software renderer).

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    thread::{self, JoinHandle},
    time::Duration
};

use iced::{
    widget::{button, checkbox, column, container, radio, row, scrollable, text, text_input, Space},
    Alignment, Element, Length, Task, Theme
};

use crate::{
    config::{Config, ConfigFile, ConfigFileDevice, CryptoConfig},
    device::Type,
    engine::run_vpn,
    util::CtrlC
};

#[derive(Debug, Clone)]
pub enum Message {
    Password(String),
    Overlay(String),
    Peer(String),
    Listen(String),
    ConfigPath(String),
    Tap(bool),
    Connect,
    Disconnect,
    TogglePause,
    Save,
    Load,
    Tick
}

pub struct Gui {
    password: String,
    overlay: String,
    peer: String,
    listen: String,
    tap: bool,
    config_path: String,
    status: String,
    worker: Option<JoinHandle<()>>
}

impl Default for Gui {
    fn default() -> Self {
        let mut gui = Self {
            password: String::new(),
            overlay: "10.0.0.1/24".into(),
            peer: String::new(),
            listen: "3210".into(),
            tap: false,
            config_path: default_config_path().display().to_string(),
            status: "Disconnected".into(),
            worker: None
        };
        if Path::new(&gui.config_path).is_file() {
            match load_into(&mut gui) {
                Ok(()) => gui.status = format!("Loaded {}", gui.config_path),
                Err(e) => gui.status = format!("Could not load config: {}", e)
            }
        }
        gui
    }
}

impl Drop for Gui {
    fn drop(&mut self) {
        CtrlC::request_stop();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        crate::util::set_fail_panics(false);
    }
}

fn title(_: &Gui) -> String {
    "VpnCloud".to_string()
}

fn theme(_: &Gui) -> Theme {
    Theme::Dark
}

fn later_tick() -> Task<Message> {
    Task::perform(
        async {
            std::thread::sleep(Duration::from_millis(400));
        },
        |_| Message::Tick
    )
}

pub fn run() -> iced::Result {
    iced::application(Gui::default, update, view)
        .title(title)
        .theme(theme)
        .window_size(iced::Size::new(460.0, 620.0))
        .antialiasing(false)
        .run()
}

fn update(gui: &mut Gui, message: Message) -> Task<Message> {
    match message {
        Message::Password(v) => gui.password = v,
        Message::Overlay(v) => gui.overlay = v,
        Message::Peer(v) => gui.peer = v,
        Message::Listen(v) => gui.listen = v,
        Message::ConfigPath(v) => gui.config_path = v,
        Message::Tap(v) => gui.tap = v,
        Message::Save => {
            match save(gui) {
                Ok(p) => gui.status = format!("Saved {}", p.display()),
                Err(e) => gui.status = format!("Save failed: {}", e)
            }
        }
        Message::Load => {
            match load_into(gui) {
                Ok(()) => gui.status = format!("Loaded {}", gui.config_path),
                Err(e) => gui.status = format!("Load failed: {}", e)
            }
        }
        Message::Connect => {
            connect(gui);
            if gui.worker.is_some() {
                return later_tick();
            }
        }
        Message::Disconnect => disconnect(gui),
        Message::TogglePause => {
            if gui.worker.is_some() {
                let paused = !CtrlC::is_paused();
                CtrlC::set_paused(paused);
                gui.status = if paused { "Paused".into() } else { "Connected".into() };
            }
        }
        Message::Tick => {
            if let Some(w) = gui.worker.as_ref() {
                if w.is_finished() {
                    let w = gui.worker.take().unwrap();
                    match w.join() {
                        Ok(()) => gui.status = "Disconnected".into(),
                        Err(e) => {
                            let msg = panic_message(&e);
                            gui.status = format!("Stopped: {}", msg);
                        }
                    }
                    crate::util::set_fail_panics(false);
                } else {
                    if !CtrlC::is_paused() {
                        gui.status = "Connected".into();
                    }
                    return later_tick();
                }
            }
        }
    }
    Task::none()
}

fn view(gui: &Gui) -> Element<'_, Message> {
    let connected = gui.worker.is_some();
    let fields = column![
        text("VpnCloud").size(22),
        text("Password"),
        text_input("required", &gui.password).secure(true).on_input(Message::Password),
        text("Overlay IP"),
        text_input("10.0.0.1/24", &gui.overlay).on_input(Message::Overlay),
        text("Peers (one per line)"),
        text_input("host:3210", &gui.peer).on_input(Message::Peer),
        text("Listen"),
        text_input("3210", &gui.listen).on_input(Message::Listen),
        text("Device"),
        row![radio("TUN", false, Some(gui.tap), Message::Tap), radio("TAP", true, Some(gui.tap), Message::Tap)]
            .spacing(16),
        text("Config file"),
        text_input("path", &gui.config_path).on_input(Message::ConfigPath),
        row![button("Load").on_press(Message::Load), button("Save").on_press(Message::Save),].spacing(8),
        Space::new().height(8),
        row![if connected {
            button("Disconnect").on_press(Message::Disconnect)
        } else {
            button("Connect").on_press(Message::Connect)
        },]
        .spacing(8),
        checkbox(connected && CtrlC::is_paused()).label("Pause forwarding").on_toggle(|_| Message::TogglePause),
        text(&gui.status).size(14),
    ]
    .spacing(6)
    .padding(16)
    .align_x(Alignment::Start);

    container(scrollable(fields)).width(Length::Fill).height(Length::Fill).into()
}

fn connect(gui: &mut Gui) {
    if gui.worker.is_some() {
        return;
    }
    if gui.password.trim().is_empty() {
        gui.status = "Password is required".into();
        return;
    }
    if let Err(e) = save(gui) {
        gui.status = format!("Save failed: {}", e);
        return;
    }
    let config = match engine_config(gui) {
        Ok(c) => c,
        Err(e) => {
            gui.status = e;
            return;
        }
    };
    CtrlC::clear_stop();
    crate::util::set_fail_panics(true);
    gui.status = "Connecting…".into();
    gui.worker = Some(
        thread::Builder::new()
            .name("vpncloud".into())
            .spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_vpn(config);
                }));
            })
            .expect("spawn vpn worker")
    );
}

fn disconnect(gui: &mut Gui) {
    CtrlC::request_stop();
    gui.status = "Disconnecting…".into();
}

fn engine_config(gui: &Gui) -> Result<Config, String> {
    let mut config = Config::default();
    let path = Path::new(&gui.config_path);
    if path.is_file() {
        let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let file: ConfigFile = serde_norway::from_str(&raw).map_err(|e| e.to_string())?;
        config.merge_file(file);
    }
    config.crypto.password = Some(gui.password.clone());
    let overlay = gui.overlay.trim();
    config.ip = if overlay.is_empty() { None } else { Some(overlay.to_string()) };
    let listen = gui.listen.trim();
    if !listen.is_empty() {
        config.listen = listen.to_string();
    }
    config.device_type = if gui.tap { Type::Tap } else { Type::Tun };
    config.peers = gui.peer.lines().map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
    config.daemonize = false;
    config.tray = false;
    Ok(config)
}

fn save(gui: &Gui) -> io::Result<PathBuf> {
    let path = PathBuf::from(&gui.config_path);
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    fs::write(&path, to_yaml(gui))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn load_into(gui: &mut Gui) -> Result<(), String> {
    let raw = fs::read_to_string(&gui.config_path).map_err(|e| e.to_string())?;
    let file: ConfigFile = serde_norway::from_str(&raw).map_err(|e| e.to_string())?;
    let mut config = Config::default();
    config.merge_file(file);
    gui.password = config.crypto.password.unwrap_or_default();
    gui.overlay = config.ip.unwrap_or_else(|| "10.0.0.1/24".into());
    gui.listen = config.listen;
    gui.tap = config.device_type == Type::Tap;
    gui.peer = config.peers.join("\n");
    Ok(())
}

fn to_yaml(gui: &Gui) -> String {
    let mut file = ConfigFile::default();
    file.crypto = CryptoConfig { password: Some(gui.password.clone()), ..CryptoConfig::default() };
    let overlay = gui.overlay.trim();
    if !overlay.is_empty() {
        file.ip = Some(overlay.to_string());
    }
    let listen = gui.listen.trim();
    if !listen.is_empty() {
        file.listen = Some(listen.to_string());
    }
    file.device = Some(ConfigFileDevice {
        type_: Some(if gui.tap { Type::Tap } else { Type::Tun }),
        name: None,
        path: None,
        fix_rp_filter: None,
        mtu: None
    });
    let peers: Vec<crate::config::PeerAddr> = gui
        .peer
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| crate::config::PeerAddr::from_config_string(s.to_string()))
        .collect();
    if !peers.is_empty() {
        file.peers = Some(peers);
    }
    serde_norway::to_string(&file).unwrap_or_default()
}

fn default_config_path() -> PathBuf {
    if let Some(p) = env::args().nth(1).filter(|s| !s.starts_with('-')) {
        return PathBuf::from(p);
    }
    if let Ok(p) = env::var("VPNCLOUD_CONFIG") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        if let Ok(ad) = env::var("LOCALAPPDATA") {
            return PathBuf::from(ad).join("VpnCloud").join("vpncloud.yaml");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join("Library/Application Support/VpnCloud/vpncloud.yaml");
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("vpncloud/vpncloud.yaml");
        }
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(".config/vpncloud/vpncloud.yaml");
        }
    }
    PathBuf::from("vpncloud.yaml")
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "worker panicked".into()
    }
}

struct GuiLogger;

impl log::Log for GuiLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init_log() {
    let _ = log::set_boxed_logger(Box::new(GuiLogger));
    log::set_max_level(log::LevelFilter::Info);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_roundtrip_password_and_peer() {
        let gui = Gui {
            password: "secret".into(),
            overlay: "10.0.0.2/24".into(),
            peer: "192.0.2.1:3210".into(),
            listen: "3210".into(),
            tap: false,
            config_path: String::new(),
            status: String::new(),
            worker: None
        };
        let yaml = to_yaml(&gui);
        assert!(yaml.contains("password"), "{}", yaml);
        assert!(yaml.contains("10.0.0.2/24"), "{}", yaml);
        assert!(yaml.contains("192.0.2.1:3210"), "{}", yaml);
        assert!(yaml.contains("tun"), "{}", yaml);
        let file: ConfigFile = serde_norway::from_str(&yaml).unwrap();
        assert_eq!(file.crypto.password.as_deref(), Some("secret"));
    }
}
