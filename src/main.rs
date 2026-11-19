// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use clap::{CommandFactory, Parser};

use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex
};

use vpncloud::{
    config::{
        config_format_from_path, load_config_file, load_config_file_with_raw, write_config_file, Args, Command, Config,
        ConfigFormat
    },
    config_verify::{verify_loaded_config, VerifyKeys},
    crypto::Crypto,
    engine::run_vpn,
    oldconfig::OldConfigFile,
    sign
};

#[cfg(feature = "installer")]
use vpncloud::installer;
#[cfg(feature = "wizard")] use vpncloud::wizard;
#[cfg(feature = "websocket")]
use vpncloud::wsproxy;

struct DualLogger {
    file: Option<Mutex<File>>,
    json: bool,
    /// Highest level for each module prefix, parsed from RUST_LOG.
    filters: Vec<(String, log::LevelFilter)>
}

fn parse_level(name: &str) -> Option<log::LevelFilter> {
    match name.trim().to_ascii_lowercase().as_str() {
        "off" => Some(log::LevelFilter::Off),
        "error" => Some(log::LevelFilter::Error),
        "warn" => Some(log::LevelFilter::Warn),
        "info" => Some(log::LevelFilter::Info),
        "debug" => Some(log::LevelFilter::Debug),
        "trace" => Some(log::LevelFilter::Trace),
        _ => None
    }
}

fn parse_log_filters() -> Vec<(String, log::LevelFilter)> {
    let Ok(spec) = std::env::var("RUST_LOG") else { return Vec::new() };
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (target, level) = match part.split_once('=') {
            Some((t, l)) => (t.to_string(), l),
            None => (String::new(), part)
        };
        let level = match level.to_ascii_lowercase().as_str() {
            "off" => log::LevelFilter::Off,
            "error" => log::LevelFilter::Error,
            "warn" => log::LevelFilter::Warn,
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "trace" => log::LevelFilter::Trace,
            _ => continue
        };
        out.push((target, level));
    }
    out
}

impl DualLogger {
    pub fn new<P: AsRef<Path>>(path: Option<P>, json: bool) -> Result<Self, io::Error> {
        if let Some(path) = path {
            let path = path.as_ref();
            // Keep the previous session's log. Rotate once when it grows past
            // 10 MiB so a long-lived node cannot fill the disk.
            const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
            if let Ok(meta) = fs::metadata(path) {
                if meta.len() > MAX_LOG_BYTES {
                    let mut rotated = path.as_os_str().to_os_string();
                    rotated.push(".old");
                    let _ = fs::remove_file(&rotated);
                    let _ = fs::rename(path, &rotated);
                }
            }
            let mut opts = fs::OpenOptions::new();
            opts.append(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // Create private from the start and never follow a symlink:
                // the old remove-then-create sequence was a root symlink race.
                opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let file = opts.open(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
            Ok(DualLogger { file: Some(Mutex::new(file)), json, filters: parse_log_filters() })
        } else {
            Ok(DualLogger { file: None, json, filters: parse_log_filters() })
        }
    }
}

impl log::Log for DualLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if self.filters.is_empty() {
            return true;
        }
        let mut level = log::LevelFilter::Off;
        let mut matched = false;
        for (prefix, filter) in &self.filters {
            if prefix.is_empty() || metadata.target().starts_with(prefix) {
                level = *filter;
                matched = true;
            }
        }
        matched && metadata.level() <= level
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = if self.json {
            serde_json::json!({
                "time": chrono::Utc::now().to_rfc3339(),
                "level": record.level().to_string(),
                "target": record.target(),
                "message": record.args().to_string()
            })
            .to_string()
        } else {
            format!("{} - {}", record.level(), record.args())
        };
        println!("{}", line);
        if let Some(ref file) = self.file {
            // A full disk or a poisoned mutex must never abort the VPN.
            let output = if self.json {
                line.clone()
            } else {
                format!("{} - {}", chrono::Local::now().format("%F %H:%M:%S"), line)
            };
            let result = file
                .lock()
                .map_err(|_| io::Error::other("log lock poisoned"))
                .and_then(|mut guard| writeln!(guard, "{}", output));
            if let Err(e) = result {
                eprintln!("Logging error: {}", e);
            }
        }
    }

    #[inline]
    fn flush(&self) {
        if let Some(ref file) = self.file {
            let mut file = file.lock().expect("Lock poisoned");
            if let Err(err) = file.flush() {
                eprintln!("Logging error: {}", err);
            }
        }
    }
}

fn main() {
    let args: Args = Args::parse();
    if args.version {
        println!("VpnCloud v{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let logger = match DualLogger::new(args.log_file.as_ref(), args.log_json) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to open logfile: {}", e);
            return;
        }
    };
    log::set_boxed_logger(Box::new(logger)).unwrap();
    assert!(args.verbose == 0 || !args.quiet);
    if args.wire_log {
        vpncloud::util::set_wire_log(true);
    }
    let max_level = if let Some(ref level) = args.log_level {
        match parse_level(level) {
            Some(level) => level,
            None => {
                eprintln!("Invalid --log-level '{}' (use off/error/warn/info/debug/trace)", level);
                return;
            }
        }
    } else if args.wire_log || args.verbose >= 2 || std::env::var_os("RUST_LOG").is_some() {
        log::LevelFilter::Trace
    } else if args.verbose == 1 {
        log::LevelFilter::Debug
    } else if args.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    };
    log::set_max_level(max_level);
    if let Some(cmd) = args.cmd {
        match cmd {
            Command::CheckConfig { config_file, verify_signature } => {
                match vpncloud::config::load_config_file_with_raw(Path::new(&config_file)) {
                    Ok((path, raw, file)) => {
                        let mut config = Config::default();
                        config.merge_file(file);
                        let mut problems = Vec::new();
                        match config.validate() {
                            Ok(warnings) => {
                                for w in warnings {
                                    println!("WARN: {}", w);
                                }
                            }
                            Err(e) => problems.push(e)
                        }
                        if verify_signature {
                            match VerifyKeys::from_cli(&args.verify_keys, args.verify_key_file.as_deref()) {
                                Ok(keys) => {
                                    if let Err(e) = verify_loaded_config(&config, Some(&raw), &keys) {
                                        problems.push(e);
                                    }
                                }
                                Err(e) => problems.push(e)
                            }
                        }
                        if problems.is_empty() {
                            println!("Config {} is valid", path.display());
                        } else {
                            for p in &problems {
                                eprintln!("ERROR: {}", p);
                            }
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Command::Network { action } => {
                let result = match action {
                    vpncloud::config::NetworkAction::List => {
                        vpncloud::network::list();
                        Ok(())
                    }
                    vpncloud::config::NetworkAction::Start { name } => vpncloud::network::start(&name),
                    vpncloud::config::NetworkAction::Stop { name } => vpncloud::network::stop(&name),
                    vpncloud::config::NetworkAction::Status { name } => vpncloud::network::status(&name)
                };
                if let Err(e) = result {
                    eprintln!("network: {}", e);
                    std::process::exit(1);
                }
            }
            Command::Doctor { config_file } => {
                let code = vpncloud::doctor::run(config_file.as_deref().map(Path::new));
                if code != 0 {
                    std::process::exit(code);
                }
            }
            Command::Status { status_file, config_file, json } => {
                let path = if let Some(p) = status_file {
                    std::path::PathBuf::from(p)
                } else if let Some(cfg) = config_file {
                    match vpncloud::config::load_config_file(Path::new(&cfg)) {
                        Ok((_, file)) => {
                            let mut config = Config::default();
                            config.merge_file(file);
                            match config.status_file {
                                Some(p) => std::path::PathBuf::from(p),
                                None => {
                                    eprintln!("No status_file configured; pass --status-file or set it in the config");
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to read config: {}", e);
                            return;
                        }
                    }
                } else {
                    eprintln!("Pass --status-file or --config");
                    return;
                };
                match fs::read_to_string(&path) {
                    Ok(raw) => {
                        if json {
                            match serde_json::from_str::<serde_json::Value>(&raw) {
                                Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
                                Err(e) => eprintln!("Invalid status file {}: {}", path.display(), e)
                            }
                        } else {
                            match serde_json::from_str::<vpncloud::runtime_status::FullStatus>(&raw) {
                                Ok(s) => {
                                    println!("Device:   {}", s.device);
                                    println!("Uptime:   {}s", s.uptime_secs);
                                    println!("Peers:    {}", s.peer_count);
                                    println!("Sent:     {} bytes", s.sent_bytes);
                                    println!("Received: {} bytes", s.recv_bytes);
                                    if s.last_handshake_unix > 0 {
                                        println!("Last handshake: {}", s.last_handshake_unix);
                                    }
                                    for p in &s.peers {
                                        let rtt = p.rtt_ms.map(|r| format!("{} ms", r)).unwrap_or_else(|| "n/a".into());
                                        let throttle = if p.throttled > 0 || p.penalty > 0 {
                                            format!(" throttled={} penalty={}", p.throttled, p.penalty)
                                        } else {
                                            String::new()
                                        };
                                        println!("  {} {} rtt={}{}", p.addr, p.node_id, rtt, throttle);
                                    }
                                    if !s.quality.is_empty() {
                                        println!("Estimated quality (best path):");
                                        for q in s.quality.iter().take(10) {
                                            println!("  {} ~{} ms", q.node_id, q.estimated_rtt_ms);
                                        }
                                    }
                                    if let Some(ref relay) = s.suggested_relay {
                                        println!(
                                            "Suggested relay: {} -> {} (~{} ms)",
                                            relay.via_addr, relay.dest_node, relay.estimated_rtt_ms
                                        );
                                    }
                                }
                                Err(e) => eprintln!("Invalid status file {}: {}", path.display(), e)
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "No status available at {} (is VpnCloud running with status_file?): {}",
                            path.display(),
                            e
                        )
                    }
                }
            }
            Command::GenKey { password, out } => {
                let (privkey, pubkey) = Crypto::generate_keypair(password.as_deref());
                if let Some(path) = out {
                    let body = format!("private-key: {}\npublic-key: {}\n", privkey, pubkey);
                    match vpncloud::config::create_private_file(Path::new(&path))
                        .and_then(|mut f| f.write_all(body.as_bytes()))
                    {
                        Ok(()) => println!("Wrote key pair to {} (mode 0600)", path),
                        Err(e) => {
                            eprintln!("Failed to write key file {}: {}", path, e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    println!("Private key: {}\nPublic key: {}\n", privkey, pubkey);
                    println!(
                        "Attention: Keep the private key secret and use only the public key on other nodes to establish trust."
                    );
                }
            }
            Command::SignConfig { config_file, private_key, password } => {
                let path = Path::new(&config_file);
                let raw = match fs::read_to_string(path) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to read {}: {}", config_file, e);
                        return;
                    }
                };
                let body = sign::body_for_signing(&raw);
                let parsed = load_config_file(path).ok().map(|(_, f)| f);
                let privk = private_key.or_else(|| parsed.as_ref().and_then(|f| f.crypto.private_key.clone()));
                let pw = password.or_else(|| parsed.as_ref().and_then(|f| f.crypto.password.clone()));
                let sig = if let Some(ref key) = privk {
                    sign::sign_body(&body, key)
                } else if let Some(ref password) = pw {
                    let salt = parsed.as_ref().and_then(|f| f.crypto.salt.as_deref());
                    let kdf = parsed.as_ref().and_then(|f| f.crypto.kdf.as_deref());
                    sign::sign_with_password(&body, password, salt, kdf)
                } else {
                    log::error!("sign-config needs --private-key or --password (or those fields in the file)");
                    return;
                };
                let sig = match sig {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to sign config: {}", e);
                        return;
                    }
                };
                let toml = config_format_from_path(path) == ConfigFormat::Toml;
                let out = sign::append_signature_line(&raw, &sig, toml);
                match vpncloud::config::create_private_file(path).and_then(|mut f| f.write_all(out.as_bytes())) {
                    Ok(()) => log::info!("Signed {}", config_file),
                    Err(e) => log::error!("Failed to write {}: {}", config_file, e)
                }
            }
            Command::MigrateConfig { config_file } => {
                log::info!("Trying to convert from old config format");
                let f = match File::open(&config_file) {
                    Ok(f) => f,
                    Err(e) => {
                        log::error!("Failed to open config file: {:?}", e);
                        return;
                    }
                };
                let config_file_old: OldConfigFile = match serde_norway::from_reader(f) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("Config file not valid for version 1: {:?}", e);
                        return;
                    }
                };
                let new_config = config_file_old.convert();
                log::info!("Successfully converted from old format");
                log::info!("Renaming original file to {}.orig", config_file);
                if let Err(e) = fs::rename(&config_file, format!("{}.orig", config_file)) {
                    log::error!("Failed to rename original file: {:?}", e);
                    return;
                }
                log::info!("Writing new config back into {}", config_file);
                if let Err(e) = write_config_file(Path::new(&config_file), &new_config) {
                    log::error!("Failed to write converted config: {:?}", e);
                    return;
                }
            }
            Command::Completion { shell } => {
                let mut cmd = Args::command();
                clap_complete::generate(shell, &mut cmd, env!("CARGO_PKG_NAME"), &mut io::stdout());
            }
            #[cfg(feature = "websocket")]
            Command::WsProxy { listen } => {
                if let Err(e) = wsproxy::run_proxy(&listen) {
                    log::error!("Failed to run websocket proxy: {:?}", e);
                }
            }
            #[cfg(feature = "wizard")]
            Command::Config { name, config_file, print } => {
                if print {
                    let path = match config_file {
                        Some(p) => std::path::PathBuf::from(p),
                        None => {
                            eprintln!("--print needs --config FILE");
                            return;
                        }
                    };
                    match vpncloud::config::load_config_file(&path) {
                        Ok((_, file)) => {
                            let mut config = Config::default();
                            config.merge_file(file);
                            print!("{}", config.redacted_yaml());
                        }
                        Err(e) => {
                            eprintln!("Failed to read config: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else if let Err(e) = wizard::configure(name, config_file) {
                    log::error!("Wizard failed: {}", e);
                }
            }
            #[cfg(feature = "installer")]
            Command::Install { uninstall, tray, no_tray, autostart, service, no_service } => {
                let tray = if no_tray {
                    Some(false)
                } else if tray {
                    Some(true)
                } else {
                    None
                };
                let service = if no_service {
                    Some(false)
                } else if service {
                    Some(true)
                } else {
                    None
                };
                let result = installer::install(installer::InstallOpts { uninstall, tray, autostart, service });
                if let Err(e) = result {
                    log::error!("{} failed: {}", if uninstall { "Uninstall" } else { "Install" }, e);
                }
            }
            #[cfg(windows)]
            Command::Service { action } => {
                use vpncloud::config::WindowsServiceAction;
                let result = match action {
                    WindowsServiceAction::Install { config, start } => {
                        let path = config.as_deref().map(std::path::Path::new);
                        vpncloud::winservice::install(path, start)
                    }
                    WindowsServiceAction::Uninstall => vpncloud::winservice::uninstall(),
                    WindowsServiceAction::Start => vpncloud::winservice::start(),
                    WindowsServiceAction::Stop => vpncloud::winservice::stop(),
                    WindowsServiceAction::Reload => vpncloud::winservice::reload()
                };
                if let Err(e) = result {
                    log::error!("Windows service: {}", e);
                }
            }
        }
        return;
    }
    // Capture verification keys before `args` is consumed by `merge_args`.
    // These are deliberately NOT merged into Config: peer trust keys must not
    // become the trust anchor for the file that defines them.
    let verify_key_args = args.verify_keys.clone();
    let verify_key_file_arg = args.verify_key_file.clone();

    let mut config = Config::default();
    let mut raw_config: Option<String> = None;
    if let Some(ref file) = args.config {
        vpncloud::util::CtrlC::set_reload_path(PathBuf::from(file));
        match load_config_file_with_raw(Path::new(file)) {
            Ok((path, raw, config_file)) => {
                log::info!("Reading config file '{}'", path.display());
                raw_config = Some(raw);
                config.merge_file(config_file)
            }
            Err(err) => {
                log::error!("Failed to read config file: {}", err);
                let path = vpncloud::config::resolve_config_path(Path::new(file));
                if config_format_from_path(&path) == ConfigFormat::Yaml {
                    log::info!("Trying to convert from old config format");
                    match fs::read_to_string(&path) {
                        Ok(raw) => {
                            match serde_norway::from_str::<OldConfigFile>(&raw) {
                                Ok(old) => {
                                    log::info!("Successfully converted from old format, please migrate your config using migrate-config");
                                    config.merge_file(old.convert())
                                }
                                Err(e) => {
                                    log::error!("Config file is neither version 2 nor version 1: {:?}", e);
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to open config file: {:?}", e);
                            return;
                        }
                    }
                } else {
                    return;
                }
            }
        }
    }
    #[cfg(windows)]
    let as_service = args.service;
    config.merge_args(args);
    let verify_keys = match VerifyKeys::from_cli(&verify_key_args, verify_key_file_arg.as_deref()) {
        Ok(keys) => keys,
        Err(e) => {
            log::error!("{}", e);
            return;
        }
    };
    // Remember these for SIGHUP reloads so a reloaded config cannot bypass the
    // signature policy enforced at startup.
    vpncloud::config_verify::set_reload_verify_keys(verify_keys.clone());
    if let Err(e) = verify_loaded_config(&config, raw_config.as_deref(), &verify_keys) {
        log::error!("{}", e);
        return;
    }
    match config.validate() {
        Ok(warnings) => {
            for w in warnings {
                log::warn!("Config: {}", w);
            }
        }
        Err(e) => {
            log::error!("Invalid config: {} (run 'vpncloud check-config' for details)", e);
            return;
        }
    }
    if let Some(ref addr) = config.metrics_addr {
        if let Err(e) = vpncloud::metrics::spawn(addr) {
            log::error!("Failed to start metrics endpoint on {}: {}", addr, e);
        } else {
            log::info!("Prometheus metrics on http://{}/metrics", addr);
        }
    }
    // Never log the full Config: it contains password, private key, beacon
    // password, and hook commands. Log only non-secret routing fields.
    log::debug!(
        "Config: type={} listen={} ip={:?} peers={} mtu={:?} mode={:?}",
        config.device_type,
        config.listen,
        config.ip,
        config.peers.len(),
        config.mtu,
        config.mode
    );
    // The menu-bar companion of the launchd service does not run the VPN
    // itself, so it needs no crypto credentials of its own.
    #[cfg(target_os = "macos")]
    if config.tray_controls_service && config.tray {
        run_vpn(config);
        return;
    }
    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        log::error!("Either password or private key must be set in config or given as parameter");
        return;
    }
    #[cfg(windows)]
    if as_service {
        config.tray = false;
        if let Err(e) = vpncloud::winservice::run(config) {
            log::error!("{}", e);
        }
        return;
    }
    // Windows has no in-box TUN/TAP. Offer to download the driver selected by
    // the config when it is missing. In service mode / without a console this
    // is a no-op (or a warning) so nothing blocks.
    #[cfg(windows)]
    {
        use vpncloud::win_driver::{ensure, Ui};
        match ensure(config.device_type, Ui::Console) {
            Ok(true) => {}
            Ok(false) => log::warn!(
                "{} driver not installed; starting the VPN anyway. Run 'vpncloud config' to choose another device type.",
                config.device_type
            ),
            Err(e) => log::error!("Driver setup failed: {}", e)
        }
    }
    run_vpn(config);
}
