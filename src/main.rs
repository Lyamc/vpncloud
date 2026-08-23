// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use clap::{CommandFactory, Parser};

use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
    sync::Mutex
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use vpncloud::{
    config::{
        config_format_from_path, load_config_file, write_config_file, Args, Command, Config, ConfigFormat
    },
    crypto::Crypto,
    engine::run_vpn,
    oldconfig::OldConfigFile
};

#[cfg(feature = "installer")]
use vpncloud::installer;
#[cfg(feature = "websocket")]
use vpncloud::wsproxy;
#[cfg(feature = "wizard")]
use vpncloud::wizard;

struct DualLogger {
    file: Option<Mutex<File>>
}

impl DualLogger {
    pub fn new<P: AsRef<Path>>(path: Option<P>) -> Result<Self, io::Error> {
        if let Some(path) = path {
            let path = path.as_ref();
            if path.exists() {
                fs::remove_file(path)?
            }
            let file = File::create(path)?;
            Ok(DualLogger { file: Some(Mutex::new(file)) })
        } else {
            Ok(DualLogger { file: None })
        }
    }
}

impl log::Log for DualLogger {
    #[inline]
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
            if let Some(ref file) = self.file {
                let mut file = file.lock().expect("Lock poisoned");
                let time = chrono::Local::now().format("%F %H:%M:%S");
                writeln!(file, "{} - {} - {}", time, record.level(), record.args())
                    .expect("Failed to write to logfile");
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
    let logger = match DualLogger::new(args.log_file.as_ref()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to open logfile: {}", e);
            return;
        }
    };
    log::set_boxed_logger(Box::new(logger)).unwrap();
    assert!(!args.verbose || !args.quiet);
    log::set_max_level(if args.verbose {
        log::LevelFilter::Debug
    } else if args.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    });
    if let Some(cmd) = args.cmd {
        match cmd {
            Command::GenKey { password } => {
                let (privkey, pubkey) = Crypto::generate_keypair(password.as_deref());
                println!("Private key: {}\nPublic key: {}\n", privkey, pubkey);
                println!(
                    "Attention: Keep the private key secret and use only the public key on other nodes to establish trust."
                );
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
                #[cfg(unix)]
                if let Err(e) = fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)) {
                    log::error!("Failed to set permissions on file: {:?}", e);
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
            Command::Config { name, config_file } => {
                if let Err(e) = wizard::configure(name, config_file) {
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
                    WindowsServiceAction::Stop => vpncloud::winservice::stop()
                };
                if let Err(e) = result {
                    log::error!("Windows service: {}", e);
                }
            }
        }
        return;
    }
    let mut config = Config::default();
    if let Some(ref file) = args.config {
        match load_config_file(Path::new(file)) {
            Ok((path, config_file)) => {
                log::info!("Reading config file '{}'", path.display());
                config.merge_file(config_file)
            }
            Err(err) => {
                log::error!("Failed to read config file: {}", err);
                let path = vpncloud::config::resolve_config_path(Path::new(file));
                if config_format_from_path(&path) == ConfigFormat::Yaml {
                    log::info!("Trying to convert from old config format");
                    match fs::read_to_string(&path) {
                        Ok(raw) => match serde_norway::from_str::<OldConfigFile>(&raw) {
                            Ok(old) => {
                                log::info!("Successfully converted from old format, please migrate your config using migrate-config");
                                config.merge_file(old.convert())
                            }
                            Err(e) => {
                                log::error!("Config file is neither version 2 nor version 1: {:?}", e);
                                return;
                            }
                        },
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
    log::debug!("Config: {:?}", config);
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
    run_vpn(config);
}
