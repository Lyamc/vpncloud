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
    config::{Args, Command, Config},
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
                let f = match File::create(&config_file) {
                    Ok(f) => f,
                    Err(e) => {
                        log::error!("Failed to open config file: {:?}", e);
                        return;
                    }
                };
                #[cfg(unix)]
                if let Err(e) = fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)) {
                    log::error!("Failed to set permissions on file: {:?}", e);
                    return;
                }
                if let Err(e) = serde_norway::to_writer(f, &new_config) {
                    log::error!("Failed to write converted config: {:?}", e);
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
            Command::Install { uninstall } => {
                let result = if uninstall { installer::uninstall() } else { installer::install() };
                if let Err(e) = result {
                    log::error!("{} failed: {}", if uninstall { "Uninstall" } else { "Install" }, e);
                }
            }
        }
        return;
    }
    let mut config = Config::default();
    if let Some(ref file) = args.config {
        log::info!("Reading config file '{}'", file);
        let f = match File::open(file) {
            Ok(f) => f,
            Err(e) => {
                log::error!("Failed to open config file: {:?}", e);
                return;
            }
        };
        let config_file = match serde_norway::from_reader(f) {
            Ok(config) => config,
            Err(err) => {
                log::error!("Failed to read config file: {}", err);
                log::info!("Trying to convert from old config format");
                let f = match File::open(file) {
                    Ok(f) => f,
                    Err(e) => {
                        log::error!("Failed to open config file: {:?}", e);
                        return;
                    }
                };
                match serde_norway::from_reader::<_, OldConfigFile>(f) {
                    Ok(old) => {
                        log::info!("Successfully converted from old format, please migrate your config using migrate-config");
                        old.convert()
                    }
                    Err(e) => {
                        log::error!("Config file is neither version 2 nor version 1: {:?}", e);
                        return;
                    }
                }
            }
        };
        config.merge_file(config_file)
    }
    config.merge_args(args);
    log::debug!("Config: {:?}", config);
    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        log::error!("Either password or private key must be set in config or given as parameter");
        return;
    }
    run_vpn(config);
}
