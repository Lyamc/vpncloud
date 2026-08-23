// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! OS service install/start/stop via the `service-manager` crate.
//!
//! Not forked. Gaps we keep here:
//! - systemd `.target` files (the crate always uses a `.service` suffix)
//! - copies under `/lib/systemd/system` (crate writes `/etc/systemd/system`)
//! - Windows display name + description (`sc create` has no description field)
//! - reinstall-over-existing (`sc create` fails if the service already exists)
//!
//! The Windows *process* (`StartServiceCtrlDispatcher`) stays in `winservice`.

pub const WIN_SERVICE: &str = "VpnCloud";
pub const WIN_DISPLAY: &str = "VpnCloud P2P VPN";
pub const WIN_DESC: &str = "Peer-to-peer mesh VPN over UDP.";
pub const MAC_LABEL: &str = "ca.witherow.vpncloud";
pub const BSD_LABEL: &str = "vpncloud";
pub const LINUX_TEMPLATE: &str = "vpncloud@";
pub const LINUX_WSPROXY: &str = "vpncloud-wsproxy";

#[cfg(any(feature = "installer", windows))]
mod manager {
    use super::*;
    use crate::error::Error;
    use service_manager::{
        LaunchdServiceManager, RcdServiceManager, RestartPolicy, ScServiceManager, ServiceInstallCtx, ServiceLabel,
        ServiceManager, ServiceStartCtx, ServiceStopCtx, ServiceUninstallCtx, SystemdServiceManager,
        TypedServiceManager
    };
    use std::{
        ffi::OsString,
        io,
        path::{Path, PathBuf},
        process::Command,
        str::FromStr
    };

    const LINUX_LIB: &str = "/lib/systemd/system";

    fn map_err(msg: &'static str, e: io::Error) -> Error {
        Error::FileIo(msg, e)
    }

    fn label(s: &str) -> ServiceLabel {
        ServiceLabel::from_str(s).expect("service label")
    }

    fn never() -> RestartPolicy {
        RestartPolicy::Never
    }

    fn on_failure() -> RestartPolicy {
        RestartPolicy::OnFailure { delay_secs: Some(5), max_retries: None, reset_after_secs: None }
    }

    fn ctx(
        name: &str, program: PathBuf, args: Vec<OsString>, contents: Option<String>, autostart: bool,
        restart: RestartPolicy
    ) -> ServiceInstallCtx {
        ServiceInstallCtx {
            label: label(name),
            program,
            args,
            contents,
            username: None,
            working_directory: None,
            environment: None,
            autostart,
            restart_policy: restart
        }
    }

    fn write_lib_unit(name: &str, body: &str, err: &'static str) -> Result<(), Error> {
        std::fs::write(format!("{}/{}", LINUX_LIB, name), body.as_bytes()).map_err(|e| map_err(err, e))
    }

    /// Install systemd template + ws-proxy via the crate; write `.target` ourselves.
    /// Also copies units to `/lib/systemd/system` so existing docs and cargo-deb still apply.
    pub fn install_systemd(template: &str, target: &str, wsproxy: &str) -> Result<(), Error> {
        let mgr = SystemdServiceManager::system();
        let bin = PathBuf::from("/usr/bin/vpncloud");
        mgr.install(ctx(LINUX_TEMPLATE, bin.clone(), vec![], Some(template.to_string()), false, on_failure()))
            .map_err(|e| map_err("Failed to install systemd unit", e))?;
        mgr.install(ctx(LINUX_WSPROXY, bin, vec![], Some(wsproxy.to_string()), false, on_failure()))
            .map_err(|e| map_err("Failed to install wsproxy systemd unit", e))?;

        let etc = service_manager::systemd_global_dir_path();
        std::fs::create_dir_all(&etc).map_err(|e| map_err("Failed to create systemd unit dir", e))?;
        std::fs::write(etc.join("vpncloud.target"), target.as_bytes())
            .map_err(|e| map_err("Failed to create service target file", e))?;

        std::fs::create_dir_all(LINUX_LIB).map_err(|e| map_err("Failed to create systemd unit dir", e))?;
        write_lib_unit("vpncloud@.service", template, "Failed to create service file")?;
        write_lib_unit("vpncloud.target", target, "Failed to create service target file")?;
        write_lib_unit("vpncloud-wsproxy.service", wsproxy, "Failed to create wsproxy service file")?;

        let _ = Command::new("systemctl").arg("daemon-reload").status();
        Ok(())
    }

    pub fn uninstall_systemd() -> Result<(), Error> {
        let mgr = SystemdServiceManager::system();
        let _ = mgr.uninstall(ServiceUninstallCtx { label: label(LINUX_WSPROXY) });
        let _ = mgr.uninstall(ServiceUninstallCtx { label: label(LINUX_TEMPLATE) });
        let etc = service_manager::systemd_global_dir_path();
        let _ = std::fs::remove_file(etc.join("vpncloud.target"));
        let _ = std::fs::remove_file(format!("{}/vpncloud@.service", LINUX_LIB));
        let _ = std::fs::remove_file(format!("{}/vpncloud.target", LINUX_LIB));
        let _ = std::fs::remove_file(format!("{}/vpncloud-wsproxy.service", LINUX_LIB));
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        Ok(())
    }

    fn launchd_plist(program: &Path, config: &Path) -> String {
        // Custom contents: the crate's generated plist sets Disabled=true whenever KeepAlive is
        // used, which blocks RunAtLoad until an explicit start(). We want a normal LaunchDaemon.
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{}</string>
		<string>--config</string>
		<string>{}</string>
	</array>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>RunAtLoad</key>
	<false/>
</dict>
</plist>
"#,
            MAC_LABEL,
            program.display(),
            config.display()
        )
    }

    /// macOS LaunchDaemon (system, because TUN needs root). Does not start until launchctl start.
    pub fn install_launchd(program: PathBuf, config: PathBuf) -> Result<(), Error> {
        let mgr = LaunchdServiceManager::system();
        let plist = launchd_plist(&program, &config);
        let args = vec![OsString::from("--config"), config.into_os_string()];
        mgr.install(ctx(MAC_LABEL, program, args, Some(plist), false, on_failure()))
            .map_err(|e| map_err("Failed to install LaunchDaemon", e))
    }

    pub fn uninstall_launchd() -> Result<(), Error> {
        let mgr = LaunchdServiceManager::system();
        mgr.uninstall(ServiceUninstallCtx { label: label(MAC_LABEL) })
            .map_err(|e| map_err("Failed to uninstall LaunchDaemon", e))
    }

    fn rcd_script(program: &Path, config: &Path) -> String {
        format!(
            r#"#!/bin/sh
#
# PROVIDE: vpncloud
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="vpncloud"
desc="Peer-to-peer VPN"
rcvar="vpncloud_enable"

load_rc_config $name

: ${{vpncloud_enable:="NO"}}
: ${{vpncloud_config="{config}"}}
: ${{vpncloud_flags:=""}}

pidfile="/var/run/${{name}}.pid"
procname="{program}"
command="/usr/sbin/daemon"
command_args="-c -f -p ${{pidfile}} ${{procname}} --config ${{vpncloud_config}} ${{vpncloud_flags}}"

vpncloud_prestart()
{{
	kldstat -q -m if_tuntap || kldstat -q -m if_tun || kldload if_tuntap || kldload if_tun || true
}}
start_precmd="vpncloud_prestart"

run_rc_command "$1"
"#,
            program = program.display(),
            config = config.display()
        )
    }

    /// FreeBSD rc.d script under `/usr/local/etc/rc.d`. Does not enable or start the service.
    pub fn install_rcd(program: PathBuf, config: PathBuf) -> Result<(), Error> {
        let mgr = RcdServiceManager::system();
        let script = rcd_script(&program, &config);
        let args = vec![OsString::from("--config"), config.into_os_string()];
        mgr.install(ctx(BSD_LABEL, program, args, Some(script), false, never()))
            .map_err(|e| map_err("Failed to install rc.d script", e))
    }

    pub fn uninstall_rcd() -> Result<(), Error> {
        let mgr = RcdServiceManager::system();
        let _ = mgr.uninstall(ServiceUninstallCtx { label: label(BSD_LABEL) });
        let _ = std::fs::remove_file("/usr/local/etc/rc.d/vpncloud");
        Ok(())
    }

    /// Windows `sc.exe` create/start/stop/delete. Display name and description are extra `sc` calls
    /// because the crate's `sc create` has no field for them. Uninstall first so reinstall works.
    pub fn install_windows(program: PathBuf, args: Vec<OsString>) -> Result<(), Error> {
        let mgr = ScServiceManager::system();
        let l = label(WIN_SERVICE);
        let _ = mgr.stop(ServiceStopCtx { label: l.clone() });
        let _ = mgr.uninstall(ServiceUninstallCtx { label: l.clone() });
        mgr.install(ctx(WIN_SERVICE, program, args, None, true, never())).map_err(|e| {
            map_err("Failed to install Windows service (run as Administrator: vpncloud service install)", e)
        })?;
        let _ = Command::new("sc.exe").args(["description", WIN_SERVICE, WIN_DESC]).status();
        let _ = Command::new("sc.exe").args(["config", WIN_SERVICE, "displayname=", WIN_DISPLAY]).status();
        Ok(())
    }

    pub fn uninstall_windows() -> Result<(), Error> {
        let mgr = ScServiceManager::system();
        let l = label(WIN_SERVICE);
        let _ = mgr.stop(ServiceStopCtx { label: l.clone() });
        match mgr.uninstall(ServiceUninstallCtx { label: l }) {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("1060") || msg.to_ascii_lowercase().contains("does not exist") {
                    Ok(())
                } else {
                    Err(map_err(
                        "Failed to uninstall Windows service (run as Administrator: vpncloud service uninstall)",
                        e
                    ))
                }
            }
        }
    }

    pub fn start_windows() -> Result<(), Error> {
        ScServiceManager::system()
            .start(ServiceStartCtx { label: label(WIN_SERVICE) })
            .map_err(|e| map_err("Failed to start Windows service (run as Administrator)", e))
    }

    pub fn stop_windows() -> Result<(), Error> {
        ScServiceManager::system()
            .stop(ServiceStopCtx { label: label(WIN_SERVICE) })
            .map_err(|e| map_err("Failed to stop Windows service (run as Administrator)", e))
    }

    pub fn native_kind_is_systemd() -> bool {
        TypedServiceManager::native().map(|m| m.is_systemd()).unwrap_or(false)
    }

    pub fn native_kind_is_launchd() -> bool {
        TypedServiceManager::native().map(|m| m.is_launchd()).unwrap_or(false)
    }

    pub fn native_kind_is_rcd() -> bool {
        TypedServiceManager::native().map(|m| m.is_rc_d()).unwrap_or(false)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn systemd_template_label_keeps_at_sign() {
            let l = label(LINUX_TEMPLATE);
            assert_eq!(l.to_script_name(), "vpncloud@");
        }

        #[test]
        fn windows_label_is_bare_name() {
            let l = label(WIN_SERVICE);
            assert_eq!(l.to_qualified_name(), "VpnCloud");
        }

        #[test]
        fn macos_label_is_reverse_dns() {
            let l = label(MAC_LABEL);
            assert_eq!(l.to_qualified_name(), "ca.witherow.vpncloud");
        }

        #[test]
        fn freebsd_label_is_bare_name() {
            let l = label(BSD_LABEL);
            assert_eq!(l.to_script_name(), "vpncloud");
        }

        #[test]
        fn rcd_script_is_rc_subr() {
            let script =
                rcd_script(Path::new("/usr/local/bin/vpncloud"), Path::new("/usr/local/etc/vpncloud/vpncloud.yaml"));
            assert!(script.contains("PROVIDE: vpncloud"));
            assert!(script.contains("/etc/rc.subr"));
            assert!(script.contains("vpncloud_enable"));
            assert!(script.contains("/usr/sbin/daemon"));
            assert!(script.contains("/usr/local/bin/vpncloud"));
            assert!(script.contains("/usr/local/etc/vpncloud/vpncloud.yaml"));
            assert!(script.contains("kldload if_tuntap"));
            assert!(!script.contains("--daemon"));
        }

        #[test]
        fn launchd_plist_keeps_keepalive_without_disabled() {
            let plist = launchd_plist(Path::new("/usr/bin/vpncloud"), Path::new("/etc/vpncloud/vpncloud.yaml"));
            assert!(plist.contains(MAC_LABEL));
            assert!(plist.contains("/usr/bin/vpncloud"));
            assert!(plist.contains("/etc/vpncloud/vpncloud.yaml"));
            assert!(plist.contains("KeepAlive"));
            assert!(!plist.contains("Disabled"));
        }

        #[test]
        fn shipped_units_keep_template_target_and_wsproxy() {
            let template = include_str!("../assets/vpncloud@.service");
            assert!(template.contains("PartOf=vpncloud.target"));
            assert!(template.contains("/etc/vpncloud/%i.net"));
            assert!(template.contains("Restart=on-failure"));
            let target = include_str!("../assets/vpncloud.target");
            assert!(target.contains("vpncloud@.service"));
            let ws = include_str!("../assets/vpncloud-wsproxy.service");
            assert!(ws.contains("ws-proxy"));
            assert!(ws.contains("WantedBy=multi-user.target"));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn native_manager_is_launchd_on_macos() {
            assert!(native_kind_is_launchd());
            assert!(!native_kind_is_systemd());
        }

        #[cfg(target_os = "freebsd")]
        #[test]
        fn native_manager_is_rcd_on_freebsd() {
            assert!(native_kind_is_rcd());
            assert!(!native_kind_is_systemd());
            assert!(!native_kind_is_launchd());
        }
    }
} // manager

#[cfg(any(feature = "installer", windows))]
pub use manager::*;
