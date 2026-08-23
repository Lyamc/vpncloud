// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Windows Service Control Manager: run as a service and install/uninstall.

use std::{
    env, fs, io,
    mem,
    path::{Path, PathBuf},
    ptr,
    sync::Mutex,
    thread,
    time::Duration
};

use windows_sys::Win32::{
    Foundation::GetLastError,
    System::Services::{
        ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
        OpenSCManagerW, OpenServiceW, RegisterServiceCtrlHandlerExW, SetServiceStatus,
        StartServiceCtrlDispatcherW, StartServiceW, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
        SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_RUNNING,
        SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
        SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP
    }
};

use crate::{config::Config, engine::run_vpn_worker, error::Error, util::CtrlC};

pub const SERVICE_NAME: &str = "VpnCloud";
pub const SERVICE_DISPLAY: &str = "VpnCloud P2P VPN";
pub const SERVICE_DESC: &str = "Peer-to-peer mesh VPN over UDP.";

static SERVICE_CONFIG: Mutex<Option<Config>> = Mutex::new(None);
static STATUS_HANDLE: Mutex<SERVICE_STATUS_HANDLE> = Mutex::new(0);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn win_err(msg: &str) -> Error {
    let code = unsafe { GetLastError() };
    Error::FileIo(msg, io::Error::from_raw_os_error(code as i32))
}

fn set_status(handle: SERVICE_STATUS_HANDLE, state: u32, accept: u32, wait_hint_ms: u32) {
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accept,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms
    };
    unsafe {
        SetServiceStatus(handle, &mut status);
    }
}

unsafe extern "system" fn ctrl_handler(ctrl: u32, _event: u32, _data: *mut core::ffi::c_void, _ctx: *mut core::ffi::c_void) -> u32 {
    match ctrl {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            if let Ok(h) = STATUS_HANDLE.lock() {
                set_status(*h, SERVICE_STOP_PENDING, 0, 10_000);
            }
            CtrlC::request_stop();
            0
        }
        _ => 0
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(SERVICE_NAME);
    let handle = RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(ctrl_handler), ptr::null_mut());
    if handle == 0 {
        error!("RegisterServiceCtrlHandlerEx failed: {}", unsafe { GetLastError() });
        return;
    }
    *STATUS_HANDLE.lock().expect("status handle") = handle;
    set_status(handle, SERVICE_START_PENDING, 0, 5000);

    let config = SERVICE_CONFIG.lock().expect("service config").take();
    let Some(mut config) = config else {
        set_status(handle, SERVICE_STOPPED, 0, 0);
        return;
    };
    config.tray = false;
    config.daemonize = false;

    set_status(handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0);
    info!("Windows service running");
    let worker = thread::Builder::new()
        .name("vpncloud".into())
        .spawn(move || run_vpn_worker(config));
    match worker {
        Ok(h) => {
            let _ = h.join();
        }
        Err(e) => error!("Failed to start VPN worker: {}", e)
    }
    set_status(handle, SERVICE_STOPPED, 0, 0);
    info!("Windows service stopped");
}

/// Called from `main` when launched by the Service Control Manager (`--service`).
pub fn run(config: Config) -> Result<(), Error> {
    *SERVICE_CONFIG.lock().expect("service config") = Some(config);
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: ptr::null_mut(), lpServiceProc: None }
    ];
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        return Err(win_err(
            "StartServiceCtrlDispatcher failed (run with --service only from the Service Control Manager)"
        ));
    }
    Ok(())
}

pub fn default_config_path() -> PathBuf {
    let program_data = env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    PathBuf::from(program_data).join("VpnCloud").join("vpncloud.yaml")
}

pub fn default_log_path() -> PathBuf {
    let program_data = env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    PathBuf::from(program_data).join("VpnCloud").join("vpncloud.log")
}

pub fn default_bin_path() -> PathBuf {
    let pf = env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    PathBuf::from(pf).join("VpnCloud").join("vpncloud.exe")
}

/// Register the current executable as a LocalSystem auto-start service. Requires Administrator.
pub fn install(config_path: Option<&Path>, start_now: bool) -> Result<(), Error> {
    let cfg_path = config_path.map(Path::to_path_buf).unwrap_or_else(default_config_path);
    if let Some(parent) = cfg_path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::FileIo("Failed to create service config folder", e))?;
    }
    if !cfg_path.exists() {
        fs::write(
            &cfg_path,
            "# Generated by vpncloud service install\nlisten: 3210\ntray: false\n"
        )
        .map_err(|e| Error::FileIo("Failed to write service config", e))?;
        info!("Wrote {}", cfg_path.display());
    }

    let exe_src = env::current_exe().map_err(|e| Error::FileIo("current_exe", e))?;
    let exe_dest = default_bin_path();
    if let Some(parent) = exe_dest.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::FileIo("Failed to create Program Files\\VpnCloud", e))?;
    }
    fs::copy(&exe_src, &exe_dest).map_err(|e| {
        Error::FileIo(
            "Failed to copy vpncloud.exe (run as Administrator to install into Program Files)",
            e
        )
    })?;

    let log_path = default_log_path();
    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let bin = format!(
        "\"{}\" --service --config \"{}\" --log-file \"{}\"",
        exe_dest.display(),
        cfg_path.display(),
        log_path.display()
    );
    create_scm_service(&bin)?;
    info!(
        "Installed Windows service '{}' (auto-start, LocalSystem). Config: {}",
        SERVICE_NAME,
        cfg_path.display()
    );
    info!("Start:  sc start {}   or   vpncloud service start", SERVICE_NAME);
    info!("Stop:   sc stop {}    or   vpncloud service stop", SERVICE_NAME);
    if start_now {
        start()?;
    }
    Ok(())
}

fn create_scm_service(bin_path: &str) -> Result<(), Error> {
    let mut name = wide(SERVICE_NAME);
    let mut display = wide(SERVICE_DISPLAY);
    let mut bin = wide(bin_path);
    let mut desc_text = wide(SERVICE_DESC);

    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm == 0 {
            return Err(win_err(
                "OpenSCManager failed. Run as Administrator: vpncloud service install"
            ));
        }
        let existing = OpenServiceW(scm, name.as_ptr(), SERVICE_ALL_ACCESS);
        if existing != 0 {
            DeleteService(existing);
            CloseServiceHandle(existing);
        }
        let svc = CreateServiceW(
            scm,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            bin.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null()
        );
        if svc == 0 {
            CloseServiceHandle(scm);
            return Err(win_err("CreateService failed"));
        }
        let mut desc = SERVICE_DESCRIPTIONW { lpDescription: desc_text.as_mut_ptr() };
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &mut desc as *mut _ as *mut _);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
    Ok(())
}

pub fn uninstall() -> Result<(), Error> {
    let _ = stop();
    let name = wide(SERVICE_NAME);
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm == 0 {
            return Err(win_err("OpenSCManager failed. Run as Administrator: vpncloud service uninstall"));
        }
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_ALL_ACCESS);
        if svc == 0 {
            let code = GetLastError();
            CloseServiceHandle(scm);
            if code == 1060 {
                info!("Service '{}' was not registered", SERVICE_NAME);
                return Ok(());
            }
            return Err(win_err("OpenService failed"));
        }
        if DeleteService(svc) == 0 {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return Err(win_err("DeleteService failed"));
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
    info!("Removed Windows service '{}'", SERVICE_NAME);
    Ok(())
}

pub fn start() -> Result<(), Error> {
    let name = wide(SERVICE_NAME);
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm == 0 {
            return Err(win_err("OpenSCManager failed. Run as Administrator."));
        }
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_START);
        if svc == 0 {
            CloseServiceHandle(scm);
            return Err(win_err("OpenService failed"));
        }
        let ok = StartServiceW(svc, 0, ptr::null());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err(win_err("StartService failed"));
        }
    }
    info!("Started service '{}'", SERVICE_NAME);
    Ok(())
}

pub fn stop() -> Result<(), Error> {
    let name = wide(SERVICE_NAME);
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm == 0 {
            return Err(win_err("OpenSCManager failed. Run as Administrator."));
        }
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_STOP);
        if svc == 0 {
            CloseServiceHandle(scm);
            return Err(win_err("OpenService failed"));
        }
        let mut status: SERVICE_STATUS = mem::zeroed();
        let ok = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err(win_err("ControlService STOP failed"));
        }
    }
    thread::sleep(Duration::from_millis(300));
    info!("Stopped service '{}'", SERVICE_NAME);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SERVICE_NAME;

    #[test]
    fn service_name_is_vpncloud() {
        assert_eq!(SERVICE_NAME, "VpnCloud");
    }
}
