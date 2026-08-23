// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Windows system tray: Enable / Disable / Open config / Exit.

use std::{
    env,
    mem,
    process::Command,
    ptr,
    sync::Mutex,
    thread::{self, JoinHandle}
};

use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Shell::{
            Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
            NOTIFYICONDATAW
        },
        WindowsAndMessaging::{
            AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
            DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW,
            PostQuitMessage, RegisterClassW, SetForegroundWindow, TrackPopupMenu,
            TranslateMessage, CS_HREDRAW, CS_VREDRAW, IDI_APPLICATION, MF_GRAYED, MF_SEPARATOR,
            MF_STRING, MSG, TPM_RIGHTBUTTON, TPM_RETURNCMD, WM_DESTROY, WM_LBUTTONDBLCLK,
            WM_RBUTTONUP, WM_USER, WNDCLASSW, WS_OVERLAPPEDWINDOW
        }
    }
};

use crate::{config::Config, util::CtrlC};

const WM_TRAY: u32 = WM_USER + 1;
const ID_ENABLE: usize = 1;
const ID_DISABLE: usize = 2;
const ID_OPEN_CONFIG: usize = 3;
const ID_EXIT: usize = 4;
const TRAY_ID: u32 = 1;

struct TrayRuntime {
    config: Config,
    worker: Option<JoinHandle<()>>
}

static RUNTIME: Mutex<Option<TrayRuntime>> = Mutex::new(None);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn copy_tip(dest: &mut [u16], s: &str) {
    let v: Vec<u16> = s.encode_utf16().take(dest.len().saturating_sub(1)).collect();
    dest[..v.len()].copy_from_slice(&v);
    if v.len() < dest.len() {
        dest[v.len()] = 0;
    }
}

fn spawn_worker(config: Config) -> JoinHandle<()> {
    CtrlC::clear_stop();
    thread::Builder::new()
        .name("vpncloud".into())
        .spawn(move || crate::engine::run_vpn_worker(config))
        .expect("spawn vpn worker")
}

fn notify(hwnd: HWND, add: bool, tip: &str) {
    unsafe {
        let mut nid: NOTIFYICONDATAW = mem::zeroed();
        nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ID;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY;
        nid.hIcon = LoadIconW(ptr::null_mut(), IDI_APPLICATION);
        copy_tip(&mut nid.szTip, tip);
        Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &nid);
    }
}

fn remove_icon(hwnd: HWND) {
    unsafe {
        let mut nid: NOTIFYICONDATAW = mem::zeroed();
        nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ID;
        Shell_NotifyIconW(NIM_DELETE, &nid);
    }
}

fn tooltip() -> String {
    if CtrlC::is_paused() {
        "VpnCloud (disabled)".into()
    } else {
        "VpnCloud (enabled)".into()
    }
}

fn show_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let paused = CtrlC::is_paused();
        let status = wide(if paused { "Status: Disabled" } else { "Status: Enabled" });
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, status.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        let en = wide("Enable");
        let dis = wide("Disable");
        AppendMenuW(menu, MF_STRING | if paused { 0 } else { MF_GRAYED }, ID_ENABLE, en.as_ptr());
        AppendMenuW(menu, MF_STRING | if paused { MF_GRAYED } else { 0 }, ID_DISABLE, dis.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        let open = wide("Open config folder");
        AppendMenuW(menu, MF_STRING, ID_OPEN_CONFIG, open.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        let exit = wide("Exit");
        AppendMenuW(menu, MF_STRING, ID_EXIT, exit.as_ptr());

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, ptr::null());
        DestroyMenu(menu);
        match cmd as usize {
            ID_ENABLE => {
                CtrlC::set_paused(false);
                notify(hwnd, false, &tooltip());
                info!("Tray: VPN enabled");
            }
            ID_DISABLE => {
                CtrlC::set_paused(true);
                notify(hwnd, false, &tooltip());
                info!("Tray: VPN disabled");
            }
            ID_OPEN_CONFIG => open_config_folder(),
            ID_EXIT => {
                CtrlC::request_stop();
                DestroyWindow(hwnd);
            }
            _ => {}
        }
    }
}

fn open_config_folder() {
    let dir = env::var_os("LOCALAPPDATA")
        .map(|p| std::path::PathBuf::from(p).join("VpnCloud"))
        .filter(|p| p.exists())
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| ".".into()));
    let _ = Command::new("explorer").arg(dir).spawn();
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            let event = lparam as u32;
            if event == WM_RBUTTONUP {
                show_menu(hwnd);
            } else if event == WM_LBUTTONDBLCLK {
                let paused = CtrlC::is_paused();
                CtrlC::set_paused(!paused);
                notify(hwnd, false, &tooltip());
            }
            0
        }
        WM_DESTROY => {
            remove_icon(hwnd);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

/// Block on the tray message loop. The VPN worker runs on a background thread.
pub fn run(config: Config) {
    info!("Starting Windows system tray (Enable / Disable / Exit)");
    let worker = spawn_worker(config.clone());
    *RUNTIME.lock().expect("tray runtime") = Some(TrayRuntime { config, worker: Some(worker) });

    unsafe {
        let class = wide("VpnCloudTray");
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: GetModuleHandleW(ptr::null()),
            hIcon: LoadIconW(ptr::null_mut(), IDI_APPLICATION),
            hCursor: ptr::null_mut(),
            hbrBackground: ptr::null_mut(),
            lpszMenuName: ptr::null(),
            lpszClassName: class.as_ptr()
        };
        RegisterClassW(&wc);
        let title = wide("VpnCloud");
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            GetModuleHandleW(ptr::null()),
            ptr::null()
        );
        if hwnd.is_null() {
            error!("Failed to create tray window");
            CtrlC::request_stop();
        } else {
            notify(hwnd, true, &tooltip());
            let mut msg = mem::zeroed::<MSG>();
            while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    CtrlC::request_stop();
    if let Some(rt) = RUNTIME.lock().expect("tray runtime").take() {
        if let Some(worker) = rt.worker {
            let _ = worker.join();
        }
    }
}
