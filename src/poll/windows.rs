// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021 Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Windows wait loop: WSA events for UDP plus a blocking tun-rs reader thread.
//!
//! TUN uses **wintun** (`wintun.dll` next to the executable). TAP uses **tap-windows6**
//! (OpenVPN TAP driver, hardware id `tap0901`). Both require Administrator.

use std::{
    collections::VecDeque,
    io,
    net::UdpSocket,
    os::windows::io::{AsRawSocket, RawSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex
    },
    thread::{self, JoinHandle},
    time::Duration
};

use super::WaitResult;
use windows_sys::Win32::{
    Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Networking::WinSock::{
        WSACloseEvent, WSACreateEvent, WSAEnumNetworkEvents, WSAEventSelect, FD_CLOSE, FD_READ, SOCKET, WSAEVENT,
        WSANETWORKEVENTS
    },
    System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects}
};

const SOCKET_SLOT: u32 = WAIT_OBJECT_0;
const DEVICE_SLOT: u32 = WAIT_OBJECT_0 + 1;

/// Source of a blocking TUN/TAP read used by the waiter thread.
pub struct WindowsDeviceSource {
    pub recv: Arc<dyn Fn(&mut [u8]) -> io::Result<usize> + Send + Sync>,
    pub queue: Arc<Mutex<VecDeque<Vec<u8>>>>
}

pub trait Pollable: Send + Sync {
    fn wait_socket(&self) -> Option<RawSocket> {
        None
    }

    fn wait_device(&self) -> Option<WindowsDeviceSource> {
        None
    }
}

impl Pollable for UdpSocket {
    fn wait_socket(&self) -> Option<RawSocket> {
        Some(self.as_raw_socket())
    }
}

impl Pollable for std::net::TcpStream {
    fn wait_socket(&self) -> Option<RawSocket> {
        Some(self.as_raw_socket())
    }
}

fn wsa_event_invalid(ev: WSAEVENT) -> bool {
    ev as usize == 0
}

pub struct WaitImpl {
    socket: SOCKET,
    socket_event: WSAEVENT,
    device_event: HANDLE,
    device_socket: Option<SOCKET>,
    device_wsa: Option<WSAEVENT>,
    handles: [HANDLE; 2],
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    timeout_ms: u32,
    stop: Arc<AtomicBool>,
    _thread: Option<JoinHandle<()>>
}

impl WaitImpl {
    pub fn new(socket: &impl Pollable, device: &impl Pollable, timeout: u32) -> io::Result<Self> {
        let raw_socket = socket.wait_socket().ok_or_else(|| io::Error::other("Windows poll requires a socket"))?;

        unsafe {
            let socket_event = WSACreateEvent();
            if wsa_event_invalid(socket_event) {
                return Err(io::Error::last_os_error());
            }
            let rc = WSAEventSelect(raw_socket as SOCKET, socket_event, (FD_READ | FD_CLOSE) as i32);
            if rc != 0 {
                WSACloseEvent(socket_event);
                return Err(io::Error::last_os_error());
            }

            if let Some(source) = device.wait_device() {
                let device_event = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
                if device_event.is_null() {
                    WSACloseEvent(socket_event);
                    return Err(io::Error::last_os_error());
                }

                let stop = Arc::new(AtomicBool::new(false));
                let queue = source.queue.clone();
                let recv = source.recv.clone();
                let stop_t = stop.clone();
                let queue_t = queue.clone();
                // windows-sys 0.61 HANDLE is a raw pointer (not Send). Pass it as usize.
                let ev_bits = device_event as usize;

                let thread = thread::Builder::new().name("vpncloud-wintun".into()).spawn(move || {
                    let mut buf = vec![0u8; 65535];
                    while !stop_t.load(Ordering::Relaxed) {
                        match (recv)(&mut buf) {
                            Ok(n) => {
                                queue_t.lock().expect("device queue").push_back(buf[..n].to_vec());
                                let _ = SetEvent(ev_bits as HANDLE);
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => {
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => {
                                if stop_t.load(Ordering::Relaxed) {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(20));
                            }
                        }
                    }
                })?;

                return Ok(Self {
                    socket: raw_socket as SOCKET,
                    socket_event,
                    device_event,
                    device_socket: None,
                    device_wsa: None,
                    handles: [socket_event as HANDLE, device_event],
                    queue,
                    timeout_ms: timeout,
                    stop,
                    _thread: Some(thread)
                });
            }

            if let Some(raw_dev) = device.wait_socket() {
                let device_wsa = WSACreateEvent();
                if wsa_event_invalid(device_wsa) {
                    WSACloseEvent(socket_event);
                    return Err(io::Error::last_os_error());
                }
                let rc = WSAEventSelect(raw_dev as SOCKET, device_wsa, (FD_READ | FD_CLOSE) as i32);
                if rc != 0 {
                    WSACloseEvent(device_wsa);
                    WSACloseEvent(socket_event);
                    return Err(io::Error::last_os_error());
                }
                return Ok(Self {
                    socket: raw_socket as SOCKET,
                    socket_event,
                    device_event: device_wsa as HANDLE,
                    device_socket: Some(raw_dev as SOCKET),
                    device_wsa: Some(device_wsa),
                    handles: [socket_event as HANDLE, device_wsa as HANDLE],
                    queue: Arc::new(Mutex::new(VecDeque::new())),
                    timeout_ms: timeout,
                    stop: Arc::new(AtomicBool::new(false)),
                    _thread: None
                });
            }

            WSACloseEvent(socket_event);
            Err(io::Error::other("Windows poll requires a TUN/TAP device or a second socket"))
        }
    }
}

impl Drop for WaitImpl {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        unsafe {
            let _ = SetEvent(self.device_event);
            WSACloseEvent(self.socket_event);
            if let Some(ev) = self.device_wsa {
                WSACloseEvent(ev);
            }
            // CreateEventW device_event is leaked until process exit so the reader thread
            // cannot signal a closed handle.
        }
    }
}

impl Iterator for WaitImpl {
    type Item = WaitResult;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.queue.lock().expect("device queue").is_empty() {
            return Some(WaitResult::Device);
        }

        let timeout = if self.timeout_ms == 0 { 0xFFFFFFFF } else { self.timeout_ms };
        unsafe {
            let rc = WaitForMultipleObjects(2, self.handles.as_ptr(), 0, timeout);
            if rc == WAIT_FAILED {
                return Some(WaitResult::Error(io::Error::last_os_error()));
            }
            if rc == WAIT_TIMEOUT {
                if !self.queue.lock().expect("device queue").is_empty() {
                    return Some(WaitResult::Device);
                }
                return Some(WaitResult::Timeout);
            }
            if rc == SOCKET_SLOT {
                let mut events = WSANETWORKEVENTS { lNetworkEvents: 0, iErrorCode: [0; 10] };
                let _ = WSAEnumNetworkEvents(self.socket, self.socket_event, &mut events);
                return Some(WaitResult::Socket);
            }
            if rc == DEVICE_SLOT {
                if let (Some(sock), Some(ev)) = (self.device_socket, self.device_wsa) {
                    let mut events = WSANETWORKEVENTS { lNetworkEvents: 0, iErrorCode: [0; 10] };
                    let _ = WSAEnumNetworkEvents(sock, ev, &mut events);
                } else {
                    let _ = ResetEvent(self.device_event);
                }
                return Some(WaitResult::Device);
            }
            Some(WaitResult::Timeout)
        }
    }
}
