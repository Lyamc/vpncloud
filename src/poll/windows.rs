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

pub struct WaitImpl {
    socket: SOCKET,
    socket_event: WSAEVENT,
    device_event: HANDLE,
    handles: [HANDLE; 2],
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    timeout_ms: u32,
    stop: Arc<AtomicBool>,
    _thread: Option<JoinHandle<()>>
}

impl WaitImpl {
    pub fn new(socket: &impl Pollable, device: &impl Pollable, timeout: u32) -> io::Result<Self> {
        let raw_socket = socket.wait_socket().ok_or_else(|| io::Error::other("Windows poll requires a UDP socket"))?;
        let source = device.wait_device().ok_or_else(|| io::Error::other("Windows poll requires a TUN/TAP device"))?;

        unsafe {
            let socket_event = WSACreateEvent();
            if socket_event.is_null() {
                return Err(io::Error::last_os_error());
            }
            let rc = WSAEventSelect(raw_socket as SOCKET, socket_event, (FD_READ | FD_CLOSE) as i32);
            if rc != 0 {
                WSACloseEvent(socket_event);
                return Err(io::Error::last_os_error());
            }

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
            let ev_t = device_event;

            let thread = thread::Builder::new().name("vpncloud-wintun".into()).spawn(move || {
                let mut buf = vec![0u8; 65535];
                while !stop_t.load(Ordering::Relaxed) {
                    match (recv)(&mut buf) {
                        Ok(n) => {
                            queue_t.lock().expect("device queue").push_back(buf[..n].to_vec());
                            let _ = SetEvent(ev_t);
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

            Ok(Self {
                socket: raw_socket as SOCKET,
                socket_event,
                device_event,
                handles: [socket_event, device_event],
                queue,
                timeout_ms: timeout,
                stop,
                _thread: Some(thread)
            })
        }
    }
}

impl Drop for WaitImpl {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        unsafe {
            let _ = SetEvent(self.device_event);
            WSACloseEvent(self.socket_event);
            // device_event is closed after the thread may still signal it; leaking it until
            // process exit is preferable to a use-after-close in the reader thread.
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
                let _ = ResetEvent(self.device_event);
                return Some(WaitResult::Device);
            }
            Some(WaitResult::Timeout)
        }
    }
}
