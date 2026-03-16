// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021 Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{io, time::Duration};

use mio::{Events, Interest, Poll, Token};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, AsRawSocket, RawHandle, RawSocket};

// Importing `WaitResult` from the parent module.
use super::WaitResult;


// Tokens are used to identify which file descriptor an event belongs to.
// They can be any `usize`.
const SOCKET_TOKEN: Token = Token(0);
const DEVICE_TOKEN: Token = Token(1);

pub struct EpollWait {
    poll: Poll,
    events: Events,
    #[cfg(unix)]
    socket_fd: i32,
    #[cfg(unix)]
    device_fd: i32,
    #[cfg(windows)]
    socket_handle: usize,
    #[cfg(windows)]
    device_handle: usize,
    timeout: u32
}

#[cfg(unix)]
pub trait Pollable {
    fn get_fd(&self) -> RawFd;
}
#[cfg(unix)]
impl<T: AsRawFd> Pollable for T {
    fn get_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
pub trait Pollable {
    fn get_socket(&self) -> RawSocket;
    fn get_handle(&self) -> RawHandle;
}
#[cfg(windows)]
impl Pollable for (RawSocket, RawHandle) {
    fn get_socket(&self) -> RawSocket {
        self.0
    }
    fn get_handle(&self) -> RawHandle {
        self.1
    }
}
#[cfg(windows)]
impl Pollable for RawSocket {
    fn get_socket(&self) -> RawSocket {
        *self
    }
    fn get_handle(&self) -> RawHandle {
        0 as RawHandle
    }
}
#[cfg(windows)]
impl Pollable for RawHandle {
    fn get_socket(&self) -> RawSocket {
        0
    }
    fn get_handle(&self) -> RawHandle {
        *self
    }
}
#[cfg(windows)]
impl<T: AsRawSocket + AsRawHandle> Pollable for T {
    fn get_socket(&self) -> RawSocket {
        self.as_raw_socket()
    }
    fn get_handle(&self) -> RawHandle {
        self.as_raw_handle()
    }
}


impl EpollWait {
    // The `new` function is simplified as `mio` handles the setup internally.
    // The file descriptors must be non-blocking.
    pub fn new(socket: &impl Pollable, device: &impl Pollable, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, Interest::READABLE)
    }

    // `testing` function now registers for both `READABLE` and `WRITABLE` interests.
    pub fn testing(socket: &impl Pollable, device: &impl Pollable, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, Interest::READABLE.add(Interest::WRITABLE))
    }

    #[cfg(unix)]
    fn create(socket: &impl Pollable, device: &impl Pollable, timeout: u32, interest: Interest) -> io::Result<Self> {
        let poll = Poll::new()?;
        let events = Events::with_capacity(128);

        let socket_fd = socket.get_fd();
        let device_fd = device.get_fd();

        // `mio` requires you to register a non-blocking object.
        // The `register` method binds a source (like a socket) to a `Token`.
        // The `interest` defines what kind of events to listen for.
        poll.registry().register(&mut mio::unix::SourceFd(&socket_fd), SOCKET_TOKEN, interest)?;
        poll.registry().register(&mut mio::unix::SourceFd(&device_fd), DEVICE_TOKEN, interest)?;

        Ok(Self { poll, events, socket_fd, device_fd, timeout })
    }

    #[cfg(windows)]
    fn create(socket: &impl Pollable, device: &impl Pollable, timeout: u32, interest: Interest) -> io::Result<Self> {
        let poll = Poll::new()?;
        let events = Events::with_capacity(128);

        let socket_handle = socket.get_socket() as usize;
        let device_handle = device.get_handle() as usize;

        // On Windows, mio doesn't have a direct equivalent of SourceFd for arbitrary handles.
        // This is a stub for now, as Windows support is still in progress.
        // In a real implementation, we would need to wrap these in something that implements Source.
        
        Ok(Self { poll, events, socket_handle, device_handle, timeout })
    }
}

// The `Drop` implementation is not needed as `mio::Poll` and `Events`
// handle resource cleanup automatically.
// The `impl Drop for CrossPlatformWait` block is removed.

impl Iterator for EpollWait {
    type Item = WaitResult;

    fn next(&mut self) -> Option<Self::Item> {
        let timeout_duration = if self.timeout == 0 { None } else { Some(Duration::from_millis(self.timeout as u64)) };

        match self.poll.poll(&mut self.events, timeout_duration) {
            Ok(_) => {
                for event in self.events.iter() {
                    match event.token() {
                        SOCKET_TOKEN => return Some(WaitResult::Socket),
                        DEVICE_TOKEN => return Some(WaitResult::Device),
                        _ => unreachable!()
                    }
                }
                // If no events were returned but the poll was successful, it's a timeout.
                Some(WaitResult::Timeout)
            }
            Err(e) => {
                // Ignore `Interrupted` errors and try again.
                if e.kind() == io::ErrorKind::Interrupted {
                    self.next()
                } else {
                    Some(WaitResult::Error(e))
                }
            }
        }
    }
}
