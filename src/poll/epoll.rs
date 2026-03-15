// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021 Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{io, time::Duration};

use mio::{Events, Interest, Poll, Token};
use std::os::unix::io::AsRawFd;

// Importing `WaitResult` from the parent module.
use super::WaitResult;


// Tokens are used to identify which file descriptor an event belongs to.
// They can be any `usize`.
const SOCKET_TOKEN: Token = Token(0);
const DEVICE_TOKEN: Token = Token(1);

pub struct EpollWait {
    poll: Poll,
    events: Events,
    socket_fd: i32,
    device_fd: i32,
    timeout: u32
}

impl EpollWait {
    // The `new` function is simplified as `mio` handles the setup internally.
    // The file descriptors must be non-blocking.
    pub fn new(socket: impl AsRawFd, device: impl AsRawFd, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, Interest::READABLE)
    }

    // `testing` function now registers for both `READABLE` and `WRITABLE` interests.
    pub fn testing(socket: impl AsRawFd, device: impl AsRawFd, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, Interest::READABLE.add(Interest::WRITABLE))
    }

    fn create(socket: impl AsRawFd, device: impl AsRawFd, timeout: u32, interest: Interest) -> io::Result<Self> {
        let poll = Poll::new()?;
        let events = Events::with_capacity(128);

        // On Windows, the RawFd traits are `AsRawSocket`. For cross-platform
        // a simple cast may be all that is needed.
        let socket_fd = socket.as_raw_fd();
        let device_fd = device.as_raw_fd();

        // `mio` requires you to register a non-blocking object.
        // The `register` method binds a source (like a socket) to a `Token`.
        // The `interest` defines what kind of events to listen for.
        poll.registry().register(&mut mio::unix::SourceFd(&socket_fd), SOCKET_TOKEN, interest)?;
        poll.registry().register(&mut mio::unix::SourceFd(&device_fd), DEVICE_TOKEN, interest)?;

        Ok(Self { poll, events, socket_fd, device_fd, timeout })
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
