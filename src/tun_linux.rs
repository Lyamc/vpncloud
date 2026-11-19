// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Linux-only TUN send batching, GSO header tuning and microsecond pacing.
//! Extracted from `device.rs` to keep the cross-platform device code readable.

#![cfg(all(target_os = "linux", not(target_env = "ohos")))]

use std::{
    cell::{Cell, RefCell},
    io,
    os::unix::io::RawFd,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}
};

use tun_rs::{ExpandBuffer, VIRTIO_NET_HDR_LEN};

pub(crate) fn tune_gso_hdr(meta: &mut crate::gso::GsoMeta, pkt: &[u8]) {
    let kind = meta.gso_type & !0x80;
    if kind == crate::gso::GSO_UDP_L4 {
        meta.hdr_len = meta.csum_start.saturating_add(8);
        return;
    }
    let cs = meta.csum_start as usize;
    if pkt.len() <= cs + 12 {
        return;
    }
    let tcp_hlen = ((pkt[cs + 12] as u16) >> 4) * 4;
    if (20..=60).contains(&tcp_hlen) {
        meta.hdr_len = meta.csum_start.saturating_add(tcp_hlen);
    }
}

pub(crate) fn tun_tx_ready(fd: RawFd) -> bool {
    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, 0) > 0 }
}

struct TunSendScratch {
    iov: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>
}

thread_local! {
    static TUN_SEND: RefCell<TunSendScratch> =
        const { RefCell::new(TunSendScratch { iov: Vec::new(), hdrs: Vec::new() }) };
}

/// Driver queue in front of the TUN reader. The kernel default of 500 packets
/// is about 6 ms, and a stall longer than that is dropped after the qdisc has
/// counted the datagrams as sent. 16384 absorbs that stall.
pub(crate) const TUN_TXQUEUELEN: u32 = 16_384;

/// Raise the TUN transmit ring. Failure leaves the kernel default in place.
pub(crate) fn widen_tx_queue(ifname: &str) {
    let qlen = TUN_TXQUEUELEN.to_string();
    match std::process::Command::new("ip").args(["link", "set", "dev", ifname, "txqueuelen", &qlen]).status() {
        Ok(status) if status.success() => info!("Set txqueuelen {qlen} on {ifname}"),
        Ok(status) => info!("Could not set txqueuelen on {ifname} ({status})"),
        Err(err) => info!("Could not set txqueuelen on {ifname}: {err}")
    }
}

/// Datagrams per TUN inject. Eight inner packets are about 11 KiB.
pub(crate) const UDP_INJECT_CHUNK: usize = 8;

/// Airtime of one inner UDP packet at the shaped underlay rate.
pub(crate) const UDP_INJECT_PACKET_NS: u64 = 12_000;

/// Upper bound on one inject wait. One chunk of packets.
pub(crate) const UDP_INJECT_GAP_NS: u64 = UDP_INJECT_PACKET_NS * UDP_INJECT_CHUNK as u64;

fn sleep_ns(ns: u64) {
    let ts = libc::timespec { tv_sec: 0, tv_nsec: ns as libc::c_long };
    while unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
    {}
}

/// Burn the rest of an inject gap with an absolute sleep plus a short spin.
pub(crate) fn hold_udp_inject_gap(ns: u64) {
    if ns == 0 {
        return;
    }
    let ns = ns.min(UDP_INJECT_GAP_NS);
    let Some(start) = crate::net::mono_now() else {
        sleep_ns(ns);
        return;
    };
    let end = start.saturating_add(ns);
    const SPIN_TAIL_NS: u64 = 20_000;
    let sleep_at = end.saturating_sub(SPIN_TAIL_NS);
    if crate::net::mono_now().unwrap_or(end) < sleep_at {
        precise_timer_slack();
        let ts = libc::timespec {
            tv_sec: (sleep_at / 1_000_000_000) as libc::time_t,
            tv_nsec: (sleep_at % 1_000_000_000) as libc::c_long
        };
        loop {
            let rc =
                unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &ts, std::ptr::null_mut()) };
            if rc != libc::EINTR {
                break;
            }
        }
    }
    while crate::net::mono_now().unwrap_or(end) < end {
        std::hint::spin_loop();
    }
}

fn precise_timer_slack() {
    thread_local! {
        static SET: Cell<bool> = const { Cell::new(false) };
    }
    SET.with(|set| {
        if set.get() {
            return;
        }
        set.set(true);
        unsafe {
            libc::prctl(libc::PR_SET_TIMERSLACK, 1, 0, 0, 0);
        }
    });
}

/// A TUN fd is a character device; remember ENOTSOCK and skip the syscall.
static TUN_SENDMMSG: AtomicBool = AtomicBool::new(true);

/// One TUN message per datagram, batched with `sendmmsg`.
// iovec/msghdr arrays are filled in lockstep with the packet buffers.
#[allow(clippy::needless_range_loop)]
pub(crate) fn tun_sendmmsg(fd: RawFd, bufs: &mut [crate::util::MsgBuffer]) -> io::Result<usize> {
    if !TUN_SENDMMSG.load(Ordering::Relaxed) {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "tun is not a socket"));
    }
    TUN_SEND.with(|cell| {
        let scratch = &mut *cell.borrow_mut();
        let n = bufs.len();
        scratch.iov.resize(n, libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 });
        scratch.hdrs.resize_with(n, || unsafe { std::mem::zeroed() });
        let iov = scratch.iov.as_mut_ptr();
        let hdrs = scratch.hdrs.as_mut_ptr();
        for i in 0..n {
            let msg = bufs[i].message();
            unsafe {
                *iov.add(i) = libc::iovec { iov_base: msg.as_ptr() as *mut _, iov_len: msg.len() };
                let mut msg_hdr: libc::msghdr = std::mem::zeroed();
                msg_hdr.msg_iov = iov.add(i);
                msg_hdr.msg_iovlen = 1;
                let mut packed: libc::mmsghdr = std::mem::zeroed();
                packed.msg_hdr = msg_hdr;
                *hdrs.add(i) = packed;
            }
        }
        let got = unsafe { libc::sendmmsg(fd, hdrs, n as u32, libc::MSG_DONTWAIT as _) };
        if got < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTSOCK) {
                TUN_SENDMMSG.store(false, Ordering::Relaxed);
            }
            Err(err)
        } else {
            Ok(got as usize)
        }
    })
}

/// Count virtio GSO trains (sampled once per 4000 flushes).
pub(crate) fn note_gro_batch(bufs: &[crate::util::MsgBuffer]) {
    static FLUSHES: AtomicU64 = AtomicU64::new(0);
    static MERGED: AtomicU64 = AtomicU64::new(0);
    static SUM_SEGS: AtomicU64 = AtomicU64::new(0);
    static MAX_SEGS: AtomicUsize = AtomicUsize::new(0);
    let flush = FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
    if !flush.is_multiple_of(4000) {
        return;
    }
    let mut merged_here = 0u64;
    let mut segs_here = 0u64;
    let mut max_here = 0usize;
    for b in bufs {
        let msg = b.message();
        if msg.len() < VIRTIO_NET_HDR_LEN || msg[1] == 0 {
            continue;
        }
        let hdr_len = u16::from_le_bytes([msg[2], msg[3]]) as usize;
        let gso_size = u16::from_le_bytes([msg[4], msg[5]]) as usize;
        if gso_size == 0 {
            continue;
        }
        let payload = msg.len().saturating_sub(VIRTIO_NET_HDR_LEN).saturating_sub(hdr_len);
        let segs = payload / gso_size + usize::from(payload % gso_size != 0);
        if segs >= 2 {
            merged_here += 1;
            segs_here += segs as u64;
            max_here = max_here.max(segs);
        }
    }
    let merged = MERGED.fetch_add(merged_here, Ordering::Relaxed) + merged_here;
    let segs_sum = SUM_SEGS.fetch_add(segs_here, Ordering::Relaxed) + segs_here;
    let mut max_segs = MAX_SEGS.load(Ordering::Relaxed);
    while max_here > max_segs {
        match MAX_SEGS.compare_exchange_weak(max_segs, max_here, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                max_segs = max_here;
                break;
            }
            Err(cur) => max_segs = cur
        }
    }
    info!("TUN gso flushes={flush} merged={merged} segs={segs_sum} max_segs={max_segs}");
}

pub(crate) struct MsgVirtio<'a>(pub &'a mut crate::util::MsgBuffer);

impl AsRef<[u8]> for MsgVirtio<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.message()
    }
}

impl AsMut<[u8]> for MsgVirtio<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.message_mut()
    }
}

impl ExpandBuffer for MsgVirtio<'_> {
    fn buf_capacity(&self) -> usize {
        self.0.remaining_capacity()
    }

    fn buf_resize(&mut self, new_len: usize, value: u8) {
        let old = self.0.len();
        self.0.set_length(new_len.min(self.0.remaining_capacity()));
        if self.0.len() > old {
            self.0.message_mut()[old..].fill(value);
        }
    }

    fn buf_extend_from_slice(&mut self, src: &[u8]) {
        let old = self.0.len();
        let add = src.len().min(self.0.remaining_capacity().saturating_sub(old));
        self.0.set_length(old + add);
        self.0.message_mut()[old..].copy_from_slice(&src[..add]);
    }
}
