# Datapath: bandwidth left on the table

vpn-bench (Dec 2025, **upstream** VpnCloud) saw ~413 Mbps TCP receive vs ~810–850 for WireGuard/Tailscale, with send 539 / receive 413 and hundreds of retransmits. That is a drain problem, not crypto.

This list is the remaining work. Skipped items stay skipped (product shape).

## Do in this tree

### 1. Stop paying a 64 KiB zero + heap copy per packet
Hot-path regressions from batching:
- `handle_socket_event` does `MsgBuffer::new()` (zeroes 65535 bytes) per UDP packet
- `send_to` does `msg.message().to_vec()` into the outbox (alloc + copy)

**Fix:** reuse preallocated `rx_bufs` / a `tx_spare` pool; copy only the payload bytes; never construct a fresh `MsgBuffer` on the wait thread.

### 2. Skip `Mutex` when `--crypto-threads` is 0
`PeerCrypto` is `Arc<Mutex<_>>` even with the pool off, so every DATA packet locks. The wait thread is then the only user.

**Fix:** store `PeerCrypto` by value when the pool is disabled; only wrap in `Arc<Mutex<_>>` when workers > 0.

### 3. Batch TUN I/O (Linux)
UDP is `recvmmsg`/`sendmmsg` + GSO/GRO. The overlay device is still one `read`/`write` syscall per packet. tun-rs already has Linux `offload(true)` plus `recv_multiple` / `send_multiple` (virtio GSO/GRO).

**Fix:** enable TUN offload on Linux TUN; batch read/write through those APIs. TAP stays one-packet (L2 offload is less reliable).

### 4. TUN write batch from the decrypt path
After a UDP batch, decrypted DATA is written to TUN one-by-one. Queue and `send_multiple` at the end of the socket event (same offload path as 3).

## Measure, then maybe

### 5. `--crypto-threads` default
Keep default 0 (one fat TCP flow serializes on per-peer nonces anyway). Revisit defaulting to `nproc` only after 1–4 are in and vpn-bench is re-run with many peers.

### 6. `aws-lc-rs` instead of `ring` (Linux AES-GCM)
Possible tens of percent on AES-only bulk. ChaCha20 would not care. Only after a profile shows AEAD in the top stacks.

## Out of product shape (do not do)

- Userspace TCP / gVisor (Tailscale’s loss/reorder win)
- Kernel datapath (WireGuard’s clean-LAN win)
- Per-app split tunnel, skip-crypto-on-LAN, OAuth

## Status

| # | Item | Status |
|---|------|--------|
| 1 | No 64 KiB zero / outbox `to_vec` | done (reuse `rx_bufs` / `buf_spare`; `MsgBuffer` clone copies payload only) |
| 2 | Direct `PeerCrypto` when pool off | done (`PeerCryptoSlot::Direct`) |
| 3 | Linux TUN offload + `recv_multiple` | done (TUN `offload(true)` + `read_batch`) |
| 4 | Linux TUN `send_multiple` after UDP batch | partial (`write_msg` uses `send_multiple` per packet; no queued batch yet) |
| 5 | Crypto-thread default | later |
| 6 | aws-lc-rs | later |
