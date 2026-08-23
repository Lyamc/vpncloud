// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Linux seccomp: no-new-privs plus a syscall blacklist after bind/TUN/privdrop.

#[cfg(not(target_os = "linux"))]
pub fn apply() {
    // Other OS: nothing to do.
}

#[cfg(target_os = "linux")]
pub fn apply() {
    if let Err(e) = apply_linux() {
        warn!("seccomp not applied: {}", e);
    } else {
        info!("seccomp: no_new_privs + exec/privilege blacklist");
    }
}

#[cfg(target_os = "linux")]
fn apply_linux() -> Result<(), String> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let arch = audit_arch()?;
    let mut filter = Vec::new();
    // if arch != expected -> KILL
    filter.push(bpf(bpf_class::LD | bpf_class::W | bpf_class::ABS, 0, 0, 4)); // arch offset
    filter.push(bpf(bpf_class::JMP | bpf_class::JEQ | bpf_class::K, 0, 1, arch));
    filter.push(bpf(bpf_class::RET | bpf_class::K, 0, 0, seccomp_ret::KILL_PROCESS));
    filter.push(bpf(bpf_class::LD | bpf_class::W | bpf_class::ABS, 0, 0, 0)); // nr offset
    for &nr in blocked_syscalls() {
        filter.push(bpf(bpf_class::JMP | bpf_class::JEQ | bpf_class::K, 0, 1, nr as u32));
        filter.push(bpf(bpf_class::RET | bpf_class::K, 0, 0, seccomp_ret::KILL_PROCESS));
    }
    filter.push(bpf(bpf_class::RET | bpf_class::K, 0, 0, seccomp_ret::ALLOW));

    let mut bpf_prog: Vec<libc::sock_filter> =
        filter.iter().map(|f| libc::sock_filter { code: f.0, jt: f.1, jf: f.2, k: f.3 }).collect();
    let prog = libc::sock_fprog { len: bpf_prog.len() as u16, filter: bpf_prog.as_mut_ptr() };
    let rc = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog as *const _) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn audit_arch() -> Result<u32, String> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(0xC000_003E)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(0xC000_00B7)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err("seccomp: unsupported architecture".into())
    }
}

#[cfg(target_os = "linux")]
fn blocked_syscalls() -> &'static [i64] {
    &[
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_init_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_kexec_load,
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_syslog,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_chroot,
        libc::SYS_pivot_root,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl
    ]
}

#[cfg(target_os = "linux")]
mod bpf_class {
    pub const LD: u16 = 0x00;
    pub const JMP: u16 = 0x05;
    pub const RET: u16 = 0x06;
    pub const W: u16 = 0x00;
    pub const ABS: u16 = 0x20;
    pub const JEQ: u16 = 0x10;
    pub const K: u16 = 0x00;
}

#[cfg(target_os = "linux")]
mod seccomp_ret {
    pub const KILL_PROCESS: u32 = 0x8000_0000;
    pub const ALLOW: u32 = 0x7fff_0000;
}

#[cfg(target_os = "linux")]
fn bpf(code: u16, jt: u8, jf: u8, k: u32) -> (u16, u8, u8, u32) {
    (code, jt, jf, k)
}

#[cfg(test)]
mod tests {
    #[test]
    fn apply_does_not_panic() {
        // In tests we do not install the filter (would break cargo); just ensure the module links.
        #[cfg(not(target_os = "linux"))]
        super::apply();
    }
}
