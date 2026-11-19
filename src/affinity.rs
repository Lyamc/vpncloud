// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! CPU topology detection and datapath thread pinning for hybrid chips.
//! Extracted from `cloud.rs` so the datapath module stays focused on routing.

#[cfg(target_os = "linux")] use log::info;
#[cfg(target_os = "linux")] use std::fs;

#[cfg(target_os = "linux")]
/// CPUs in the fastest frequency cluster, lowest id first. Empty when every
/// CPU reports the same maximum, so a uniform machine is left unpinned.
#[allow(dead_code)] // Linux CPU-frequency analysis
pub(crate) fn fast_cluster(freqs: &[(usize, u64)]) -> Vec<usize> {
    let Some(max) = freqs.iter().map(|(_, freq)| *freq).max() else {
        return Vec::new();
    };
    let Some(min) = freqs.iter().map(|(_, freq)| *freq).min() else {
        return Vec::new();
    };
    if max == 0 || max == min {
        return Vec::new();
    }
    let mut cpus: Vec<usize> = freqs.iter().filter(|(_, freq)| *freq == max).map(|(cpu, _)| *cpu).collect();
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

#[cfg(target_os = "linux")]
pub(crate) fn online_cpu_freqs() -> Vec<(usize, u64)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("cpu") else {
            continue;
        };
        let Ok(cpu) = rest.parse::<usize>() else {
            continue;
        };
        let Ok(text) = fs::read_to_string(entry.path().join("cpufreq/cpuinfo_max_freq")) else {
            continue;
        };
        let Ok(freq) = text.trim().parse::<u64>() else {
            continue;
        };
        out.push((cpu, freq));
    }
    out
}

#[cfg(target_os = "linux")]
pub(crate) fn set_thread_affinity(cpus: &[usize]) -> bool {
    if cpus.is_empty() || cpus.iter().any(|cpu| *cpu >= 1024) {
        return false;
    }
    let mut mask = [0u64; 16];
    for cpu in cpus {
        mask[cpu / 64] |= 1u64 << (cpu % 64);
    }
    let rc =
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&mask), mask.as_ptr() as *const libc::cpu_set_t) };
    rc == 0
}

/// One sibling group inside the fast cluster. Two processes with different
/// pids land on different physical cores. Pinning both to every fast CPU let
/// the scheduler park them on the interrupt core together.
#[cfg(target_os = "linux")]
pub(crate) fn datapath_cpus(groups: &[Vec<usize>], slot: usize) -> Vec<usize> {
    if groups.is_empty() {
        return Vec::new();
    }
    groups[slot % groups.len()].clone()
}

/// A different physical core from [`datapath_cpus`] for the same pid, so the
/// TUN read overlaps encryption instead of sharing one core.
#[cfg(target_os = "linux")]
pub(crate) fn reader_slot(ngroups: usize, main_slot: usize) -> usize {
    if ngroups < 2 {
        return main_slot;
    }
    (main_slot + ngroups / 2) % ngroups
}

#[cfg(target_os = "linux")]
fn sibling_groups(cluster: &[usize]) -> Vec<Vec<usize>> {
    let members: std::collections::BTreeSet<usize> = cluster.iter().copied().collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut groups = Vec::new();
    for cpu in cluster {
        if !seen.insert(*cpu) {
            continue;
        }
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
        let text = fs::read_to_string(path).unwrap_or_default();
        let mut group: Vec<usize> = parse_cpu_list(&text).into_iter().filter(|cpu| members.contains(cpu)).collect();
        if group.is_empty() {
            group.push(*cpu);
        }
        group.sort_unstable();
        group.dedup();
        for cpu in &group {
            seen.insert(*cpu);
        }
        groups.push(group);
    }
    groups
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_cpu_list(list: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in list.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let Ok(start) = start.parse::<usize>() else {
                continue;
            };
            let Ok(end) = end.parse::<usize>() else {
                continue;
            };
            if end >= start && end - start < 4096 {
                out.extend(start..=end);
            }
        } else if let Ok(cpu) = part.parse::<usize>() {
            out.push(cpu);
        }
    }
    out
}

/// Hybrid chips report the same capacity for a 4.7 GHz core and a 3.5 GHz
/// core, so the scheduler will park this thread on the slow cluster. Pin this
/// thread to every fast CPU. One sibling group was slower: the thread stayed
/// on a busy core. Leaving out the interrupt cores was slower too. A uniform
/// machine is left alone.
#[cfg(target_os = "linux")]
pub(crate) fn pin_datapath_thread() {
    let cpus = fast_cluster(&online_cpu_freqs());
    if cpus.is_empty() {
        return;
    }
    if set_thread_affinity(&cpus) {
        info!("Pinned datapath thread to cpus {cpus:?}");
    }
}

/// The TUN prefetch thread inherits the datapath pin. Move it to another fast
/// core so the read is not fighting the encrypt loop for the same core.
#[cfg(target_os = "linux")]
pub(crate) fn pin_reader_thread() {
    let groups = sibling_groups(&fast_cluster(&online_cpu_freqs()));
    if groups.len() < 2 {
        return;
    }
    let slot = reader_slot(groups.len(), std::process::id() as usize);
    let cpus = datapath_cpus(&groups, slot);
    if set_thread_affinity(&cpus) {
        info!("Pinned TUN read thread to cpus {cpus:?}");
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn pin_datapath_thread() {}
