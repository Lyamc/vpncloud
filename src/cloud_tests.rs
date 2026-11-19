#[cfg(test)]
mod gro_hold_tests {
    use crate::cloud::gro_batch_ready;

    #[test]
    fn gro_batch_waits_for_a_train_and_then_flushes() {
        let start = 1_000_000u64;
        let deadline = start + crate::cloud::GRO_HOLD_NS;
        // One socket read is about eight segments. Flushing there ACKs every
        // eight. The train has to outlast that read; the deadline still writes
        // a short batch, and an unarmed hold still writes immediately.
        assert!(crate::cloud::GRO_TRAIN > 8);
        assert!(!gro_batch_ready(1, start, deadline));
        assert!(!gro_batch_ready(8, start, deadline));
        assert!(!gro_batch_ready(crate::cloud::GRO_TRAIN - 1, start, deadline));
        assert!(gro_batch_ready(crate::cloud::GRO_TRAIN, start, deadline));
        assert!(gro_batch_ready(8, deadline, deadline));
        assert!(gro_batch_ready(3, 0, 0));
    }
}


#[cfg(test)]
mod ipv6_claim_tests {
    use crate::{cloud::configured_ipv6_host_claim, types::Address};
    use std::str::FromStr;

    #[test]
    fn ipv6_overlay_claims_the_host_not_the_prefix() {
        let range = configured_ipv6_host_claim(Some("fd00:8::1/64")).unwrap();
        assert_eq!(range.prefix_len, 128);
        assert!(range.matches(Address::from_str("fd00:8::1").unwrap()));
        assert!(!range.matches(Address::from_str("fd00:8::2").unwrap()));
        assert!(configured_ipv6_host_claim(Some("10.8.0.1/24")).is_none());
        assert!(configured_ipv6_host_claim(None).is_none());
    }
}


#[cfg(all(test, target_os = "linux"))]
mod affinity_tests {
    use crate::cloud::fast_cluster;

    #[test]
    fn fast_cluster_skips_a_uniform_machine() {
        assert!(fast_cluster(&[]).is_empty());
        assert!(fast_cluster(&[(0, 0), (1, 0)]).is_empty());
        assert!(fast_cluster(&[(0, 4700), (1, 4700), (2, 4700)]).is_empty());
    }

    #[test]
    fn fast_cluster_is_every_cpu_at_the_top_frequency() {
        assert_eq!(fast_cluster(&[(0, 4700), (12, 3500), (2, 4700)]), vec![0, 2]);
        assert_eq!(fast_cluster(&[(3, 2000), (8, 4000), (1, 4000)]), vec![1, 8]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn datapath_cpus_are_one_sibling_group() {
        let groups = vec![vec![0, 1], vec![2, 3], vec![4, 5]];
        assert_eq!(crate::cloud::datapath_cpus(&groups, 0), vec![0, 1]);
        assert_eq!(crate::cloud::datapath_cpus(&groups, 1), vec![2, 3]);
        assert_eq!(crate::cloud::datapath_cpus(&groups, 5), vec![4, 5]);
        assert!(crate::cloud::datapath_cpus(&[], 3).is_empty());
        assert_eq!(crate::cloud::reader_slot(4, 1), 3);
        assert_ne!(1 % 4, crate::cloud::reader_slot(4, 1));
        assert_eq!(crate::cloud::reader_slot(1, 0), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn datapath_thread_pins_only_when_a_slower_cluster_exists() {
        let freqs = crate::cloud::online_cpu_freqs();
        let want = fast_cluster(&freqs);
        let before = allowed_cpus();
        let _restore = AffinityGuard(before.clone());
        crate::cloud::pin_datapath_thread();
        let after = allowed_cpus();
        if want.is_empty() {
            assert_eq!(after, before, "uniform machine changed affinity");
        } else {
            assert_eq!(after, want, "freqs {freqs:?}");
        }
    }

    #[cfg(target_os = "linux")]
    struct AffinityGuard(Vec<usize>);

    #[cfg(target_os = "linux")]
    impl Drop for AffinityGuard {
        fn drop(&mut self) {
            let _ = crate::cloud::set_thread_affinity(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn allowed_cpus() -> Vec<usize> {
        let text = std::fs::read_to_string("/proc/thread-self/status").expect("status");
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Cpus_allowed_list:") {
                return parse_cpu_list(rest);
            }
        }
        panic!("Cpus_allowed_list missing:\n{text}");
    }

    #[cfg(target_os = "linux")]
    fn parse_cpu_list(list: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for part in list.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((start, end)) = part.split_once('-') {
                let start: usize = start.parse().expect(start);
                let end: usize = end.parse().expect(end);
                out.extend(start..=end);
            } else {
                out.push(part.parse().expect(part));
            }
        }
        out
    }
}
