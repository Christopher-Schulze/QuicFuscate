//! IP address pool for client allocation (IPv4 and IPv6).

use std::collections::{HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};

fn ipv4_range_size(start: u32, end: u32) -> u64 {
    if start > end {
        0
    } else {
        u64::from(end) - u64::from(start) + 1
    }
}

fn ipv6_range_size(start: u128, end: u128) -> u128 {
    if start > end {
        0
    } else {
        end.saturating_sub(start).saturating_add(1)
    }
}

/// IP address pool for VPN clients.
pub struct IpPool {
    start: u32,
    end: u32,
    next_cursor: u32,
    allocated: HashSet<u32>,
    free_list: VecDeque<u32>,
}

impl IpPool {
    /// Create a new IP pool.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let start = u32::from(start);
        Self {
            start,
            end: u32::from(end),
            next_cursor: start,
            allocated: HashSet::new(),
            free_list: VecDeque::new(),
        }
    }

    /// Allocate the next available IP.
    ///
    /// Released addresses are reused before the forward cursor. The cursor only
    /// walks addresses that were explicitly reserved, so allocation is O(1)
    /// amortized without enumerating the configured range.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        while let Some(ip) = self.free_list.pop_front() {
            if self.allocated.insert(ip) {
                return Some(Ipv4Addr::from(ip));
            }
        }

        if self.start > self.end {
            return None;
        }

        let mut candidate = self.next_cursor;
        loop {
            if self.allocated.insert(candidate) {
                self.next_cursor = self.next_address(candidate);
                return Some(Ipv4Addr::from(candidate));
            }
            if candidate == self.end {
                self.next_cursor = self.start;
                return None;
            }
            candidate += 1;
        }
    }

    /// Allocate a specific IP (if available).
    pub fn allocate_specific(&mut self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        if ip_u32 >= self.start && ip_u32 <= self.end && !self.allocated.contains(&ip_u32) {
            self.allocated.insert(ip_u32);
            if ip_u32 == self.next_cursor {
                self.next_cursor = self.next_address(ip_u32);
            }
            true
        } else {
            false
        }
    }

    /// Release an IP back to the pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        let ip_u32 = u32::from(ip);
        if ip_u32 < self.start || ip_u32 > self.end {
            return;
        }
        if self.allocated.remove(&ip_u32) {
            self.free_list.push_back(ip_u32);
        }
    }

    /// Check if an IP is allocated.
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        self.allocated.contains(&u32::from(ip))
    }

    /// Get the number of available IPs.
    pub fn available(&self) -> usize {
        let total = self.total();
        total.saturating_sub(self.allocated.len())
    }

    /// Get the total pool size.
    pub fn total(&self) -> usize {
        let total = ipv4_range_size(self.start, self.end);
        if total > usize::MAX as u64 {
            usize::MAX
        } else {
            total as usize
        }
    }

    /// Get the number of allocated IPs.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    fn next_address(&self, address: u32) -> u32 {
        if address == self.end {
            self.start
        } else {
            address + 1
        }
    }
}

/// IPv6 address pool for VPN clients.
/// Uses ULA range (fd00::/48) by default for private VPN addressing.
#[allow(dead_code)]
pub struct Ipv6Pool {
    start: u128,
    end: u128,
    next_cursor: u128,
    allocated: HashSet<u128>,
    free_list: VecDeque<u128>,
}

#[allow(dead_code)]
impl Ipv6Pool {
    /// Create a new IPv6 address pool.
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        let start = u128::from(start);
        Self {
            start,
            end: u128::from(end),
            next_cursor: start,
            allocated: HashSet::new(),
            free_list: VecDeque::new(),
        }
    }

    /// Allocate the next available IPv6 address.
    ///
    /// Released addresses are reused before the forward cursor. The cursor only
    /// walks addresses that were explicitly reserved, so allocation is O(1)
    /// amortized without enumerating the configured range.
    pub fn allocate(&mut self) -> Option<Ipv6Addr> {
        while let Some(ip) = self.free_list.pop_front() {
            if self.allocated.insert(ip) {
                return Some(Ipv6Addr::from(ip));
            }
        }

        if self.start > self.end {
            return None;
        }

        let mut candidate = self.next_cursor;
        loop {
            if self.allocated.insert(candidate) {
                self.next_cursor = self.next_address(candidate);
                return Some(Ipv6Addr::from(candidate));
            }
            if candidate == self.end {
                self.next_cursor = self.start;
                return None;
            }
            candidate += 1;
        }
    }

    /// Release an IPv6 address back to the pool.
    pub fn release(&mut self, ip: Ipv6Addr) {
        let ip_u128 = u128::from(ip);
        if ip_u128 < self.start || ip_u128 > self.end {
            return;
        }
        if self.allocated.remove(&ip_u128) {
            self.free_list.push_back(ip_u128);
        }
    }

    /// Check if an IPv6 address is allocated.
    pub fn is_allocated(&self, ip: Ipv6Addr) -> bool {
        self.allocated.contains(&u128::from(ip))
    }

    /// Get the number of available IPv6 addresses.
    pub fn available(&self) -> u128 {
        ipv6_range_size(self.start, self.end).saturating_sub(self.allocated.len() as u128)
    }

    /// Get the total IPv6 pool size.
    ///
    /// The full IPv6 address space contains 2^128 addresses, which cannot be
    /// represented by u128. That one range saturates at u128::MAX.
    pub fn total(&self) -> u128 {
        ipv6_range_size(self.start, self.end)
    }

    /// Get the number of allocated IPv6 addresses.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    fn next_address(&self, address: u128) -> u128 {
        if address == self.end {
            self.start
        } else {
            address + 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_ip_pool() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 5));

        assert_eq!(pool.total(), 4);
        assert_eq!(pool.available(), 4);

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(pool.available(), 3);

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2, Ipv4Addr::new(10, 8, 0, 3));

        pool.release(ip1);
        assert_eq!(pool.available(), 3); // Was 2 allocated, released 1 = 3 available

        // Should reuse released IP
        let ip3 = pool.allocate().unwrap();
        assert_eq!(ip3, Ipv4Addr::new(10, 8, 0, 2));
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));

        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_none()); // Exhausted
    }

    #[test]
    fn ip_pool_allocation_stays_fast_near_capacity() {
        let start = Ipv4Addr::new(10, 0, 0, 0);
        let end = Ipv4Addr::new(10, 0, 255, 255);
        let mut pool = IpPool::new(start, end);
        let total = pool.total();

        for _ in 0..(total * 99 / 100) {
            assert!(pool.allocate().is_some());
        }

        let started = Instant::now();
        assert!(pool.allocate().is_some());
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(1), "allocation at 99% capacity took {elapsed:?}");
    }

    #[test]
    fn test_ipv6_pool() {
        let start = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002);
        let end = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0005);
        let mut pool = Ipv6Pool::new(start, end);

        assert_eq!(pool.total(), 4);
        assert_eq!(pool.available(), 4);

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1, start);
        assert_eq!(pool.available(), 3);

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0003));

        pool.release(ip1);
        assert_eq!(pool.available(), 3);

        let ip3 = pool.allocate().unwrap();
        assert_eq!(ip3, start); // Reuse released
    }

    #[test]
    fn test_ipv6_pool_exhaustion() {
        let start = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001);
        let end = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002);
        let mut pool = Ipv6Pool::new(start, end);

        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_none());
    }

    #[test]
    fn ipv6_pool_handles_large_prefix_without_range_scan() {
        let start = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let end = Ipv6Addr::new(0xfd00, 0, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff);
        let mut pool = Ipv6Pool::new(start, end);

        assert_eq!(pool.total(), 1u128 << 64);
        for offset in 0..1000u128 {
            assert_eq!(pool.allocate(), Some(Ipv6Addr::from(u128::from(start) + offset)));
        }
        assert_eq!(pool.available(), (1u128 << 64) - 1000);

        let larger_prefix = Ipv6Pool::new(
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::new(0, 0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
        assert_eq!(larger_prefix.total(), 1u128 << 96);
    }

    #[test]
    fn release_ignores_addresses_outside_pool() {
        let mut ipv4_pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let mut ipv6_pool = Ipv6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3),
        );

        let ipv4 = ipv4_pool.allocate().unwrap();
        let ipv6 = ipv6_pool.allocate().unwrap();
        ipv4_pool.release(Ipv4Addr::new(10, 0, 0, 1));
        ipv6_pool.release(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(ipv4_pool.allocated_count(), 1);
        assert_eq!(ipv6_pool.allocated_count(), 1);
        assert_eq!(ipv4_pool.available(), 1);
        assert_eq!(ipv6_pool.available(), 1);
        assert!(ipv4_pool.is_allocated(ipv4));
        assert!(ipv6_pool.is_allocated(ipv6));
    }

    #[test]
    fn invalid_ranges_are_empty_and_safe() {
        let mut ipv4_pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 2));
        let mut ipv6_pool = Ipv6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        );

        assert_eq!(ipv4_pool.total(), 0);
        assert_eq!(ipv4_pool.available(), 0);
        assert!(ipv4_pool.allocate().is_none());
        assert_eq!(ipv6_pool.total(), 0);
        assert_eq!(ipv6_pool.available(), 0);
        assert!(ipv6_pool.allocate().is_none());
    }
}
