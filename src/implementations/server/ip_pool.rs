//! IP address pool for client allocation (IPv4 and IPv6).

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// IP address pool for VPN clients.
pub struct IpPool {
    start: u32,
    end: u32,
    allocated: HashSet<u32>,
}

impl IpPool {
    /// Create a new IP pool.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self { start: u32::from(start), end: u32::from(end), allocated: HashSet::new() }
    }

    /// Allocate the next available IP.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        for ip in self.start..=self.end {
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Some(Ipv4Addr::from(ip));
            }
        }
        None
    }

    /// Allocate a specific IP (if available).
    pub fn allocate_specific(&mut self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        if ip_u32 >= self.start && ip_u32 <= self.end && !self.allocated.contains(&ip_u32) {
            self.allocated.insert(ip_u32);
            true
        } else {
            false
        }
    }

    /// Release an IP back to the pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.remove(&u32::from(ip));
    }

    /// Check if an IP is allocated.
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        self.allocated.contains(&u32::from(ip))
    }

    /// Get the number of available IPs.
    pub fn available(&self) -> usize {
        let total = (self.end - self.start + 1) as usize;
        total.saturating_sub(self.allocated.len())
    }

    /// Get the total pool size.
    pub fn total(&self) -> usize {
        (self.end - self.start + 1) as usize
    }

    /// Get the number of allocated IPs.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }
}

/// IPv6 address pool for VPN clients.
/// Uses ULA range (fd00::/48) by default for private VPN addressing.
#[allow(dead_code)]
pub struct Ipv6Pool {
    start: u128,
    end: u128,
    allocated: HashSet<u128>,
}

#[allow(dead_code)]
impl Ipv6Pool {
    /// Create a new IPv6 address pool.
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        Self { start: u128::from(start), end: u128::from(end), allocated: HashSet::new() }
    }

    /// Allocate the next available IPv6 address.
    pub fn allocate(&mut self) -> Option<Ipv6Addr> {
        for ip in self.start..=self.end {
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Some(Ipv6Addr::from(ip));
            }
        }
        None
    }

    /// Release an IPv6 address back to the pool.
    pub fn release(&mut self, ip: Ipv6Addr) {
        self.allocated.remove(&u128::from(ip));
    }

    /// Check if an IPv6 address is allocated.
    pub fn is_allocated(&self, ip: Ipv6Addr) -> bool {
        self.allocated.contains(&u128::from(ip))
    }

    /// Get the number of available IPv6 addresses.
    pub fn available(&self) -> usize {
        let total = (self.end - self.start + 1) as usize;
        total.saturating_sub(self.allocated.len())
    }

    /// Get the total pool size.
    pub fn total(&self) -> usize {
        (self.end - self.start + 1) as usize
    }

    /// Get the number of allocated IPv6 addresses.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
