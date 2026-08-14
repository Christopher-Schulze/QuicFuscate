#[cfg(target_os = "linux")]
use super::RoutingError;
use super::RoutingManager;
#[cfg(any(test, target_os = "linux"))]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::process::Command;

impl RoutingManager {
    // ================================================================
    // TUN interface address assignment
    // ================================================================

    #[cfg(target_os = "linux")]
    pub(super) fn run_ip_command(args: &[&str]) -> Result<(), RoutingError> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .map_err(|error| RoutingError::CommandFailed(format!("ip spawn: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(RoutingError::CommandFailed(format!(
            "ip {} returned status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    /// Assign the IPv4 address to the TUN interface on Linux.
    #[cfg(target_os = "linux")]
    pub(super) fn assign_tun_address_linux(&self) -> Result<(), RoutingError> {
        let prefix = self.ipv4_prefix_len()?;
        let addr = format!("{}/{}", self.server_ip, prefix);
        let address_text = self.server_ip.to_string();
        if let Some(interface) = self.linux_address_on_other_interface("inet", &address_text)? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN address {} already exists on interface {}; refusing address conflict",
                self.server_ip, interface
            )));
        }
        let address_present = self.linux_address_present("inet", &address_text, prefix)?;
        if !address_present {
            let result = Self::run_ip_command(&["-4", "addr", "add", &addr, "dev", &self.tun_name]);
            if result.is_err() && !self.linux_address_present("inet", &address_text, prefix)? {
                return result;
            }
            self.ownership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .ipv4_address_added = true;
        }

        if !self.linux_link_is_up()? {
            let result = Self::run_ip_command(&["link", "set", "up", "dev", &self.tun_name]);
            if result.is_err() && !self.linux_link_is_up()? {
                return result;
            }
            self.ownership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .link_brought_up = true;
        }
        if !self.linux_address_present("inet", &address_text, prefix)?
            || !self.linux_link_is_up()?
        {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} failed IPv4/link postcondition",
                self.tun_name
            )));
        }
        log::debug!("TUN IPv4 address verified: {} on {}", addr, self.tun_name);
        Ok(())
    }

    /// Assign the IPv6 address to the TUN interface on Linux.
    #[cfg(target_os = "linux")]
    pub(super) fn assign_tun_address_v6_linux(&self) -> Result<(), RoutingError> {
        if let Some(ipv6) = self.server_ipv6 {
            if self.ipv6_prefix_len > 128 {
                return Err(RoutingError::UnsupportedConfiguration(format!(
                    "IPv6 prefix length {} exceeds 128",
                    self.ipv6_prefix_len
                )));
            }
            let addr = format!("{}/{}", ipv6, self.ipv6_prefix_len);
            let address_text = ipv6.to_string();
            if let Some(interface) =
                self.linux_address_on_other_interface("inet6", &address_text)?
            {
                return Err(RoutingError::CommandFailed(format!(
                    "Linux TUN IPv6 address {} already exists on interface {}; refusing address conflict",
                    ipv6, interface
                )));
            }
            if !self.linux_address_present("inet6", &address_text, self.ipv6_prefix_len)? {
                let result =
                    Self::run_ip_command(&["-6", "addr", "add", &addr, "dev", &self.tun_name]);
                if result.is_err()
                    && !self.linux_address_present("inet6", &address_text, self.ipv6_prefix_len)?
                {
                    return result;
                }
                self.ownership
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .ipv6_address_added = true;
            }
            self.verify_linux_addresses()?;
            log::debug!("TUN IPv6 address verified: {} on {}", addr, self.tun_name);
        }
        Ok(())
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn calculate_subnet(&self) -> String {
        // Simple CIDR calculation based on netmask
        let mask_bits = self.netmask.octets().iter().map(|b| b.count_ones()).sum::<u32>();

        let network = u32::from(self.server_ip) & u32::from(self.netmask);
        let network_ip = Ipv4Addr::from(network);

        format!("{}/{}", network_ip, mask_bits)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn calculate_subnet_checked(&self) -> Result<String, RoutingError> {
        let prefix = self.ipv4_prefix_len()?;
        let network = u32::from(self.server_ip) & u32::from(self.netmask);
        Ok(format!("{}/{}", Ipv4Addr::from(network), prefix))
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn ipv4_broadcast(&self) -> Ipv4Addr {
        let mask = u32::from(self.netmask);
        Ipv4Addr::from((u32::from(self.server_ip) & mask) | !mask)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn ipv4_fanout_destinations(&self) -> [String; 3] {
        [
            "255.255.255.255/32".to_string(),
            format!("{}/32", self.ipv4_broadcast()),
            "224.0.0.0/4".to_string(),
        ]
    }

    /// Calculate the IPv6 subnet CIDR (e.g., "fd00::/64").
    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn calculate_ipv6_subnet(&self) -> String {
        match self.server_ipv6 {
            Some(ip) => {
                let prefix = self.ipv6_prefix_len.min(128);
                let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                format!("{}/{}", Ipv6Addr::from(u128::from(ip) & mask), prefix)
            }
            None => String::new(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn calculate_ipv6_subnet_checked(&self) -> Result<String, RoutingError> {
        if self.ipv6_prefix_len > 128 {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "IPv6 prefix length {} exceeds 128",
                self.ipv6_prefix_len
            )));
        }
        Ok(self.calculate_ipv6_subnet())
    }
}
