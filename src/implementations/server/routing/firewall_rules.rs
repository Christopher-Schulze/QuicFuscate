#[cfg(any(test, target_os = "linux"))]
use super::{RoutingError, RoutingManager};

#[cfg(any(test, target_os = "linux"))]
impl RoutingManager {
    pub(super) const IPTABLES_FILTER_CHAIN: &'static str = "QUICFUSCATE_RT";

    pub(super) const IPTABLES_NAT_CHAIN: &'static str = "QUICFUSCATE_NAT";

    pub(super) fn iptables_ruleset(
        &self,
        subnet: &str,
        ipv6: bool,
        install_nat_jump: bool,
        install_filter_jump: bool,
    ) -> String {
        let mut rules = format!(
            "*nat\n\
             :{} - [0:0]\n\
             -A {} -s {} -o {} -j MASQUERADE\n",
            Self::IPTABLES_NAT_CHAIN,
            Self::IPTABLES_NAT_CHAIN,
            subnet,
            self.wan_interface,
        );
        if install_nat_jump {
            rules.push_str(&format!("-I POSTROUTING 1 -j {}\n", Self::IPTABLES_NAT_CHAIN));
        }
        rules.push_str(&format!(
            "COMMIT\n\
             *filter\n\
             :{} - [0:0]\n\
             -A {} -i {} -o {} -j ACCEPT\n",
            Self::IPTABLES_FILTER_CHAIN,
            Self::IPTABLES_FILTER_CHAIN,
            self.tun_name,
            self.wan_interface,
        ));

        if ipv6 {
            rules.push_str(&format!(
                "-A {} -i {} -o {} -d ff00::/8 -j ACCEPT\n",
                Self::IPTABLES_FILTER_CHAIN,
                self.tun_name,
                self.tun_name,
            ));
        } else {
            for destination in [
                "255.255.255.255/32".to_string(),
                format!("{}/32", self.ipv4_broadcast()),
                "224.0.0.0/4".to_string(),
            ] {
                rules.push_str(&format!(
                    "-A {} -i {} -o {} -d {} -j ACCEPT\n",
                    Self::IPTABLES_FILTER_CHAIN,
                    self.tun_name,
                    self.tun_name,
                    destination,
                ));
            }
        }

        let isolation_action = if self.client_to_client_enabled { "ACCEPT" } else { "DROP" };
        rules.push_str(&format!(
            "-A {} -i {} -o {} -j {}\n\
             -A {} -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT\n",
            Self::IPTABLES_FILTER_CHAIN,
            self.tun_name,
            self.tun_name,
            isolation_action,
            Self::IPTABLES_FILTER_CHAIN,
            self.wan_interface,
            self.tun_name,
        ));
        if install_filter_jump {
            rules.push_str(&format!("-I FORWARD 1 -j {}\n", Self::IPTABLES_FILTER_CHAIN));
        }
        rules.push_str("COMMIT\n");
        rules
    }
}

#[cfg(any(test, target_os = "linux"))]
impl RoutingManager {
    /// Dedicated nftables table name for QuicFuscate server routing/NAT rules.
    pub(super) const NFT_RT_TABLE: &'static str = "quicfuscate_rt";

    #[cfg(test)]
    pub(super) fn nftables_ruleset(&self, subnet: &str) -> String {
        self.nftables_ruleset_with_owner(subnet, "unowned")
    }

    pub(super) fn nft_owner_marker(owner_generation: &str) -> String {
        format!("quicfuscate-owner-{owner_generation}")
    }

    pub(super) fn nftables_ruleset_with_owner(
        &self,
        subnet: &str,
        owner_generation: &str,
    ) -> String {
        let v6_masquerade = if self.is_ipv6_enabled() {
            let v6_subnet = self.calculate_ipv6_subnet();
            format!(
                "ip6 saddr {} oifname \"{}\" masquerade comment \"{}\"\n",
                v6_subnet,
                self.wan_interface,
                Self::nft_owner_marker(owner_generation)
            )
        } else {
            String::new()
        };
        let v6_fanout = if self.is_ipv6_enabled() {
            format!(
                "iifname \"{}\" oifname \"{}\" ip6 daddr ff00::/8 accept comment \"{}\"\n",
                self.tun_name,
                self.tun_name,
                Self::nft_owner_marker(owner_generation)
            )
        } else {
            String::new()
        };
        let isolation_action = if self.client_to_client_enabled { "accept" } else { "drop" };
        let directed_broadcast = self.ipv4_broadcast();

        format!(
            "table inet {table} {{\n\
             \x20   comment \"{owner_marker}\"\n\
             \x20   chain postrouting {{\n\
             \x20       type nat hook postrouting priority 100; policy accept;\n\
             \x20       ip saddr {subnet} oifname \"{wan}\" masquerade comment \"{owner_marker}\"\n\
             \x20       {v6_masquerade}\
             \x20   }}\n\
             \x20   chain forward {{\n\
             \x20       type filter hook forward priority 0; policy accept;\n\
             \x20       iifname \"{tun}\" oifname \"{tun}\" ip daddr {{ 255.255.255.255, {directed_broadcast}, 224.0.0.0/4 }} accept comment \"{owner_marker}\"\n\
             \x20       {v6_fanout}\
             \x20       iifname \"{tun}\" oifname \"{tun}\" {isolation_action} comment \"{owner_marker}\"\n\
             \x20       iifname \"{tun}\" oifname \"{wan}\" accept comment \"{owner_marker}\"\n\
             \x20       iifname \"{wan}\" oifname \"{tun}\" ct state established,related accept comment \"{owner_marker}\"\n\
             \x20   }}\n\
             }}\n",
            table = Self::NFT_RT_TABLE,
            owner_marker = Self::nft_owner_marker(owner_generation),
            subnet = subnet,
            wan = self.wan_interface,
            v6_masquerade = v6_masquerade,
            v6_fanout = v6_fanout,
            tun = self.tun_name,
            directed_broadcast = directed_broadcast,
            isolation_action = isolation_action,
        )
    }

    pub(super) fn nftables_initial_transaction(
        ruleset: &str,
        table_exists: bool,
    ) -> Result<String, RoutingError> {
        if table_exists {
            Err(RoutingError::CommandFailed(format!(
                "nftables table inet {} already exists; refusing replacement",
                Self::NFT_RT_TABLE
            )))
        } else {
            Ok(ruleset.to_string())
        }
    }

    pub(super) fn nftables_required_fragments(&self, subnet: &str) -> Vec<String> {
        let mut required_fragments = vec![
            "chain postrouting".to_string(),
            "chain forward".to_string(),
            format!(
                "ip saddr {subnet} oifname \"{}\" masquerade",
                self.wan_interface
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" ip daddr {{ 255.255.255.255, {}, 224.0.0.0/4 }} accept",
                self.tun_name,
                self.tun_name,
                self.ipv4_broadcast()
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" {}",
                self.tun_name,
                self.tun_name,
                if self.client_to_client_enabled { "accept" } else { "drop" }
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" accept",
                self.tun_name, self.wan_interface
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" ct state established,related accept",
                self.wan_interface, self.tun_name
            ),
        ];
        if self.server_ipv6.is_some() {
            required_fragments.push(format!(
                "ip6 saddr {} oifname \"{}\" masquerade",
                self.calculate_ipv6_subnet(),
                self.wan_interface
            ));
            required_fragments.push(format!(
                "iifname \"{}\" oifname \"{}\" ip6 daddr ff00::/8 accept",
                self.tun_name, self.tun_name
            ));
        }
        required_fragments
    }

    pub(super) fn nftables_expected_rule_count(&self) -> usize {
        if self.server_ipv6.is_some() {
            7
        } else {
            5
        }
    }
}

#[cfg(test)]
impl RoutingManager {
    const WINDOWS_NAT_NAME: &'static str = "QuicFuscateNat";

    #[cfg(target_os = "macos")]
    pub(super) fn pf_rules(&self, subnet: &str, ipv6_subnet: Option<&str>) -> String {
        let fanout_v4 = format!(
            "pass quick on {} inet from {} to {{ 255.255.255.255, {}, 224.0.0.0/4 }} keep state\n",
            self.tun_name,
            subnet,
            self.ipv4_broadcast()
        );
        let isolation_v4 = if self.client_to_client_enabled {
            String::new()
        } else {
            format!("block drop quick on {} inet from {} to {}\n", self.tun_name, subnet, subnet)
        };
        let mut rules = format!(
            "nat on {} from {} to any -> ({})\n\
             {}\
             {}\
             pass quick on {} inet from {} to any keep state\n\
             pass quick on {} inet from any to {} keep state\n",
            self.wan_interface,
            subnet,
            self.wan_interface,
            fanout_v4,
            isolation_v4,
            self.tun_name,
            subnet,
            self.wan_interface,
            subnet
        );
        if let Some(ipv6_subnet) = ipv6_subnet {
            let isolation_v6 = if self.client_to_client_enabled {
                String::new()
            } else {
                format!(
                    "block drop quick on {} inet6 from {} to {}\n",
                    self.tun_name, ipv6_subnet, ipv6_subnet
                )
            };
            rules.push_str(&format!(
                "nat on {} inet6 from {} to any -> ({})\n\
                 pass quick on {} inet6 from {} to ff00::/8 keep state\n{}\
                 pass quick on {} inet6 from {} to any keep state\n\
                 pass quick on {} inet6 from any to {} keep state\n",
                self.wan_interface,
                ipv6_subnet,
                self.wan_interface,
                self.tun_name,
                ipv6_subnet,
                isolation_v6,
                self.tun_name,
                ipv6_subnet,
                self.wan_interface,
                ipv6_subnet
            ));
        }
        rules
    }

    pub(super) fn windows_nat_script(&self, subnet: &str) -> String {
        let nat_name = Self::WINDOWS_NAT_NAME;
        format!(
            "$ErrorActionPreference='Stop'; \
             if (Get-NetNat -Name '{nat_name}' -ErrorAction SilentlyContinue) {{ \
               Remove-NetNat -Name '{nat_name}' -Confirm:$false | Out-Null \
             }}; \
             New-NetNat -Name '{nat_name}' -InternalIPInterfaceAddressPrefix '{subnet}' | Out-Null"
        )
    }

    pub(super) fn validate_windows_contract(&self) -> Result<(), RoutingError> {
        if self.is_ipv6_enabled() {
            return Err(RoutingError::UnsupportedConfiguration(
                "Windows WinNAT does not provide IPv6 NAT; use routed IPv6 or run the dual-stack server on Linux/macOS"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
