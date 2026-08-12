use super::*;

impl RoutingManager {
    #[cfg(target_os = "linux")]
    fn linux_json(args: &[&str]) -> Result<serde_json::Value, RoutingError> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .map_err(|error| RoutingError::CommandFailed(format!("ip inspect spawn: {error}")))?;
        if !output.status.success() {
            return Err(RoutingError::CommandFailed(format!(
                "ip {} returned status {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        serde_json::from_slice(&output.stdout).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "ip {} returned invalid JSON: {error}",
                args.join(" ")
            ))
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_link_is_up(&self) -> Result<bool, RoutingError> {
        let value = Self::linux_json(&["-j", "link", "show", "dev", &self.tun_name])?;
        let item = value.as_array().and_then(|items| items.first()).ok_or_else(|| {
            RoutingError::CommandFailed(format!(
                "ip link inspection returned no device {}",
                self.tun_name
            ))
        })?;
        Ok(item
            .get("flags")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP"))))
    }

    #[cfg(target_os = "linux")]
    fn linux_interface_exists(&self) -> Result<bool, RoutingError> {
        let output = Command::new("ip")
            .args(["link", "show", "dev", &self.tun_name])
            .output()
            .map_err(|error| RoutingError::CommandFailed(format!("ip link existence: {error}")))?;
        if output.status.success() {
            return Ok(true);
        }
        let detail = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if detail.contains("does not exist") || detail.contains("cannot find device") {
            return Ok(false);
        }
        Err(RoutingError::CommandFailed(format!(
            "ip link show dev {} returned status {}: {}",
            self.tun_name,
            output.status,
            detail.trim()
        )))
    }

    #[cfg(target_os = "linux")]
    fn linux_interface_index(&self) -> Result<u32, RoutingError> {
        let value = Self::linux_json(&["-j", "link", "show", "dev", &self.tun_name])?;
        value
            .as_array()
            .and_then(|items| items.first())
            .and_then(|item| item.get("ifindex"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| {
                RoutingError::CommandFailed(format!(
                    "ip link inspection omitted a valid ifindex for {}",
                    self.tun_name
                ))
            })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_boot_id() -> Result<String, RoutingError> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| RoutingError::CommandFailed(format!("read Linux boot ID: {error}")))?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() {
            return Err(RoutingError::CommandFailed("Linux boot ID is empty".to_string()));
        }
        Ok(boot_id.to_string())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_process_start_time(pid: u32) -> Result<Option<u64>, RoutingError> {
        let path = format!("/proc/{pid}/stat");
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "read Linux process identity {path}: {error}"
                )))
            }
        };
        let fields = contents.rsplit_once(") ").map(|(_, fields)| fields).ok_or_else(|| {
            RoutingError::CommandFailed(format!("parse Linux process identity {path}"))
        })?;
        let start_time = fields
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| {
                RoutingError::CommandFailed(format!(
                    "Linux process identity {path} omitted the start time"
                ))
            })?
            .parse::<u64>()
            .map_err(|error| {
                RoutingError::CommandFailed(format!(
                    "parse Linux process start time in {path}: {error}"
                ))
            })?;
        Ok(Some(start_time))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn reject_active_owner(
        state: &PersistedRoutingOwnership,
    ) -> Result<(), RoutingError> {
        let current_boot_id = Self::linux_boot_id()?;
        if current_boot_id != state.owner_boot_id {
            return Err(RoutingError::CommandFailed(
            "durable routing state belongs to a different Linux boot; refusing guessed recovery"
                .to_string(),
        ));
        }
        if active_owner_matches(
            &state.owner_boot_id,
            &current_boot_id,
            state.owner_start_time,
            Self::linux_process_start_time(state.owner_pid)?,
        ) {
            return Err(RoutingError::CommandFailed(format!(
                "durable routing state is still owned by active PID {}",
                state.owner_pid
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_address_present(
        &self,
        family: &str,
        address: &str,
        prefix: u8,
    ) -> Result<bool, RoutingError> {
        let value = Self::linux_json(&["-j", "address", "show", "dev", &self.tun_name])?;
        let address_items = value
            .as_array()
            .and_then(|items| items.first())
            .and_then(|item| item.get("addr_info"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                RoutingError::CommandFailed(format!(
                    "ip address inspection omitted addr_info for {}",
                    self.tun_name
                ))
            })?;
        Ok(address_items.iter().any(|entry| {
            entry.get("family").and_then(serde_json::Value::as_str) == Some(family)
                && entry.get("local").and_then(serde_json::Value::as_str) == Some(address)
                && entry.get("prefixlen").and_then(serde_json::Value::as_u64)
                    == Some(u64::from(prefix))
        }))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_address_on_other_interface(
        &self,
        family: &str,
        address: &str,
    ) -> Result<Option<String>, RoutingError> {
        let value = Self::linux_json(&["-j", "address", "show"])?;
        let interfaces = value.as_array().ok_or_else(|| {
            RoutingError::CommandFailed(
                "ip address inspection returned no interface array".to_string(),
            )
        })?;
        for interface in interfaces {
            let Some(name) = interface.get("ifname").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if name == self.tun_name {
                continue;
            }
            let Some(addresses) = interface.get("addr_info").and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            if addresses.iter().any(|entry| {
                entry.get("family").and_then(serde_json::Value::as_str) == Some(family)
                    && entry.get("local").and_then(serde_json::Value::as_str) == Some(address)
            }) {
                return Ok(Some(name.to_string()));
            }
        }
        Ok(None)
    }

    #[cfg(target_os = "linux")]
    fn validate_forwarding_mutation(
        label: &str,
        mutation: &TextMutation,
    ) -> Result<(), RoutingError> {
        if !matches!(mutation.before.trim(), "0" | "1") || mutation.after.trim() != "1" {
            return Err(RoutingError::CommandFailed(format!(
                "durable routing state has invalid {label} forwarding mutation"
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn validate_persisted_ownership(
        &self,
        state: &PersistedRoutingOwnership,
    ) -> Result<(), RoutingError> {
        if state.schema != ROUTING_STATE_SCHEMA {
            return Err(RoutingError::CommandFailed(format!(
                "unsupported durable routing state schema {}",
                state.schema
            )));
        }
        let expected_ipv6 = self.server_ipv6.map(|address| address.to_string());
        if state.tun_name != self.tun_name
            || state.server_ipv4 != self.server_ip.to_string()
            || state.netmask != self.netmask.to_string()
            || state.wan_interface != self.wan_interface
            || state.server_ipv6 != expected_ipv6
            || state.ipv6_prefix_len != self.ipv6_prefix_len
            || state.firewall_backend != self.firewall_backend
            || state.client_to_client_enabled != self.client_to_client_enabled
        {
            return Err(RoutingError::CommandFailed(
                "durable routing state identity does not match the requested server routing"
                    .to_string(),
            ));
        }
        if self.ipv6_prefix_len > 128 {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "IPv6 prefix length {} exceeds 128",
                self.ipv6_prefix_len
            )));
        }
        if state.interface_index == 0 {
            return Err(RoutingError::CommandFailed(
                "durable routing state has an invalid Linux interface index".to_string(),
            ));
        }
        if state.owner_boot_id.trim().is_empty()
            || state.owner_pid == 0
            || state.owner_start_time == 0
        {
            return Err(RoutingError::CommandFailed(
                "durable routing state has an invalid process ownership identity".to_string(),
            ));
        }
        if state.firewall_owner_generation.trim().is_empty() {
            return Err(RoutingError::CommandFailed(
                "durable routing state has no firewall ownership generation".to_string(),
            ));
        }
        if !state.ipv4_address.after || !state.link_up.after {
            return Err(RoutingError::CommandFailed(
                "durable routing state does not describe the expected Linux postcondition"
                    .to_string(),
            ));
        }
        if state.ipv6_address.is_some() != self.server_ipv6.is_some()
            || state.ipv6_address.as_ref().is_some_and(|mutation| !mutation.after)
        {
            return Err(RoutingError::CommandFailed(
                "durable routing state has an invalid IPv6 address ownership record".to_string(),
            ));
        }
        Self::validate_forwarding_mutation("IPv4", &state.ipv4_forwarding)?;
        if let Some(mutation) = state.ipv6_forwarding.as_ref() {
            Self::validate_forwarding_mutation("IPv6", mutation)?;
        } else if self.server_ipv6.is_some() {
            return Err(RoutingError::CommandFailed(
                "durable routing state is missing IPv6 forwarding ownership".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn read_persisted_ownership(
        &self,
    ) -> Result<Option<PersistedRoutingOwnership>, RoutingError> {
        let contents = match std::fs::read_to_string(&self.ownership_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "read durable routing state {}: {error}",
                    self.ownership_path.display()
                )))
            }
        };
        serde_json::from_str(&contents).map(Some).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "parse durable routing state {}: {error}",
                self.ownership_path.display()
            ))
        })
    }

    #[cfg(target_os = "linux")]
    fn ensure_ownership_directory(&self) -> Result<(), RoutingError> {
        let parent = self.ownership_path.parent().ok_or_else(|| {
            RoutingError::CommandFailed("durable routing state has no parent directory".to_string())
        })?;
        std::fs::create_dir_all(parent).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "create durable routing state directory {}: {error}",
                parent.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |error| {
                    RoutingError::CommandFailed(format!(
                        "secure durable routing state directory {}: {error}",
                        parent.display()
                    ))
                },
            )?;
            let mode = std::fs::metadata(parent)
                .map_err(|error| {
                    RoutingError::CommandFailed(format!(
                        "inspect durable routing state directory {}: {error}",
                        parent.display()
                    ))
                })?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o700 {
                return Err(RoutingError::CommandFailed(format!(
                    "durable routing state directory {} has unsafe mode {:o}",
                    parent.display(),
                    mode
                )));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn persist_ownership(&self, state: &PersistedRoutingOwnership) -> Result<(), RoutingError> {
        match std::fs::symlink_metadata(&self.ownership_path) {
            Ok(_) => {
                return Err(RoutingError::CommandFailed(format!(
            "durable routing state {} already exists; stale recovery is required before setup",
            self.ownership_path.display()
        )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "inspect durable routing state {}: {error}",
                    self.ownership_path.display()
                )))
            }
        }
        self.ensure_ownership_directory()?;
        let bytes = serde_json::to_vec_pretty(state).map_err(|error| {
            RoutingError::CommandFailed(format!("serialize durable routing state: {error}"))
        })?;
        crate::implementations::server::fsutil::atomic_write_file(
            &self.ownership_path,
            &bytes,
            Some(0o600),
            "server::routing_ownership_tmp_nonce",
        )
        .map_err(|error| {
            RoutingError::CommandFailed(format!(
                "persist durable routing state {}: {error}",
                self.ownership_path.display()
            ))
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn remove_ownership_file(&self) -> Result<(), RoutingError> {
        match std::fs::remove_file(&self.ownership_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(RoutingError::CommandFailed(format!(
                "remove durable routing state {}: {error}",
                self.ownership_path.display()
            ))),
        }
    }

    #[cfg(target_os = "linux")]
    fn firewall_owner_path(&self) -> PathBuf {
        Path::new(ROUTING_STATE_DIR).join(ROUTING_FIREWALL_OWNER_FILE)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn read_firewall_ownership(
        &self,
    ) -> Result<Option<PersistedFirewallOwnership>, RoutingError> {
        let path = self.firewall_owner_path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "inspect durable firewall ownership {}: {error}",
                    path.display()
                )))
            }
        };
        if !metadata.file_type().is_file() {
            return Err(RoutingError::CommandFailed(format!(
                "durable firewall ownership {} is not a regular file",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(RoutingError::CommandFailed(format!(
                    "durable firewall ownership {} has unsafe mode {:o}",
                    path.display(),
                    mode
                )));
            }
        }
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "read durable firewall ownership {}: {error}",
                path.display()
            ))
        })?;
        let owner =
            serde_json::from_str::<PersistedFirewallOwnership>(&contents).map_err(|error| {
                RoutingError::CommandFailed(format!(
                    "parse durable firewall ownership {}: {error}",
                    path.display()
                ))
            })?;
        Self::validate_firewall_owner_shape(&owner)?;
        Ok(Some(owner))
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn validate_firewall_owner_shape(
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        if owner.schema != FIREWALL_OWNER_SCHEMA {
            return Err(RoutingError::CommandFailed(format!(
                "unsupported durable firewall ownership schema {}",
                owner.schema
            )));
        }
        if owner.tun_name.is_empty()
            || owner.owner_boot_id.trim().is_empty()
            || owner.owner_pid == 0
            || owner.owner_start_time == 0
            || owner.owner_generation.trim().is_empty()
            || owner.firewall_identity != firewall_identity(owner.firewall_backend)
        {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership has an invalid identity".to_string(),
            ));
        }
        let expected_generation = firewall_owner_generation(
            &owner.tun_name,
            &owner.owner_boot_id,
            owner.owner_pid,
            owner.owner_start_time,
        );
        if owner.owner_generation != expected_generation {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership generation does not match its process identity"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn validate_firewall_owner_for_manager(
        &self,
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        Self::validate_firewall_owner_shape(owner)?;
        if owner.tun_name != self.tun_name
            || owner.firewall_backend != self.firewall_backend
            || owner.server_ipv4 != self.server_ip.to_string()
            || owner.netmask != self.netmask.to_string()
            || owner.wan_interface != self.wan_interface
            || owner.server_ipv6 != self.server_ipv6.map(|address| address.to_string())
            || owner.ipv6_prefix_len != self.ipv6_prefix_len
            || owner.client_to_client_enabled != self.client_to_client_enabled
        {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership identity does not match the requested server routing"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn firewall_owner_from_state(
        state: &PersistedRoutingOwnership,
    ) -> PersistedFirewallOwnership {
        PersistedFirewallOwnership {
            schema: FIREWALL_OWNER_SCHEMA,
            owner_generation: state.firewall_owner_generation.clone(),
            tun_name: state.tun_name.clone(),
            firewall_backend: state.firewall_backend,
            firewall_identity: firewall_identity(state.firewall_backend).to_string(),
            owner_boot_id: state.owner_boot_id.clone(),
            owner_pid: state.owner_pid,
            owner_start_time: state.owner_start_time,
            server_ipv4: state.server_ipv4.clone(),
            netmask: state.netmask.clone(),
            wan_interface: state.wan_interface.clone(),
            server_ipv6: state.server_ipv6.clone(),
            ipv6_prefix_len: state.ipv6_prefix_len,
            client_to_client_enabled: state.client_to_client_enabled,
        }
    }

    #[cfg(target_os = "linux")]
    fn persist_firewall_ownership(
        &self,
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        use std::io::Write;

        let path = self.firewall_owner_path();
        let bytes = serde_json::to_vec_pretty(owner).map_err(|error| {
            RoutingError::CommandFailed(format!("serialize durable firewall ownership: {error}"))
        })?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "create durable firewall ownership {}: {error}",
                path.display()
            ))
        })?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&path);
            return Err(RoutingError::CommandFailed(format!(
                "write durable firewall ownership {}: {error}",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |error| {
                    let _ = std::fs::remove_file(&path);
                    RoutingError::CommandFailed(format!(
                        "secure durable firewall ownership {}: {error}",
                        path.display()
                    ))
                },
            )?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn remove_firewall_ownership(
        &self,
        expected: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        let path = self.firewall_owner_path();
        let Some(current) = self.read_firewall_ownership()? else {
            return Err(RoutingError::CommandFailed(format!(
                "durable firewall ownership {} is missing; refusing release",
                path.display()
            )));
        };
        if &current != expected {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership changed externally; refusing release".to_string(),
            ));
        }
        std::fs::remove_file(&path).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "remove durable firewall ownership {}: {error}",
                path.display()
            ))
        })
    }

    #[cfg(target_os = "linux")]
    fn reject_other_routing_owners(&self) -> Result<(), RoutingError> {
        for tun_name in persisted_tun_names()? {
            if firewall_claim_decision(&self.tun_name, Some(&tun_name), false, false, false)
                == FirewallClaimDecision::RejectForeignRoutingOwner
            {
                return Err(RoutingError::CommandFailed(format!(
                "durable routing state for TUN {tun_name} already exists; one server firewall owner per network namespace is supported"
            )));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn fixed_firewall_resource_present(&self) -> Result<bool, RoutingError> {
        for program in ["iptables", "ip6tables"] {
            for (table, parent, owned) in [
                ("filter", "FORWARD", Self::IPTABLES_FILTER_CHAIN),
                ("nat", "POSTROUTING", Self::IPTABLES_NAT_CHAIN),
            ] {
                let (jumps, chain) =
                    crate::firewall::inspect_iptables_owned(program, table, parent, owned)
                        .map_err(RoutingError::CommandFailed)?;
                if jumps > 0 || chain {
                    return Ok(true);
                }
            }
        }
        crate::firewall::nft_table_exists("inet", Self::NFT_RT_TABLE)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn ensure_fixed_firewall_resources_absent(&self) -> Result<(), RoutingError> {
        let fixed_resource_present = self.fixed_firewall_resource_present()?;
        if firewall_claim_decision(&self.tun_name, None, false, false, fixed_resource_present)
            == FirewallClaimDecision::RejectExistingResource
        {
            return Err(RoutingError::CommandFailed(
            "fixed QuicFuscate server firewall identity already exists; refusing replacement or collision"
                .to_string(),
        ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn claim_firewall_ownership(
        &self,
        state: &PersistedRoutingOwnership,
    ) -> Result<(), RoutingError> {
        let owner = Self::firewall_owner_from_state(state);
        self.ensure_ownership_directory()?;
        match self.persist_firewall_ownership(&owner) {
            Ok(()) => {}
            Err(error) => {
                if self.firewall_owner_path().exists() {
                    let existing = self.read_firewall_ownership()?.ok_or_else(|| {
                        RoutingError::CommandFailed(
                            "durable firewall ownership disappeared during collision check"
                                .to_string(),
                        )
                    })?;
                    let current_boot_id = Self::linux_boot_id()?;
                    let owner_active = active_owner_matches(
                        &existing.owner_boot_id,
                        &current_boot_id,
                        existing.owner_start_time,
                        Self::linux_process_start_time(existing.owner_pid)?,
                    );
                    match firewall_claim_decision(
                        &self.tun_name,
                        Some(&existing.tun_name),
                        owner_active,
                        true,
                        false,
                    ) {
                        FirewallClaimDecision::RejectActiveOwner => {
                            return Err(RoutingError::CommandFailed(format!(
                                "durable firewall identity is owned by active PID {}",
                                existing.owner_pid
                            )));
                        }
                        FirewallClaimDecision::RejectForeignRoutingOwner => {
                            return Err(RoutingError::CommandFailed(format!(
                            "durable firewall identity belongs to TUN {}; refusing cross-TUN claim",
                            existing.tun_name
                        )));
                        }
                        FirewallClaimDecision::RejectStaleOwner => {
                            return Err(RoutingError::CommandFailed(
                            "durable firewall identity has a stale owner; explicit stale recovery is required"
                                .to_string(),
                        ));
                        }
                        _ => {}
                    }
                }
                return Err(error);
            }
        }
        if let Err(error) = self.ensure_fixed_firewall_resources_absent() {
            let _ = self.remove_firewall_ownership(&owner);
            return Err(error);
        }
        self.ownership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .firewall_owner_generation = Some(owner.owner_generation);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn prepare_persisted_ownership(&self) -> Result<(), RoutingError> {
        self.reject_other_routing_owners()?;
        let ipv4_prefix = self.ipv4_prefix_len()?;
        if self.server_ipv6.is_some() && self.ipv6_prefix_len > 128 {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "IPv6 prefix length {} exceeds 128",
                self.ipv6_prefix_len
            )));
        }
        let ipv4_address =
            self.linux_address_present("inet", &self.server_ip.to_string(), ipv4_prefix)?;
        let interface_index = self.linux_interface_index()?;
        let owner_boot_id = Self::linux_boot_id()?;
        let owner_pid = std::process::id();
        let owner_start_time = Self::linux_process_start_time(owner_pid)?.ok_or_else(|| {
            RoutingError::CommandFailed(format!(
                "current Linux process {} disappeared during ownership preparation",
                owner_pid
            ))
        })?;
        let link_up = self.linux_link_is_up()?;
        let ipv4_forwarding =
            std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").map_err(|error| {
                RoutingError::CommandFailed(format!("read IPv4 forwarding: {error}"))
            })?;
        let ipv6_address = if let Some(address) = self.server_ipv6 {
            Some(self.linux_address_present("inet6", &address.to_string(), self.ipv6_prefix_len)?)
        } else {
            None
        };
        let ipv6_forwarding = if self.server_ipv6.is_some() {
            Some(std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").map_err(
                |error| RoutingError::CommandFailed(format!("read IPv6 forwarding: {error}")),
            )?)
        } else {
            None
        };
        let firewall_owner_generation =
            firewall_owner_generation(&self.tun_name, &owner_boot_id, owner_pid, owner_start_time);
        let state = PersistedRoutingOwnership {
            schema: ROUTING_STATE_SCHEMA,
            tun_name: self.tun_name.clone(),
            interface_index,
            owner_boot_id,
            owner_pid,
            owner_start_time,
            server_ipv4: self.server_ip.to_string(),
            netmask: self.netmask.to_string(),
            wan_interface: self.wan_interface.clone(),
            server_ipv6: self.server_ipv6.map(|address| address.to_string()),
            ipv6_prefix_len: self.ipv6_prefix_len,
            firewall_backend: self.firewall_backend,
            firewall_owner_generation,
            client_to_client_enabled: self.client_to_client_enabled,
            ipv4_address: BoolMutation { before: ipv4_address, after: true },
            ipv6_address: ipv6_address.map(|before| BoolMutation { before, after: true }),
            link_up: BoolMutation { before: link_up, after: true },
            ipv4_forwarding: TextMutation { before: ipv4_forwarding, after: "1".to_string() },
            ipv6_forwarding: ipv6_forwarding
                .map(|before| TextMutation { before, after: "1".to_string() }),
        };
        self.validate_persisted_ownership(&state)?;
        self.claim_firewall_ownership(&state)?;
        if let Err(error) = self.persist_ownership(&state) {
            let owner = Self::firewall_owner_from_state(&state);
            let _ = self.remove_firewall_ownership(&owner);
            return Err(error);
        }
        self.ownership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .firewall_owner_generation = Some(state.firewall_owner_generation.clone());
        self.ownership.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).state_prepared =
            true;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_address(
        &self,
        family: &str,
        address: &str,
        prefix: u8,
        mutation: &BoolMutation,
    ) -> Result<(), RoutingError> {
        let current = self.linux_address_present(family, address, prefix)?;
        match recovery_decision(&mutation.before, &mutation.after, &current) {
        RecoveryDecision::Noop => Ok(()),
        RecoveryDecision::Restore => self.remove_linux_address(family, address, prefix),
        RecoveryDecision::Conflict => Err(RoutingError::CommandFailed(format!(
            "not removing durable {} address {address}/{prefix}: interface state changed externally",
            family
        ))),
    }
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_link(&self, mutation: &BoolMutation) -> Result<(), RoutingError> {
        let current = self.linux_link_is_up()?;
        match recovery_decision(&mutation.before, &mutation.after, &current) {
            RecoveryDecision::Noop => Ok(()),
            RecoveryDecision::Restore => self.set_linux_link_down(),
            RecoveryDecision::Conflict => Err(RoutingError::CommandFailed(format!(
                "not lowering durable Linux TUN link {}: link state changed externally",
                self.tun_name
            ))),
        }
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_forwarding(
        &self,
        path: &str,
        mutation: &TextMutation,
    ) -> Result<(), RoutingError> {
        let current = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("read {path}: {error}")))?;
        let before = mutation.before.trim();
        let after = mutation.after.trim();
        let current_value = current.trim();
        match recovery_decision(&before, &after, &current_value) {
        RecoveryDecision::Noop => Ok(()),
        RecoveryDecision::Restore => self.restore_forwarding(path, &mutation.before),
        RecoveryDecision::Conflict => Err(RoutingError::CommandFailed(format!(
            "not restoring {path}: durable owner expected {:?} or {:?}, found {:?}; preserving external state",
            before, after, current_value
        ))),
    }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn recover_persisted_ownership(&self) -> Result<bool, RoutingError> {
        self.recover_persisted_ownership_with_active_check(true)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn recover_current_persisted_ownership(&self) -> Result<bool, RoutingError> {
        self.recover_persisted_ownership_with_active_check(false)
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_ownership_with_active_check(
        &self,
        reject_active: bool,
    ) -> Result<bool, RoutingError> {
        let Some(state) = self.read_persisted_ownership()? else {
            return Ok(false);
        };
        self.validate_persisted_ownership(&state)?;
        if reject_active {
            Self::reject_active_owner(&state)?;
        }
        let mut failures = Vec::new();
        if self.linux_interface_exists()? {
            if self.linux_interface_index()? != state.interface_index {
                failures.push(format!(
                    "not recovering Linux TUN {}: interface identity changed externally",
                    self.tun_name
                ));
            } else {
                Self::record_cleanup_failure(
                    &mut failures,
                    self.recover_persisted_address(
                        "inet",
                        &self.server_ip.to_string(),
                        self.ipv4_prefix_len()?,
                        &state.ipv4_address,
                    ),
                );
                if let (Some(address), Some(mutation)) =
                    (self.server_ipv6, state.ipv6_address.as_ref())
                {
                    Self::record_cleanup_failure(
                        &mut failures,
                        self.recover_persisted_address(
                            "inet6",
                            &address.to_string(),
                            self.ipv6_prefix_len,
                            mutation,
                        ),
                    );
                }
                Self::record_cleanup_failure(
                    &mut failures,
                    self.recover_persisted_link(&state.link_up),
                );
            }
        }
        Self::record_cleanup_failure(
            &mut failures,
            self.recover_persisted_forwarding(
                "/proc/sys/net/ipv4/ip_forward",
                &state.ipv4_forwarding,
            ),
        );
        if let Some(mutation) = state.ipv6_forwarding.as_ref() {
            Self::record_cleanup_failure(
                &mut failures,
                self.recover_persisted_forwarding(
                    "/proc/sys/net/ipv6/conf/all/forwarding",
                    mutation,
                ),
            );
        }
        Self::finish_cleanup(failures)?;
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn ipv4_prefix_len(&self) -> Result<u8, RoutingError> {
        let raw = u32::from(self.netmask);
        let prefix = raw.leading_ones();
        let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        if raw != canonical {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "server IPv4 netmask {} is not contiguous",
                self.netmask
            )));
        }
        Ok(prefix as u8)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn verify_linux_addresses(&self) -> Result<(), RoutingError> {
        let prefix = self.ipv4_prefix_len()?;
        let address = self.server_ip.to_string();
        if !self.linux_address_present("inet", &address, prefix)? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} is missing IPv4 address {}/{}",
                self.tun_name, address, prefix
            )));
        }
        if let Some(ipv6) = self.server_ipv6 {
            let address = ipv6.to_string();
            if self.ipv6_prefix_len > 128
                || !self.linux_address_present("inet6", &address, self.ipv6_prefix_len)?
            {
                return Err(RoutingError::CommandFailed(format!(
                    "Linux TUN {} is missing IPv6 address {}/{}",
                    self.tun_name, address, self.ipv6_prefix_len
                )));
            }
        }
        if !self.linux_link_is_up()? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} is not administratively up",
                self.tun_name
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn current_firewall_owner(
        &self,
    ) -> Result<PersistedFirewallOwnership, RoutingError> {
        let state = self.read_persisted_ownership()?.ok_or_else(|| {
            RoutingError::CommandFailed(
                "durable routing state is missing; refusing firewall mutation".to_string(),
            )
        })?;
        self.validate_persisted_ownership(&state)?;
        let expected = Self::firewall_owner_from_state(&state);
        let current = self.read_firewall_ownership()?.ok_or_else(|| {
            RoutingError::CommandFailed(
                "durable firewall ownership is missing; refusing firewall mutation".to_string(),
            )
        })?;
        self.validate_firewall_owner_for_manager(&current)?;
        if current != expected {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership does not match the routing record; refusing mutation"
                    .to_string(),
            ));
        }
        Ok(current)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn verify_owned_firewall_resource(
        &self,
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        let subnet = self.calculate_subnet_checked()?;
        match owner.firewall_backend {
            crate::firewall::FirewallBackend::Iptables => {
                self.verify_iptables_family("iptables", &subnet, false)?;
                if self.server_ipv6.is_some() {
                    let v6_subnet = self.calculate_ipv6_subnet_checked()?;
                    self.verify_iptables_family("ip6tables", &v6_subnet, true)?;
                }
            }
            crate::firewall::FirewallBackend::Nftables => {
                let required_fragments = self.nftables_required_fragments(&subnet);
                let required_refs =
                    required_fragments.iter().map(String::as_str).collect::<Vec<_>>();
                crate::firewall::verify_nft_table_owner(
                    "inet",
                    Self::NFT_RT_TABLE,
                    &Self::nft_owner_marker(&owner.owner_generation),
                    &required_refs,
                    self.nftables_expected_rule_count(),
                )
                .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn ensure_owned_firewall_absent(&self) -> Result<(), RoutingError> {
        if self.fixed_firewall_resource_present()? {
            return Err(RoutingError::CommandFailed(
            "managed firewall resources remain without a configured ownership generation; refusing guessed cleanup"
                .to_string(),
        ));
        }
        Ok(())
    }
}
