//! Native Windows Filtering Platform kill switch.
//!
//! Policy objects are persistent and replaced transactionally. A process crash
//! therefore retains the last fail-closed state, while startup cleanup removes
//! only QuicFuscate's fixed object identities.

use super::{KillSwitchError, VpnFirewallPolicy};
use std::net::IpAddr;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
    FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmProviderAdd0,
    FwpmProviderDeleteByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER0, FWPM_FILTER0_0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V6, FWPM_PROVIDER0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_EMPTY,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8,
    FWP_VALUE0, FWP_VALUE0_0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const LEGACY_BLOCK_RULE: &str = "QuicFuscate-KillSwitch-Block";
const LEGACY_VPN_RULE: &str = "QuicFuscate-KillSwitch-VPN";

const PROVIDER_KEY: GUID = GUID::from_u128(0xd7fa9887_09af_4cc8_8944_0993ff31c5b8);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x62fb4f2e_1603_46fe_8109_1f53e6c84077);
const FILTER_KEY_NAMESPACE: u128 = 0x608fc680_76dd_43fb_81cf_000000000000;
const SUBLAYER_WEIGHT: u16 = 0x7fff;
const PERMIT_WEIGHT_RANGE: u8 = 15;
const BLOCK_WEIGHT_RANGE: u8 = 0;
const IP_PROTOCOL_UDP: u8 = 17;
const TRANSACTION_WAIT_MS: u32 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layer {
    OutboundTransportV4,
    OutboundTransportV6,
}

impl Layer {
    // Windows locates these filters at the top of the network layer so they
    // also classify third-party transports and raw packets while retaining
    // the protocol/port fields required for an exact VPN endpoint exception.
    const ALL: [Self; 2] = [Self::OutboundTransportV4, Self::OutboundTransportV6];

    const fn key(self) -> GUID {
        match self {
            Self::OutboundTransportV4 => FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            Self::OutboundTransportV6 => FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        }
    }

    const fn is_ipv6(self) -> bool {
        matches!(self, Self::OutboundTransportV6)
    }

    const fn slot_base(self) -> u8 {
        match self {
            Self::OutboundTransportV4 => 0,
            Self::OutboundTransportV6 => 4,
        }
    }
}

#[derive(Clone, Copy)]
enum FilterKind {
    Loopback = 1,
    Endpoint = 2,
    Tunnel = 3,
    Block = 4,
}

const fn filter_key_value(layer: Layer, kind: FilterKind) -> u128 {
    FILTER_KEY_NAMESPACE | (layer.slot_base() + kind as u8) as u128
}

const fn filter_key(layer: Layer, kind: FilterKind) -> GUID {
    GUID::from_u128(filter_key_value(layer, kind))
}

pub(super) struct WindowsKillSwitch {
    rules_active: AtomicBool,
    operation: Mutex<()>,
}

impl WindowsKillSwitch {
    pub(super) fn new() -> Self {
        Self { rules_active: AtomicBool::new(false), operation: Mutex::new(()) }
    }

    pub(super) fn block_traffic(&self) -> Result<(), KillSwitchError> {
        let _operation = self.operation.lock().map_err(|_| {
            KillSwitchError::CommandFailed("Windows WFP operation lock poisoned".to_string())
        })?;
        Self::replace_policy(None, false)?;
        Self::cleanup_legacy_rules()?;
        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Windows kill switch: persistent WFP block policy committed");
        Ok(())
    }

    pub(super) fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        let _operation = self.operation.lock().map_err(|_| {
            KillSwitchError::CommandFailed("Windows WFP operation lock poisoned".to_string())
        })?;
        Self::remove_wfp_objects()?;
        Self::cleanup_legacy_rules()?;
        self.rules_active.store(false, Ordering::SeqCst);
        log::debug!("Windows kill switch: owned WFP objects removed");
        Ok(())
    }

    pub(super) fn allow_vpn_connecting(
        &self,
        policy: &VpnFirewallPolicy,
    ) -> Result<(), KillSwitchError> {
        let _operation = self.operation.lock().map_err(|_| {
            KillSwitchError::CommandFailed("Windows WFP operation lock poisoned".to_string())
        })?;
        Self::replace_policy(Some(policy), false)?;
        Self::cleanup_legacy_rules()?;
        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Windows kill switch: endpoint-only WFP policy committed");
        Ok(())
    }

    pub(super) fn allow_vpn_traffic(
        &self,
        policy: &VpnFirewallPolicy,
    ) -> Result<(), KillSwitchError> {
        let _operation = self.operation.lock().map_err(|_| {
            KillSwitchError::CommandFailed("Windows WFP operation lock poisoned".to_string())
        })?;
        Self::replace_policy(Some(policy), true)?;
        Self::cleanup_legacy_rules()?;
        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Windows kill switch: endpoint and Wintun WFP policy committed");
        Ok(())
    }

    pub(super) fn cleanup_stale() -> Result<(), KillSwitchError> {
        let wfp_result = Self::remove_wfp_objects();
        let legacy_result = Self::cleanup_legacy_rules();
        match (wfp_result, legacy_result) {
            (Ok(()), Ok(())) => {
                log::info!("Stale Windows WFP and legacy firewall rules verified absent");
                Ok(())
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(wfp_error), Err(legacy_error)) => Err(KillSwitchError::CommandFailed(format!(
                "WFP cleanup: {wfp_error}; legacy firewall cleanup: {legacy_error}"
            ))),
        }
    }

    fn cleanup_legacy_rules() -> Result<(), KillSwitchError> {
        let mut failures = Vec::new();
        for rule_name in [LEGACY_BLOCK_RULE, LEGACY_VPN_RULE] {
            if let Err(error) = crate::firewall::cleanup_windows_firewall_rule(rule_name) {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(KillSwitchError::CommandFailed(failures.join("; ")))
        }
    }

    fn replace_policy(
        policy: Option<&VpnFirewallPolicy>,
        connected: bool,
    ) -> Result<(), KillSwitchError> {
        let mut tunnel_luid = match (policy, connected) {
            (Some(policy), true) => Some(interface_luid(policy.tun_name())?),
            _ => None,
        };
        let engine = Engine::open()?;
        let transaction = Transaction::begin(&engine)?;
        delete_owned_objects(&engine)?;
        add_provider(&engine)?;
        add_sublayer(&engine)?;

        for layer in Layer::ALL {
            add_loopback_filter(&engine, layer)?;
            if let Some(policy) = policy {
                add_endpoint_filter(&engine, layer, policy)?;
            }
            if let Some(luid) = tunnel_luid.as_mut() {
                add_tunnel_filter(&engine, layer, luid)?;
            }
            add_block_filter(&engine, layer)?;
        }

        transaction.commit()?;
        engine.close()
    }

    fn remove_wfp_objects() -> Result<(), KillSwitchError> {
        let engine = Engine::open()?;
        let transaction = Transaction::begin(&engine)?;
        delete_owned_objects(&engine)?;
        transaction.commit()?;
        engine.close()
    }

    #[cfg(test)]
    fn verify_managed_objects_absent() -> Result<(), KillSwitchError> {
        let engine = Engine::open()?;
        let transaction = Transaction::begin(&engine)?;
        for layer in Layer::ALL {
            for kind in
                [FilterKind::Loopback, FilterKind::Endpoint, FilterKind::Tunnel, FilterKind::Block]
            {
                let status =
                    unsafe { FwpmFilterDeleteByKey0(engine.handle, &filter_key(layer, kind)) };
                if status != FWP_E_FILTER_NOT_FOUND as u32 {
                    return Err(KillSwitchError::CommandFailed(format!(
                        "managed WFP filter residue detected for slot {}: 0x{status:08x}",
                        layer.slot_base() + kind as u8
                    )));
                }
            }
        }
        let sublayer_status = unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &SUBLAYER_KEY) };
        if sublayer_status != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            return Err(KillSwitchError::CommandFailed(format!(
                "managed WFP sublayer residue detected: 0x{sublayer_status:08x}"
            )));
        }
        let provider_status = unsafe { FwpmProviderDeleteByKey0(engine.handle, &PROVIDER_KEY) };
        if provider_status != FWP_E_PROVIDER_NOT_FOUND as u32 {
            return Err(KillSwitchError::CommandFailed(format!(
                "managed WFP provider residue detected: 0x{provider_status:08x}"
            )));
        }
        transaction.abort()?;
        engine.close()
    }
}

struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open() -> Result<Self, KillSwitchError> {
        let mut name = wide("QuicFuscate kill switch session");
        let mut description = wide("Transactional persistent WFP policy management");
        let session =
            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION0 {
                sessionKey: GUID::from_u128(0),
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: description.as_mut_ptr(),
                },
                flags: 0,
                txnWaitTimeoutInMSec: TRANSACTION_WAIT_MS,
                processId: 0,
                sid: null_mut(),
                username: null_mut(),
                kernelMode: 0,
            };
        let mut handle = null_mut();
        let status =
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle) };
        check_status("open WFP engine", status)?;
        if handle.is_null() {
            return Err(KillSwitchError::CommandFailed(
                "open WFP engine returned a null handle".to_string(),
            ));
        }
        Ok(Self { handle })
    }

    fn close(mut self) -> Result<(), KillSwitchError> {
        let handle = self.handle;
        self.handle = null_mut();
        check_status("close WFP engine", unsafe { FwpmEngineClose0(handle) })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let status = unsafe { FwpmEngineClose0(self.handle) };
            if status != ERROR_SUCCESS {
                log::error!("WFP engine close during cleanup failed: 0x{status:08x}");
            }
            self.handle = null_mut();
        }
    }
}

struct Transaction<'a> {
    engine: &'a Engine,
    active: bool,
}

impl<'a> Transaction<'a> {
    fn begin(engine: &'a Engine) -> Result<Self, KillSwitchError> {
        check_status("begin WFP transaction", unsafe { FwpmTransactionBegin0(engine.handle, 0) })?;
        Ok(Self { engine, active: true })
    }

    fn commit(mut self) -> Result<(), KillSwitchError> {
        check_status("commit WFP transaction", unsafe {
            FwpmTransactionCommit0(self.engine.handle)
        })?;
        self.active = false;
        Ok(())
    }

    #[cfg(test)]
    fn abort(mut self) -> Result<(), KillSwitchError> {
        check_status("abort WFP verification transaction", unsafe {
            FwpmTransactionAbort0(self.engine.handle)
        })?;
        self.active = false;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if self.active {
            let status = unsafe { FwpmTransactionAbort0(self.engine.handle) };
            if status != ERROR_SUCCESS {
                log::error!("WFP transaction abort during cleanup failed: 0x{status:08x}");
            }
            self.active = false;
        }
    }
}

fn delete_owned_objects(engine: &Engine) -> Result<(), KillSwitchError> {
    for layer in Layer::ALL {
        for kind in
            [FilterKind::Loopback, FilterKind::Endpoint, FilterKind::Tunnel, FilterKind::Block]
        {
            let status = unsafe { FwpmFilterDeleteByKey0(engine.handle, &filter_key(layer, kind)) };
            check_delete_status("delete WFP filter", status, FWP_E_FILTER_NOT_FOUND as u32)?;
        }
    }
    let status = unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &SUBLAYER_KEY) };
    check_delete_status("delete WFP sublayer", status, FWP_E_SUBLAYER_NOT_FOUND as u32)?;
    let status = unsafe { FwpmProviderDeleteByKey0(engine.handle, &PROVIDER_KEY) };
    check_delete_status("delete WFP provider", status, FWP_E_PROVIDER_NOT_FOUND as u32)
}

fn add_provider(engine: &Engine) -> Result<(), KillSwitchError> {
    let mut name = wide("QuicFuscate");
    let mut description = wide("QuicFuscate persistent kill-switch policy");
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: null_mut(),
    };
    check_status("add WFP provider", unsafe {
        FwpmProviderAdd0(engine.handle, &provider, null_mut())
    })
}

fn add_sublayer(engine: &Engine) -> Result<(), KillSwitchError> {
    let mut name = wide("QuicFuscate kill switch");
    let mut description = wide("Atomic outbound VPN exception and fail-closed block policy");
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
        providerData: empty_blob(),
        weight: SUBLAYER_WEIGHT,
    };
    check_status("add WFP sublayer", unsafe {
        FwpmSubLayerAdd0(engine.handle, &sublayer, null_mut())
    })
}

fn add_loopback_filter(engine: &Engine, layer: Layer) -> Result<(), KillSwitchError> {
    let mut conditions = [FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ALL_SET,
        conditionValue: condition_u32(FWP_CONDITION_FLAG_IS_LOOPBACK),
    }];
    add_filter(
        engine,
        layer,
        FilterKind::Loopback,
        "Permit loopback",
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT_RANGE,
        &mut conditions,
    )
}

fn add_endpoint_filter(
    engine: &Engine,
    layer: Layer,
    policy: &VpnFirewallPolicy,
) -> Result<(), KillSwitchError> {
    let endpoint = if layer.is_ipv6() {
        policy.server_ipv6().map(|(ip, port)| (IpAddr::V6(ip), port))
    } else {
        policy.server_ipv4().map(|(ip, port)| (IpAddr::V4(ip), port))
    };
    let Some((ip, port)) = endpoint else {
        return Ok(());
    };

    match ip {
        IpAddr::V4(ip) => {
            let mut conditions = [
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: condition_u32(u32::from_be_bytes(ip.octets())),
                },
                empty_condition(),
                empty_condition(),
            ];
            conditions[1] = protocol_condition();
            conditions[2] = port_condition(port);
            add_filter(
                engine,
                layer,
                FilterKind::Endpoint,
                "Permit VPN endpoint",
                FWP_ACTION_PERMIT,
                PERMIT_WEIGHT_RANGE,
                &mut conditions,
            )
        }
        IpAddr::V6(ip) => {
            let mut address = FWP_BYTE_ARRAY16 { byteArray16: ip.octets() };
            let mut conditions = [
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_ARRAY16_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: &mut address },
                    },
                },
                empty_condition(),
                empty_condition(),
            ];
            conditions[1] = protocol_condition();
            conditions[2] = port_condition(port);
            add_filter(
                engine,
                layer,
                FilterKind::Endpoint,
                "Permit VPN endpoint",
                FWP_ACTION_PERMIT,
                PERMIT_WEIGHT_RANGE,
                &mut conditions,
            )
        }
    }
}

fn add_tunnel_filter(engine: &Engine, layer: Layer, luid: &mut u64) -> Result<(), KillSwitchError> {
    let mut conditions = [FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint64: luid },
        },
    }];
    add_filter(
        engine,
        layer,
        FilterKind::Tunnel,
        "Permit Wintun interface",
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT_RANGE,
        &mut conditions,
    )
}

fn add_block_filter(engine: &Engine, layer: Layer) -> Result<(), KillSwitchError> {
    add_filter(
        engine,
        layer,
        FilterKind::Block,
        "Block non-VPN outbound traffic",
        FWP_ACTION_BLOCK,
        BLOCK_WEIGHT_RANGE,
        &mut [],
    )
}

#[allow(clippy::too_many_arguments)]
fn add_filter(
    engine: &Engine,
    layer: Layer,
    kind: FilterKind,
    label: &str,
    action_type: u32,
    weight_range: u8,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), KillSwitchError> {
    let mut name = wide(label);
    let mut description = wide("QuicFuscate managed persistent kill-switch filter");
    let filter = FWPM_FILTER0 {
        filterKey: filter_key(layer, kind),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
        providerData: empty_blob(),
        layerKey: layer.key(),
        subLayerKey: SUBLAYER_KEY,
        weight: FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: weight_range } },
        numFilterConditions: conditions.len() as u32,
        filterCondition: if conditions.is_empty() { null_mut() } else { conditions.as_mut_ptr() },
        action: FWPM_ACTION0 {
            r#type: action_type,
            Anonymous: FWPM_ACTION0_0 { filterType: GUID::from_u128(0) },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: null_mut(),
        filterId: 0,
        effectiveWeight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: FWP_VALUE0_0 { uint64: null_mut() },
        },
    };
    check_status("add WFP filter", unsafe {
        FwpmFilterAdd0(engine.handle, &filter, null_mut(), null_mut())
    })
}

fn protocol_condition() -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_PROTOCOL,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: IP_PROTOCOL_UDP },
        },
    }
}

fn port_condition(port: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
        },
    }
}

fn condition_u32(value: u32) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 { r#type: FWP_UINT32, Anonymous: FWP_CONDITION_VALUE0_0 { uint32: value } }
}

fn empty_condition() -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: GUID::from_u128(0),
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint64: null_mut() },
        },
    }
}

fn interface_luid(alias: &str) -> Result<u64, KillSwitchError> {
    let alias = wide(alias);
    let mut luid = NET_LUID_LH { Value: 0 };
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
    check_status("resolve Wintun interface LUID", status)?;
    let value = unsafe { luid.Value };
    if value == 0 {
        return Err(KillSwitchError::CommandFailed(
            "resolved Wintun interface LUID is zero".to_string(),
        ));
    }
    Ok(value)
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB { size: 0, data: null_mut() }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check_status(action: &str, status: u32) -> Result<(), KillSwitchError> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else if status == ERROR_ACCESS_DENIED {
        Err(KillSwitchError::PermissionDenied)
    } else {
        Err(KillSwitchError::CommandFailed(format!(
            "{action} failed with WFP status 0x{status:08x}"
        )))
    }
}

fn check_delete_status(action: &str, status: u32, not_found: u32) -> Result<(), KillSwitchError> {
    if status == ERROR_SUCCESS || status == not_found {
        Ok(())
    } else {
        check_status(action, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::UdpSocket;

    struct NativeCleanup;

    impl Drop for NativeCleanup {
        fn drop(&mut self) {
            let _ = WindowsKillSwitch::cleanup_stale();
        }
    }

    fn test_policy() -> VpnFirewallPolicy {
        VpnFirewallPolicy::new(
            "QuicFuscate-Test",
            "192.0.2.1:4433".parse().expect("valid documentation endpoint"),
            Some("2001:db8::1".parse().expect("valid documentation endpoint")),
            [],
        )
        .expect("valid native test policy")
    }

    #[test]
    fn managed_filter_keys_are_unique_and_complete() {
        let mut keys = BTreeSet::new();
        for layer in Layer::ALL {
            for kind in
                [FilterKind::Loopback, FilterKind::Endpoint, FilterKind::Tunnel, FilterKind::Block]
            {
                assert!(keys.insert(filter_key_value(layer, kind)));
            }
        }
        assert_eq!(keys.len(), 8);
    }

    #[test]
    fn layer_contract_covers_both_ip_families() {
        assert_eq!(Layer::ALL.iter().filter(|layer| layer.is_ipv6()).count(), 1);
        assert_eq!(Layer::ALL.iter().filter(|layer| !layer.is_ipv6()).count(), 1);
    }

    #[test]
    #[ignore = "requires an elevated native Windows host with Base Filtering Engine"]
    fn native_wfp_block_endpoint_exception_and_cleanup() {
        let _cleanup = NativeCleanup;
        WindowsKillSwitch::cleanup_stale().expect("pre-test WFP cleanup");
        let kill_switch = WindowsKillSwitch::new();
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind native UDP probe");
        let payload = b"quicfuscate-wfp-probe";

        kill_switch.block_traffic().expect("install block policy");
        let blocked = socket.send_to(payload, "192.0.2.1:4433");
        assert!(
            blocked.is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied),
            "catch-all WFP block must reject the outbound packet"
        );

        kill_switch.allow_vpn_connecting(&test_policy()).expect("install endpoint exception");
        assert_eq!(
            socket.send_to(payload, "192.0.2.1:4433").expect("send permitted endpoint packet"),
            payload.len()
        );
        let other_endpoint = socket.send_to(payload, "192.0.2.2:4433");
        assert!(
            other_endpoint.is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied),
            "non-policy endpoint must remain blocked"
        );

        kill_switch.block_traffic().expect("restore fail-closed policy");
        let blocked_again = socket.send_to(payload, "192.0.2.1:4433");
        assert!(
            blocked_again.is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied),
            "disconnect transition must remove the endpoint exception"
        );

        kill_switch.allow_traffic().expect("remove WFP policy");
        assert_eq!(
            socket.send_to(payload, "192.0.2.2:4433").expect("send after disable"),
            payload.len()
        );
        WindowsKillSwitch::verify_managed_objects_absent().expect("zero WFP object residue");
    }
}
