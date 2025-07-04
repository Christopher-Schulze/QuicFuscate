use lazy_static::lazy_static;
use prometheus::{Encoder, Gauge, IntCounter, Registry, TextEncoder};
use std::error::Error;
use std::sync::Mutex;
use sysinfo::{CpuExt, System, SystemExt};

pub struct Telemetry {
    pub registry: Registry,
    cpu_usage: Gauge,
    throughput: IntCounter,
    fec_sent: IntCounter,
    fec_recovered: IntCounter,
    fec_lost: IntCounter,
    stealth_outgoing: IntCounter,
    stealth_incoming: IntCounter,
    system: Mutex<System>,
}

lazy_static! {
    pub static ref TELEMETRY: Telemetry = Telemetry::new();
}

impl Telemetry {
    fn new() -> Self {
        let registry = Registry::new();
        let cpu_usage = Gauge::new("cpu_usage_percent", "CPU usage percentage").unwrap();
        let throughput =
            IntCounter::new("throughput_bytes_total", "Total bytes processed").unwrap();
        let fec_sent = IntCounter::new("fec_packets_sent_total", "FEC packets sent").unwrap();
        let fec_recovered =
            IntCounter::new("fec_packets_recovered_total", "FEC packets recovered").unwrap();
        let fec_lost = IntCounter::new("fec_packets_lost_total", "FEC packets lost").unwrap();
        let stealth_outgoing =
            IntCounter::new("stealth_outgoing_total", "Packets obfuscated by stealth").unwrap();
        let stealth_incoming =
            IntCounter::new("stealth_incoming_total", "Packets deobfuscated by stealth").unwrap();

        registry.register(Box::new(cpu_usage.clone())).unwrap();
        registry.register(Box::new(throughput.clone())).unwrap();
        registry.register(Box::new(fec_sent.clone())).unwrap();
        registry.register(Box::new(fec_recovered.clone())).unwrap();
        registry.register(Box::new(fec_lost.clone())).unwrap();
        registry
            .register(Box::new(stealth_outgoing.clone()))
            .unwrap();
        registry
            .register(Box::new(stealth_incoming.clone()))
            .unwrap();

        let mut system = System::new();
        system.refresh_cpu();

        Self {
            registry,
            cpu_usage,
            throughput,
            fec_sent,
            fec_recovered,
            fec_lost,
            stealth_outgoing,
            stealth_incoming,
            system: Mutex::new(system),
        }
    }

    pub fn start_exporter(
        &self,
        addr: &str,
    ) -> Result<prometheus_exporter::Exporter, Box<dyn Error>> {
        let binding: std::net::SocketAddr = addr.parse()?;
        let mut builder = prometheus_exporter::Builder::new(binding);
        builder.with_registry(self.registry.clone());
        Ok(builder.start()?)
    }

    pub fn update_cpu(&self) {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_cpu();
        let usage = sys.global_cpu_info().cpu_usage();
        self.cpu_usage.set(usage as f64);
    }

    pub fn inc_throughput(&self, bytes: usize) {
        self.throughput.inc_by(bytes as u64);
    }

    pub fn inc_fec_sent(&self, n: usize) {
        self.fec_sent.inc_by(n as u64);
    }

    pub fn inc_fec_recovered(&self, n: usize) {
        self.fec_recovered.inc_by(n as u64);
    }

    pub fn inc_fec_lost(&self, n: usize) {
        self.fec_lost.inc_by(n as u64);
    }

    pub fn inc_stealth_outgoing(&self) {
        self.stealth_outgoing.inc();
    }

    pub fn inc_stealth_incoming(&self) {
        self.stealth_incoming.inc();
    }

    pub fn gather(&self) -> Vec<u8> {
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        buffer
    }
}
