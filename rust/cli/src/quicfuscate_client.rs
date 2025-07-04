use stealth::QuicFuscateStealth;
use std::env;
use log::{info, error};
use logger::init as init_logger;

fn main() {
    init_logger();
    let args: Vec<String> = env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "localhost".into());
    let port: u16 = args
        .get(2)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    info!("QuicFuscate Client gestartet. Verbinde mit {}:{}...", host, port);
    let stealth = QuicFuscateStealth::new();
    if stealth.initialize() {
        info!("Verbunden mit Server!");
    } else {
        error!("Fehler bei der Initialisierung des Stealth-Moduls");
    }
    stealth.shutdown();
}
