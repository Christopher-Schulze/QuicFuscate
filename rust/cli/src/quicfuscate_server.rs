use log::info;
use logger::init as init_logger;

fn main() {
    init_logger();
    info!("QuicFuscate Server gestartet. Warte auf Verbindungen...");
}
