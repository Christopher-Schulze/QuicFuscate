use stealth::QuicFuscateStealth;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "localhost".into());
    let port: u16 = args
        .get(2)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    println!("QuicFuscate Client gestartet. Verbinde mit {}:{}...", host, port);
    let stealth = QuicFuscateStealth::new();
    if stealth.initialize() {
        println!("Verbunden mit Server!");
    } else {
        println!("Fehler bei der Initialisierung des Stealth-Moduls");
    }
    stealth.shutdown();
}
