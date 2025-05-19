# QuicSand API-Dokumentation

## Inhalt

Die QuicSand API-Dokumentation ist in mehrere Abschnitte unterteilt:

1. [Core-Komponenten](api_documentation_core.md) - Die grundlegenden Komponenten des QuicSand-Projekts:
   * QuicConnection
   * PathMtuManager
   * Error Handling Framework
   * FEC (Forward Error Correction)

2. [Stealth-Komponenten](api_documentation_stealth.md) - Die Tarnfunktionen für den VPN-Verkehr:
   * SNI Hiding
   * DPI Evasion
   * Stealth Manager
   * uTLS Integration
   * HTTP3 Masquerading

3. [Performance-Optimierungen](api_documentation_optimizations.md) - Die Performance und Energieeffizienz-Optimierungen:
   * Cache-Optimierungen
   * Energieoptimierungen
   * Zero-Copy-Optimierungen
   * Optimizations Manager

## QuicSand Projekt Überblick

QuicSand ist eine QUIC-basierte VPN-Lösung mit Fokus auf:

* **Stealth-Funktionen**: Vermeidung von Zensur und Deep Packet Inspection
* **Performance**: Optimierungen für hohe Datenraten und niedrige Latenz
* **Energieeffizienz**: Optimierungen für mobile Geräte wie den Apple M1/M2
* **Sicherheit**: Robuste Verschlüsselung und Fehlerbehandlung

Die Zielplattformen sind:
- macOS (insbesondere M1/M2 Macs)
- Linux-Server

## Projektstruktur

QuicSand ist in folgende Hauptkomponenten strukturiert:

```
QuicSand/
├── core/                  # Kern-Komponenten und Netzwerk-Stack
├── crypto/                # Kryptographie-Implementierung
├── fec/                   # Forward Error Correction
├── stealth/               # Stealth-Funktionen
├── cli/                   # Befehlszeilenschnittstelle
├── flutter_ui/            # Flutter GUI für macOS
├── tests/                 # Tests und Benchmarks
└── docs/                  # Dokumentation
```

## Verwendung von QuicSand

### Grundlegende Verwendung

```cpp
#include "quicsand/core/quic_connection.hpp"
#include "quicsand/stealth/stealth_manager.hpp"

int main() {
    // Stealth-Manager für maximale Tarnung initialisieren
    quicsand::stealth::StealthManager stealth;
    stealth.set_stealth_level(quicsand::stealth::StealthLevel::MAXIMUM);
    
    // QUIC-Verbindung mit aktiviertem Zero-Copy erstellen
    quicsand::QuicConnection connection(true);
    
    // Verbindung herstellen
    if (!connection.connect("example.com", 443)) {
        std::cerr << "Verbindungsfehler" << std::endl;
        return 1;
    }
    
    // Daten senden
    std::vector<uint8_t> data = {/* Daten */};
    auto result = connection.send_data(data);
    
    if (!result) {
        std::cerr << "Fehler beim Senden: " << result.error().message << std::endl;
        return 1;
    }
    
    // Verbindung schließen
    connection.disconnect();
    
    return 0;
}
```

### Weiterführende Dokumentation

Weitere Informationen finden Sie in den einzelnen Dokumentationsabschnitten und der Beispiel-Code-Sammlung unter `examples/`.
