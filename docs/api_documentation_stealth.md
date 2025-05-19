# QuicSand API-Dokumentation: Stealth-Komponenten

## Stealth-Komponenten

### 1. SNI Hiding

Die `SniHiding`-Klasse implementiert verschiedene Techniken zum Verbergen des SNI (Server Name Indication) in TLS-Verbindungen.

```cpp
struct SniConfig {
    bool enable_sni_padding = false;
    bool enable_sni_split = false;
    bool enable_domain_fronting = false;
    std::string front_domain;
    std::string real_domain;
};

class SniHiding {
public:
    explicit SniHiding(const SniConfig& config);
    
    // TLS ClientHello verarbeiten
    std::vector<uint8_t> process_client_hello(const std::vector<uint8_t>& client_hello);
    
    // Spezifische Techniken anwenden
    std::vector<uint8_t> apply_sni_padding(const std::vector<uint8_t>& client_hello);
    std::vector<uint8_t> apply_sni_split(const std::vector<uint8_t>& client_hello);
    std::vector<uint8_t> apply_domain_fronting(const std::vector<uint8_t>& client_hello);
    
    // Konfiguration ändern
    void set_config(const SniConfig& config);
    const SniConfig& get_config() const;
};
```

#### Beispiel
```cpp
// SNI-Hiding-Konfiguration erstellen
SniConfig config;
config.enable_sni_split = true;
config.enable_domain_fronting = true;
config.front_domain = "cdn.example.com";
config.real_domain = "blocked.example.com";

// SNI-Hiding initialisieren
SniHiding sni_hiding(config);

// TLS ClientHello verarbeiten
std::vector<uint8_t> original_hello = get_client_hello();
std::vector<uint8_t> modified_hello = sni_hiding.process_client_hello(original_hello);

// Modifiziertes ClientHello senden
send_tls_data(modified_hello);
```

### 2. DPI Evasion

Die `DpiEvasion`-Klasse implementiert Techniken zur Umgehung von Deep Packet Inspection (DPI).

```cpp
struct DpiConfig {
    bool enable_packet_padding = false;
    uint16_t min_padding_length = 10;
    uint16_t max_padding_length = 100;
    
    bool enable_protocol_obfuscation = false;
    bool enable_timing_jitter = false;
    uint16_t min_jitter_ms = 5;
    uint16_t max_jitter_ms = 30;
    
    bool enable_dpi_fingerprint_evasion = false;
    bool enable_active_dpi_detection = false;
};

class DpiEvasion {
public:
    explicit DpiEvasion(const DpiConfig& config);
    
    // DPI-Umgehungstechniken auf ein Paket anwenden
    bool apply_techniques(std::shared_ptr<QuicPacket> packet);
    
    // Timing-Jitter einführen
    bool apply_timing_jitter();
    
    // DPI-Erkennung durchführen
    bool detect_dpi();
    
    // Konfiguration ändern
    void set_config(const DpiConfig& config);
    const DpiConfig& get_config() const;
};
```

#### Beispiel
```cpp
// DPI-Evasion-Konfiguration erstellen
DpiConfig config;
config.enable_packet_padding = true;
config.min_padding_length = 20;
config.max_padding_length = 50;
config.enable_timing_jitter = true;

// DPI-Evasion initialisieren
DpiEvasion dpi_evasion(config);

// Auf ein Paket anwenden
auto packet = create_quic_packet();
if (dpi_evasion.apply_techniques(packet)) {
    // Modifiziertes Paket senden
    send_packet(packet);
    
    // Timing-Jitter hinzufügen
    dpi_evasion.apply_timing_jitter();
}
```

### 3. Stealth Manager

Die `StealthManager`-Klasse koordiniert alle Stealth-Techniken für eine umfassende Tarnung der Verbindungen.

```cpp
enum class StealthLevel {
    NONE,      // Keine Stealth-Techniken
    MINIMAL,   // Minimale Tarnung
    MEDIUM,    // Mittlere Tarnung
    HIGH,      // Hohe Tarnung
    MAXIMUM    // Maximale Tarnung (alle Techniken)
};

class StealthManager {
public:
    StealthManager();
    
    // Stealth-Level einstellen
    void set_stealth_level(StealthLevel level);
    StealthLevel get_stealth_level() const;
    
    // Konfiguration
    void set_sni_config(const SniConfig& config);
    void set_dpi_config(const DpiConfig& config);
    
    // Paketverarbeitung
    bool process_outgoing_packet(std::shared_ptr<QuicPacket> packet);
    bool process_incoming_packet(std::shared_ptr<QuicPacket> packet);
    
    // TLS-Verarbeitung
    std::vector<uint8_t> process_client_hello(const std::vector<uint8_t>& client_hello);
    
    // Aktive Stealth-Funktionen verwalten
    void enable_feature(const std::string& feature_name, bool enabled);
    bool is_feature_enabled(const std::string& feature_name) const;
};
```

#### Beispiel
```cpp
// StealthManager mit maximaler Tarnung initialisieren
StealthManager stealth_manager;
stealth_manager.set_stealth_level(StealthLevel::MAXIMUM);

// Spezifische Konfiguration anpassen
SniConfig sni_config;
sni_config.enable_sni_split = true;
sni_config.enable_domain_fronting = true;
sni_config.front_domain = "cdn.example.com";
sni_config.real_domain = "blocked.example.com";

stealth_manager.set_sni_config(sni_config);

// Eingehende und ausgehende Pakete verarbeiten
connection.set_packet_processor([&stealth_manager](std::shared_ptr<QuicPacket> packet, bool outgoing) {
    if (outgoing) {
        return stealth_manager.process_outgoing_packet(packet);
    } else {
        return stealth_manager.process_incoming_packet(packet);
    }
});

// TLS-Handshake-Verarbeitung
tls_connection.set_client_hello_processor([&stealth_manager](const std::vector<uint8_t>& hello) {
    return stealth_manager.process_client_hello(hello);
});
```

### 4. uTLS Integration

Die `UtlsManager`-Klasse bietet eine C++-Implementation ähnlich dem uTLS in Go, um Browser-TLS-Fingerprints zu imitieren.

```cpp
enum class TlsFingerprint {
    FIREFOX_LATEST,
    CHROME_LATEST,
    SAFARI_LATEST,
    EDGE_LATEST,
    IOS_SAFARI,
    ANDROID_CHROME,
    RANDOM,
    CUSTOM
};

struct UtlsConfig {
    TlsFingerprint fingerprint = TlsFingerprint::CHROME_LATEST;
    bool randomize_extensions = false;
    std::vector<uint16_t> custom_cipher_suites;
    std::vector<uint16_t> custom_extensions;
    std::string custom_ja3_string;
};

class UtlsManager {
public:
    UtlsManager(const UtlsConfig& config = UtlsConfig());
    
    // Konfiguration ändern
    void set_config(const UtlsConfig& config);
    const UtlsConfig& get_config() const;
    
    // TLS ClientHello anpassen
    std::vector<uint8_t> modify_client_hello(const std::vector<uint8_t>& original_hello);
    
    // Kompletten TLS-Handshake durchführen
    Result<std::unique_ptr<TlsConnection>> establish_connection(
        const std::string& host,
        uint16_t port
    );
    
    // JA3-Fingerprint berechnen
    std::string calculate_ja3_fingerprint(const std::vector<uint8_t>& client_hello);
    
    // Vorgegebene Fingerprints laden
    std::vector<TlsFingerprint> available_fingerprints() const;
    void set_fingerprint(TlsFingerprint fingerprint);
};
```

#### Beispiel
```cpp
// UtlsManager mit Chrome-Fingerprint initialisieren
UtlsConfig utls_config;
utls_config.fingerprint = TlsFingerprint::CHROME_LATEST;
utls_config.randomize_extensions = true;

UtlsManager utls_manager(utls_config);

// TLS-Verbindung mit dem Chrome-Fingerprint herstellen
auto connection_result = utls_manager.establish_connection("example.com", 443);
if (!connection_result) {
    std::cerr << "TLS-Verbindungsfehler: " << connection_result.error().message << std::endl;
    return;
}

auto tls_connection = std::move(connection_result.value());

// Daten über die TLS-Verbindung senden
tls_connection->send_data(data);

// JA3-Fingerprint des eigenen ClientHello berechnen
std::vector<uint8_t> client_hello = generate_client_hello();
std::string ja3 = utls_manager.calculate_ja3_fingerprint(client_hello);
std::cout << "JA3-Fingerprint: " << ja3 << std::endl;
```

### 5. HTTP3 Masquerading

Die `Http3Masquerading`-Klasse ermöglicht die Tarnung des VPN-Verkehrs als legitimen HTTP/3-Verkehr.

```cpp
struct Http3Config {
    bool enable_masquerading = false;
    bool fake_browser_headers = false;
    std::string user_agent;
    std::vector<std::string> allowed_hosts;
    bool enable_real_http3_fallback = false;
};

class Http3Masquerading {
public:
    explicit Http3Masquerading(const Http3Config& config = Http3Config());
    
    // Konfiguration ändern
    void set_config(const Http3Config& config);
    const Http3Config& get_config() const;
    
    // VPN-Pakete als HTTP/3 tarnen
    std::vector<uint8_t> masquerade_packet(const std::vector<uint8_t>& packet);
    
    // HTTP/3-Pakete entpacken
    std::optional<std::vector<uint8_t>> extract_vpn_packet(const std::vector<uint8_t>& http3_packet);
    
    // HTTP/3-Header generieren
    std::vector<uint8_t> generate_http3_headers(const std::string& host, const std::string& path);
    
    // Prüfen, ob ein Paket HTTP/3 ist
    bool is_http3_packet(const std::vector<uint8_t>& packet);
};
```

#### Beispiel
```cpp
// HTTP/3-Masquerading initialisieren
Http3Config config;
config.enable_masquerading = true;
config.fake_browser_headers = true;
config.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36";
config.allowed_hosts = {"api.example.com", "cdn.example.com"};

Http3Masquerading http3_masq(config);

// VPN-Paket als HTTP/3 tarnen
std::vector<uint8_t> vpn_packet = prepare_vpn_packet();
std::vector<uint8_t> http3_packet = http3_masq.masquerade_packet(vpn_packet);

// HTTP/3-Paket senden
connection.send_data(http3_packet);

// Empfangenes HTTP/3-Paket verarbeiten
std::vector<uint8_t> received_packet = connection.receive_data(4096).value();
if (http3_masq.is_http3_packet(received_packet)) {
    auto extracted = http3_masq.extract_vpn_packet(received_packet);
    if (extracted) {
        process_vpn_packet(*extracted);
    }
}
```
