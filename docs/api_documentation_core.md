# QuicSand API-Dokumentation: Core-Komponenten

## Überblick

QuicSand ist eine QUIC-basierte VPN-Lösung mit Fokus auf Stealth-Funktionen, Leistungsoptimierung und Sicherheit. Diese Dokumentation beschreibt die wichtigsten Komponenten und APIs des Systems.

## Core-Komponenten

### 1. QuicConnection

Die `QuicConnection`-Klasse bildet das Herzstück der QUIC-Kommunikation im QuicSand-System.

```cpp
class QuicConnection {
public:
    QuicConnection(bool enable_zero_copy = false);
    
    // Verbindungsaufbau
    bool connect(const std::string& host, uint16_t port);
    void disconnect();
    bool is_connected() const;
    
    // Datenübertragung
    Result<size_t> send_data(const std::vector<uint8_t>& data);
    Result<std::vector<uint8_t>> receive_data(size_t max_size);
    
    // Zero-Copy Schnittstelle
    Result<size_t> send_packet_zero_copy(const uint8_t* data, size_t length);
    Result<size_t> process_incoming_packet_zero_copy(const uint8_t* data, size_t length);
    
    // Statistik
    size_t get_sent_packet_count() const;
    size_t get_received_packet_count() const;
    
    // Weitere Methoden...
};
```

#### Beispiel
```cpp
// Verbindung mit Zero-Copy-Optimierung erstellen
QuicConnection connection(true);

// Verbindung zu einem Server herstellen
if (!connection.connect("example.com", 443)) {
    // Fehlerbehandlung
}

// Daten senden
std::vector<uint8_t> data = {...};
auto result = connection.send_data(data);
if (!result) {
    // Fehlerbehandlung mit detaillierten Fehlercodes
    std::cout << "Fehler beim Senden: " << result.error().message << std::endl;
}

// Verbindung schließen
connection.disconnect();
```

### 2. PathMtuManager

Die `PathMtuManager`-Klasse verwaltet die Path MTU Discovery zwischen Endpunkten.

```cpp
class PathMtuManager {
public:
    PathMtuManager(QuicConnection& connection);
    
    // MTU Discovery aktivieren/deaktivieren
    Result<void> enable_mtu_discovery(bool enabled);
    
    // MTU-Größen konfigurieren
    Result<void> set_min_mtu_size(uint16_t size);
    Result<void> set_max_mtu_size(uint16_t size);
    Result<void> set_initial_mtu_size(uint16_t size);
    
    // MTU Discovery-Proben senden
    Result<void> send_probe(uint16_t size);
    Result<void> handle_probe_response(const ProbeResponse& response);
    
    // Aktuellen MTU-Zustand abfragen
    uint16_t get_current_mtu() const;
    bool is_discovery_active() const;
    
    // Event-Callbacks registrieren
    void set_mtu_change_callback(std::function<void(uint16_t)> callback);
    void set_blackhole_detection_callback(std::function<void()> callback);
};
```

#### Beispiel
```cpp
// MTU-Manager initialisieren
PathMtuManager mtu_manager(connection);

// MTU Discovery aktivieren
auto result = mtu_manager.enable_mtu_discovery(true);
if (!result) {
    std::cout << "Fehler bei MTU-Discovery-Aktivierung: " 
              << result.error().message << std::endl;
}

// MTU-Änderungs-Callback registrieren
mtu_manager.set_mtu_change_callback([](uint16_t new_mtu) {
    std::cout << "Neue MTU: " << new_mtu << std::endl;
});

// Blackhole-Detection-Callback registrieren
mtu_manager.set_blackhole_detection_callback([]() {
    std::cout << "MTU-Blackhole erkannt - Verbindungsprobleme!" << std::endl;
});
```

### 3. Error Handling Framework

Das Error-Handling-Framework bietet eine einheitliche Methode zur Fehlerbehandlung im gesamten QuicSand-Projekt.

```cpp
// Fehler-Kategorien
enum class ErrorCategory {
    NONE,
    NETWORK,
    CRYPTO,
    PROTOCOL,
    SYSTEM,
    APPLICATION
};

// Detaillierte Fehlercodes
enum class ErrorCode {
    SUCCESS,
    UNKNOWN_ERROR,
    
    // Netzwerkfehler
    NETWORK_UNREACHABLE,
    CONNECTION_REFUSED,
    CONNECTION_RESET,
    
    // Kryptographische Fehler
    CRYPTO_HANDSHAKE_FAILURE,
    CRYPTO_KEY_GENERATION_FAILURE,
    
    // Protokollfehler
    PROTOCOL_VIOLATION,
    INVALID_FRAME,
    
    // Systemfehler
    SYSTEM_RESOURCE_EXHAUSTED,
    SYSTEM_PERMISSION_DENIED,
    
    // Anwendungsfehler
    APPLICATION_STREAM_ERROR,
    APPLICATION_INVALID_STATE
};

// Fehlerinformation
struct ErrorInfo {
    ErrorCategory category;
    ErrorCode code;
    std::string message;
    std::optional<int> system_errno;
};

// Result-Template für Rückgabewerte mit Fehlerbehandlung
template <typename T>
class Result {
public:
    // Erfolgreich
    static Result<T> success(const T& value);
    static Result<T> success(T&& value);
    
    // Fehler
    static Result<T> failure(const ErrorInfo& error);
    
    // Prüfungen
    bool has_value() const;
    bool has_error() const;
    
    // Wertzugriff
    const T& value() const;
    T& value();
    
    // Fehlerzugriff
    const ErrorInfo& error() const;
    
    // Operator-Overloads
    explicit operator bool() const;
    
    // Transformationen
    template <typename U, typename Func>
    Result<U> map(Func&& func) const;
    
    template <typename Func>
    Result<T> and_then(Func&& func) const;
};

// Spezialisierung für void
template <>
class Result<void> {
    // Ähnlich wie oben, aber ohne Wert
};
```

#### Beispiel
```cpp
// Funktion mit Result-Rückgabetyp
Result<std::vector<uint8_t>> read_encrypted_data(const std::string& path, const Key& key) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return Result<std::vector<uint8_t>>::failure({
            ErrorCategory::SYSTEM,
            ErrorCode::SYSTEM_PERMISSION_DENIED,
            "Konnte Datei nicht öffnen: " + path,
            errno
        });
    }
    
    std::vector<uint8_t> data;
    // Datei lesen...
    
    try {
        // Entschlüsselung versuchen...
    } catch (const CryptoException& e) {
        return Result<std::vector<uint8_t>>::failure({
            ErrorCategory::CRYPTO,
            ErrorCode::CRYPTO_KEY_GENERATION_FAILURE,
            "Entschlüsselungsfehler: " + std::string(e.what())
        });
    }
    
    return Result<std::vector<uint8_t>>::success(data);
}

// Verwendung
auto result = read_encrypted_data("secret.dat", key);
if (result) {
    auto data = result.value();
    // Mit Daten arbeiten...
} else {
    const auto& error = result.error();
    std::cerr << "Fehler: " << error.message << std::endl;
    
    if (error.category == ErrorCategory::CRYPTO) {
        // Kryptographie-spezifische Fehlerbehandlung
    }
}
```

### 4. FEC (Forward Error Correction)

Die `FecManager`-Klasse implementiert eine vereinfachte XOR-basierte Parity-Methode für Forward Error Correction.

```cpp
class FecManager {
public:
    FecManager(QuicConnection& connection, bool enabled = false);
    
    // FEC aktivieren/deaktivieren
    void enable(bool enabled);
    bool is_enabled() const;
    
    // FEC-Parameter konfigurieren
    void set_block_size(uint8_t size);
    void set_overhead_percentage(float percentage);
    
    // FEC auf Pakete anwenden/wiederherstellen
    std::vector<uint8_t> encode_packet(const std::vector<uint8_t>& packet);
    std::optional<std::vector<uint8_t>> decode_packet(const std::vector<uint8_t>& encoded_packet);
    
    // Statistik
    uint32_t get_packets_recovered() const;
    float get_recovery_rate() const;
};
```

#### Beispiel
```cpp
// FEC-Manager initialisieren
FecManager fec_manager(connection, true);

// Parameter anpassen
fec_manager.set_block_size(8); // 8 Datenpakete + 1 FEC-Paket
fec_manager.set_overhead_percentage(12.5f); // 12.5% Overhead

// Daten senden mit FEC
std::vector<uint8_t> packet = prepare_packet();
std::vector<uint8_t> encoded_packet = fec_manager.encode_packet(packet);
connection.send_data(encoded_packet);

// Statistik anzeigen
std::cout << "Wiederhergestellte Pakete: " << fec_manager.get_packets_recovered() << std::endl;
std::cout << "Wiederherstellungsrate: " << fec_manager.get_recovery_rate() << "%" << std::endl;
```
