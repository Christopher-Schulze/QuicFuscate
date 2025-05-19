#ifndef UTLS_CLIENT_CONFIGURATOR_HPP
#define UTLS_CLIENT_CONFIGURATOR_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <quiche.h>
#include "session_ticket_manager.hpp"

// Definition der unterstützten Browser-Fingerprint-Typen
enum class BrowserFingerprint {
    // Desktop-Browser (neueste Versionen)
    CHROME_LATEST,         // Chrome neueste Version (120+, Mai 2024)
    FIREFOX_LATEST,        // Firefox neueste Version (124+, Mai 2024) 
    SAFARI_LATEST,         // Safari neueste Version (Safari 17+, Mai 2024)
    EDGE_CHROMIUM,         // Microsoft Edge (Chromium-basiert, Version 120+)
    BRAVE,                 // Brave Browser (meist Chrome-basiert mit Privatsphäre-Anpassungen)
    OPERA,                 // Opera (Chromium-basiert)
    
    // Ältere Browser-Versionen (für Verbindungen zu älteren Servern)
    CHROME_70,             // Ältere Chrome-Version
    FIREFOX_63,            // Ältere Firefox-Version
    
    // Mobile Browser
    CHROME_ANDROID,        // Chrome auf Android (aktuelle Version)
    SAFARI_IOS,            // Safari auf iOS (iOS 17+)
    SAMSUNG_BROWSER,       // Samsung Internet Browser für Android
    FIREFOX_MOBILE,        // Firefox für iOS/Android
    EDGE_MOBILE,           // Edge für iOS/Android
    
    // Spezialisierte Clients
    OUTLOOK,               // Microsoft Outlook Client
    THUNDERBIRD,           // Mozilla Thunderbird E-Mail Client
    CURL,                  // cURL Tool (für API-Anfragen)
    
    // Andere Browser
    OPERA_LATEST,          // Opera
    BRAVE_LATEST,          // Brave Browser
    
    // Spezielle Profile
    RANDOMIZED,            // Zufällige Auswahl von Parametern
    CUSTOM                 // Benutzerdefinierte Einstellungen
};

// TLS Erweiterung-Struktur
struct TLSExtension {
    uint16_t type;
    std::vector<uint8_t> data;
};

// Fingerprint-Profil-Struktur mit allen TLS-Parametern für realistische Nachahmung
struct FingerprintProfile {
    std::string name;                        // Bezeichner des Profils
    std::vector<std::string> cipher_suites;  // Unterstützte Cipher Suites
    std::vector<uint8_t> compression_methods; // Unterstützte Kompressionsmethoden (meist nur 0x00=keine)
    std::vector<uint16_t> curves;            // Unterstützte elliptische Kurven/Gruppen
    std::vector<uint16_t> signature_algos;   // Unterstützte Signaturalgorithmen
    std::vector<TLSExtension> extensions;    // TLS-Erweiterungen im ClientHello
    std::string client_hello_version;        // TLS-Version im ClientHello-Record
    
    // Zusätzliche Parameter für realistischere Fingerabdrücke
    uint16_t record_size_limit = 0;          // Maximum Record Size (0 = Standard)
    uint8_t padding_multiple = 0;            // ClientHello-Padding auf Vielfache von X (0 = kein Padding)
    uint8_t session_ticket_mode = 1;         // 0 = deaktiviert, 1 = aktiviert, 2 = erweitert
    uint16_t max_early_data_size = 0;        // Maximum Early Data Size (0-RTT, 0 = deaktiviert)
    
    // Optionale Parameter für spezielle Browser
    bool supports_post_handshake_auth = true; // Unterstützung für Post-Handshake-Authentifizierung
    bool supports_delegated_credentials = false; // Unterstützung für delegierte Credentials
    uint16_t max_fragment_length = 0;        // Maximum Fragment Length (0 = Standard)
};

class UTLSClientConfigurator {
public:
    UTLSClientConfigurator();
    ~UTLSClientConfigurator();

    // Initialisiert SSL_CTX, SSL Objekt und quiche_config
    // fingerprint: Der zu verwendende Browser-Fingerprint
    // hostname: Der Hostname für SNI
    // ca_cert_path: Pfad zum CA-Zertifikat für die Peer-Verifizierung (optional, nullptr für keine Verifizierung)
    // use_session_tickets: Aktiviert oder deaktiviert die Verwendung von TLS-Session-Tickets
    bool initialize(BrowserFingerprint fingerprint, const std::string& hostname, 
                   const char* ca_cert_path = nullptr, bool use_session_tickets = true);
    
    // Überladene Version die einen String-Bezeichner akzeptiert (für Abwärtskompatibilität)
    bool initialize(const std::string& fingerprint_profile_name, const std::string& hostname, 
                   const char* ca_cert_path = nullptr, bool use_session_tickets = true);
    
    // Hilfsmethode zur Konvertierung von String zu BrowserFingerprint
    static BrowserFingerprint string_to_fingerprint(const std::string& name);
    
    // Hilfsmethode zur Konvertierung von BrowserFingerprint zu String
    static std::string fingerprint_to_string(BrowserFingerprint fingerprint);

    // Zugriff auf die internen Objekte
    SSL* get_ssl_conn() const { return ssl_conn_; }
    quiche_config* get_quiche_config() const { return q_config_; }
    SSL_CTX* get_ssl_context() const { return ssl_ctx_; }
    
    // Gibt das aktuelle Fingerprint-Profil zurück
    BrowserFingerprint get_current_fingerprint() const { return current_fingerprint_; }
    
    // Hilfsmethoden für spezifische uTLS-Funktionalität
    bool set_sni(const std::string& hostname);
    bool apply_custom_fingerprint(const FingerprintProfile& profile);
    
    /**
     * @brief Wendet Zero-RTT-spezifische TLS-Extensions an
     * 
     * Konfiguriert quiche_config mit den richtigen TLS-Extensions für Zero-RTT,
     * basierend auf dem Browser-Fingerprint. Bei Zero-RTT-Verbindungen müssen
     * die gleichen Extensions wie bei der ursprünglichen Verbindung gesendet werden.
     * 
     * @param config Die Quiche-Konfiguration
     * @param fingerprint Der zu verwendende Browser-Fingerprint
     * @return bool True wenn erfolgreich
     */
    bool apply_zero_rtt_extensions(quiche_config* config, BrowserFingerprint fingerprint);

    // Speichert die aktuelle Session für den angegebenen Hostnamen
    bool storeCurrentSession(const std::string& hostname);
    
    // Versucht, eine vorherige Session für den Hostnamen wiederherzustellen
    bool restoreSession(const std::string& hostname);
    
    // Callback für neue Session-Tickets
    static int new_session_callback(SSL *ssl, SSL_SESSION *session);

private:
    SSL_CTX* ssl_ctx_;
    SSL* ssl_conn_;
    quiche_config* q_config_;
    BrowserFingerprint current_fingerprint_;
    bool use_session_tickets_;
    std::string current_hostname_;

    // Speichert die vorgefertigten Fingerprint-Profile
    static std::map<BrowserFingerprint, FingerprintProfile> fingerprint_profiles_;
    
    // Initialisiert die vorgefertigten Fingerprint-Profile
    static void initialize_fingerprint_profiles();
    
    // Private Hilfsmethoden zur Konfiguration des SSL_CTX
    bool apply_fingerprint_profile(BrowserFingerprint fingerprint);
    bool set_cipher_suites(const std::vector<std::string>& ciphers);
    bool set_curves(const std::vector<uint16_t>& curves);
    bool set_signature_algorithms(const std::vector<uint16_t>& sig_algs);
    bool add_extensions(const std::vector<TLSExtension>& extensions);
    bool set_client_hello_version(const std::string& version);
    
    // Erzeugt einen zufälligen Fingerprint
    FingerprintProfile generate_random_fingerprint();

    // Callback für benutzerdefinierte TLS-Erweiterungen
    static inline int add_custom_extension_cb(SSL *ssl, unsigned int ext_type,
                                       unsigned int context,
                                       const unsigned char **out,
                                       size_t *outlen, X509 *x, size_t chainidx,
                                       int *al, void *add_arg) {
        (void)ssl;
        (void)context;
        (void)x;
        (void)chainidx;
        (void)al;
        
        // Typumwandlung des add_arg zu einer BrowserFingerprint-Enum
        BrowserFingerprint fingerprint = BrowserFingerprint::CHROME_LATEST;
        if (add_arg != nullptr) {
            fingerprint = *static_cast<BrowserFingerprint*>(add_arg);
        }
        
        // Allokierter Speicher wird automatisch von OpenSSL freigegeben
        unsigned char* extension_data = nullptr;
        size_t extension_len = 0;
        
        // Extension-Typ bestimmen und entsprechende Daten generieren
        switch (ext_type) {
            case 0x0010: // ALPN (Application-Layer Protocol Negotiation)
                generate_alpn_extension(&extension_data, &extension_len, fingerprint);
                break;
                
            case 0x0017: // Extended Master Secret
                extension_data = static_cast<unsigned char*>(OPENSSL_malloc(0));
                extension_len = 0; // Diese Extension hat keine Daten
                break;
                
            case 0x002B: // Supported Versions
                generate_supported_versions(&extension_data, &extension_len, fingerprint);
                break;
                
            case 0x002D: // PSK Key Exchange Modes
                generate_psk_modes(&extension_data, &extension_len, fingerprint);
                break;
                
            case 0x0033: // Key Share
                generate_key_share(&extension_data, &extension_len, fingerprint);
                break;
                
            case 0x0029: // Session Tickets
                extension_data = static_cast<unsigned char*>(OPENSSL_malloc(0));
                extension_len = 0; // Diese Extension hat normalerweise keine Daten im ClientHello
                break;
                
            case 0x0000: // Server Name Indication (SNI)
                // SNI wird bereits von OpenSSL verarbeitet
                return 0;
                
            case 0x000A: // Supported Groups/Elliptic Curves
                // Wird bereits von OpenSSL verarbeitet
                return 0;
                
            case 0x000B: // EC Point Formats
                generate_ec_point_formats(&extension_data, &extension_len, fingerprint);
                break;
                
            default:
                // Für alle anderen Extensions: Default-Verhalten
                if (fingerprint == BrowserFingerprint::RANDOMIZED) {
                    // Für zufälliges Profil - zufällige Daten generieren
                    generate_random_extension_data(&extension_data, &extension_len, ext_type);
                } else {
                    // Für unbekannte Extensions fallback auf Standard
                    extension_data = static_cast<unsigned char*>(OPENSSL_malloc(4));
                    if (extension_data) {
                        extension_data[0] = 0x01;
                        extension_data[1] = 0x02;
                        extension_data[2] = 0x03;
                        extension_data[3] = 0x04;
                        extension_len = 4;
                    }
                }
                break;
        }
        
        // Prüfen, ob die Daten generiert wurden
        if (extension_data == nullptr) {
            return 0; // Fehler
        }
        
        *out = extension_data;
        *outlen = extension_len;
        
        return 1; // Erfolgreich
    }
    
    // Helper-Methoden für die TLS-Erweiterungsgenerierung
    static inline void generate_alpn_extension(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
        // ALPN-Protokolle für verschiedene Browser
        std::vector<std::string> protocols;
        
        switch (fingerprint) {
            case BrowserFingerprint::CHROME_LATEST:
            case BrowserFingerprint::CHROME_70:
            case BrowserFingerprint::CHROME_ANDROID:
            case BrowserFingerprint::EDGE_CHROMIUM:
                // Chrome und Chrome-basierte Browser
                protocols = {"h3", "h3-29", "h2", "http/1.1"};
                break;
                
            case BrowserFingerprint::FIREFOX_LATEST:
            case BrowserFingerprint::FIREFOX_63:
                // Firefox tendiert zu weniger Protokollen
                protocols = {"h2", "http/1.1"};
                break;
                
            case BrowserFingerprint::SAFARI_LATEST:
            case BrowserFingerprint::SAFARI_IOS:
                // Safari unterstützt HTTP/2 und HTTP/1.1
                protocols = {"h2", "http/1.1"};
                break;
                
            case BrowserFingerprint::OPERA_LATEST:
                // Opera (Chromium-basiert)
                protocols = {"h3", "h3-29", "h2", "http/1.1"};
                break;
                
            case BrowserFingerprint::BRAVE_LATEST:
                // Brave (Chromium-basiert)
                protocols = {"h3", "h3-29", "h2", "http/1.1"};
                break;
                
            case BrowserFingerprint::RANDOMIZED:
            case BrowserFingerprint::CUSTOM:
            default:
                // Zufällige Auswahl oder Fallback
                protocols = {"h2", "http/1.1"};
                
                // Zufällig auch HTTP/3 hinzufügen
                if (rand() % 2 == 0) {
                    protocols.insert(protocols.begin(), "h3");
                    protocols.insert(protocols.begin() + 1, "h3-29");
                }
                break;
        }
        
        // Berechne die Größe der ALPN-Erweiterung
        size_t total_size = 2; // 2 Bytes für die Länge der gesamten Liste
        
        for (const auto& proto : protocols) {
            total_size += 1 + proto.size(); // 1 Byte für Länge + Protokollname
        }
        
        // Allokiere Speicher für die Erweiterung
        *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
        if (*out == nullptr) {
            *outlen = 0;
            return;
        }
        
        unsigned char* p = *out;
        
        // Berechne die Länge der Protokollliste
        uint16_t list_length = static_cast<uint16_t>(total_size - 2);
        
        // Setze die Länge der gesamten Liste (Network Byte Order)
        *p++ = static_cast<unsigned char>((list_length >> 8) & 0xFF);
        *p++ = static_cast<unsigned char>(list_length & 0xFF);
        
        // Füge jedes Protokoll hinzu
        for (const auto& proto : protocols) {
            uint8_t proto_len = static_cast<uint8_t>(proto.size());
            *p++ = proto_len;
            std::memcpy(p, proto.c_str(), proto_len);
            p += proto_len;
        }
        
        *outlen = total_size;
    }
    
    static inline void generate_supported_versions(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
        // TLS-Versionen für verschiedene Browser (in Prioritätsreihenfolge)
        std::vector<uint16_t> versions;
        
        switch (fingerprint) {
            case BrowserFingerprint::CHROME_LATEST:
            case BrowserFingerprint::EDGE_CHROMIUM:
            case BrowserFingerprint::BRAVE_LATEST:
            case BrowserFingerprint::OPERA_LATEST:
                // Moderne Chrome-basierte Browser
                versions = {0x0304, 0x0303, 0x0302}; // TLS 1.3, TLS 1.2, TLS 1.1
                break;
                
            case BrowserFingerprint::CHROME_70:
                // Ältere Chrome-Version
                versions = {0x0303, 0x0302, 0x0301}; // TLS 1.2, TLS 1.1, TLS 1.0
                break;
                
            case BrowserFingerprint::CHROME_ANDROID:
                // Chrome für Android
                versions = {0x0304, 0x0303}; // TLS 1.3, TLS 1.2
                break;
                
            case BrowserFingerprint::FIREFOX_LATEST:
                // Moderner Firefox
                versions = {0x0304, 0x0303}; // TLS 1.3, TLS 1.2
                break;
                
            case BrowserFingerprint::FIREFOX_63:
                // Älterer Firefox
                versions = {0x0303, 0x0302, 0x0301}; // TLS 1.2, TLS 1.1, TLS 1.0
                break;
                
            case BrowserFingerprint::SAFARI_LATEST:
            case BrowserFingerprint::SAFARI_IOS:
                // Safari
                versions = {0x0304, 0x0303, 0x0302}; // TLS 1.3, TLS 1.2, TLS 1.1
                break;
                
            case BrowserFingerprint::RANDOMIZED:
            case BrowserFingerprint::CUSTOM:
            default:
                // Zufällige Auswahl oder Fallback
                versions = {0x0304, 0x0303}; // TLS 1.3, TLS 1.2
                break;
        }
        
        // Berechne die Größe der Extension
        size_t total_size = 1 + versions.size() * 2; // 1 Byte für die Länge + 2 Bytes pro Version
        
        // Allokiere Speicher für die Erweiterung
        *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
        if (*out == nullptr) {
            *outlen = 0;
            return;
        }
        
        unsigned char* p = *out;
        
        // Setze die Länge der Versionsliste
        *p++ = static_cast<unsigned char>(versions.size() * 2);
        
        // Füge jede Version hinzu (Network Byte Order)
        for (uint16_t version : versions) {
            *p++ = static_cast<unsigned char>((version >> 8) & 0xFF);
            *p++ = static_cast<unsigned char>(version & 0xFF);
        }
        
        *outlen = total_size;
    }
    
    static inline void generate_psk_modes(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
        // PSK-Modi für verschiedene Browser
        std::vector<uint8_t> modes;
        
        // Die meisten modernen Browser unterstützen PSK mit (EC)DHE
        modes = {0x01}; // PSK with (EC)DHE key establishment
        
        // Spezialfall: Erweiterung vollständig weglassen für ältere Browser
        if (fingerprint == BrowserFingerprint::CHROME_70 || 
            fingerprint == BrowserFingerprint::FIREFOX_63) {
            *out = nullptr;
            *outlen = 0;
            return;
        }
        
        // Berechne die Größe der Extension
        size_t total_size = 1 + modes.size(); // 1 Byte für die Länge + 1 Byte pro Modus
        
        // Allokiere Speicher für die Erweiterung
        *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
        if (*out == nullptr) {
            *outlen = 0;
            return;
        }
        
        unsigned char* p = *out;
        
        // Setze die Länge der Modiliste
        *p++ = static_cast<unsigned char>(modes.size());
        
        // Füge jeden Modus hinzu
        for (uint8_t mode : modes) {
            *p++ = mode;
        }
        
        *outlen = total_size;
    }
    
    static inline void generate_key_share(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
        // Da die tatsächliche Schlüsselgenerierung komplex ist, erstellen wir hier
        // eine vereinfachte Erweiterung mit einem Platzhalter-Schlüssel
        
        // Key-Share-Gruppen für verschiedene Browser
        std::vector<uint16_t> groups;
        
        switch (fingerprint) {
            case BrowserFingerprint::CHROME_LATEST:
            case BrowserFingerprint::EDGE_CHROMIUM:
            case BrowserFingerprint::BRAVE_LATEST:
            case BrowserFingerprint::OPERA_LATEST:
                // Moderne Chrome-basierte Browser
                groups = {0x001D, 0x0017}; // x25519, secp256r1
                break;
                
            case BrowserFingerprint::FIREFOX_LATEST:
                // Moderner Firefox
                groups = {0x001D, 0x0017}; // x25519, secp256r1
                break;
                
            case BrowserFingerprint::SAFARI_LATEST:
            case BrowserFingerprint::SAFARI_IOS:
                // Safari
                groups = {0x001D, 0x0017}; // x25519, secp256r1
                break;
                
            case BrowserFingerprint::RANDOMIZED:
            case BrowserFingerprint::CUSTOM:
            default:
                // Ein zufällige Gruppe
                groups = {0x001D}; // x25519
                break;
        }
        
        // Simuliere einen einfachen Key Share für X25519 (32 Bytes)
        uint8_t key_data[32];
        RAND_bytes(key_data, sizeof(key_data));
        
        // Berechne die Größe der Extension
        size_t client_shares_size = 0;
        for (size_t i = 0; i < groups.size(); i++) {
            // 2 Bytes für die Gruppe + 2 Bytes für die Keylänge + simulierte Keylänge (32 Bytes)
            client_shares_size += 2 + 2 + 32;
        }
        
        size_t total_size = 2 + client_shares_size; // 2 Bytes für die Länge + Inhalt
        
        // Allokiere Speicher für die Erweiterung
        *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
        if (*out == nullptr) {
            *outlen = 0;
            return;
        }
        
        unsigned char* p = *out;
        
        // Setze die Länge der Client-Shares
        uint16_t shares_length = static_cast<uint16_t>(client_shares_size);
        *p++ = static_cast<unsigned char>((shares_length >> 8) & 0xFF);
        *p++ = static_cast<unsigned char>(shares_length & 0xFF);
        
        // Füge jeden Key Share hinzu
        for (uint16_t group : groups) {
            // Named Group
            *p++ = static_cast<unsigned char>((group >> 8) & 0xFF);
            *p++ = static_cast<unsigned char>(group & 0xFF);
            
            // Key Exchange Länge
            uint16_t key_length = 32; // X25519 hat immer 32 Bytes
            *p++ = static_cast<unsigned char>((key_length >> 8) & 0xFF);
            *p++ = static_cast<unsigned char>(key_length & 0xFF);
            
            // Key Exchange Daten (zufällig)
            RAND_bytes(p, key_length);
            p += key_length;
        }
        
        *outlen = total_size;
    }
    
    static inline void generate_ec_point_formats(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
        // EC Point Formats für verschiedene Browser
        std::vector<uint8_t> formats;
        
        // Die meisten Browser verwenden nur uncompressed
        formats = {0x00}; // uncompressed
        
        // Berechne die Größe der Extension
        size_t total_size = 1 + formats.size(); // 1 Byte für die Länge + 1 Byte pro Format
        
        // Allokiere Speicher für die Erweiterung
        *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
        if (*out == nullptr) {
            *outlen = 0;
            return;
        }
        
        unsigned char* p = *out;
        
        // Setze die Länge der Formatliste
        *p++ = static_cast<unsigned char>(formats.size());
        
        // Füge jedes Format hinzu
        for (uint8_t format : formats) {
            *p++ = format;
        }
        
        *outlen = total_size;
    }
    
    static inline void generate_random_extension_data(unsigned char** out, size_t* outlen, unsigned int ext_type) {
        // Generiere eine zufällige Länge zwischen 0 und 32 Bytes
        size_t length = rand() % 33;
        
        // Allokiere Speicher für die Erweiterung
        *out = static_cast<unsigned char*>(OPENSSL_malloc(length));
        if (*out == nullptr || length == 0) {
            *out = static_cast<unsigned char*>(OPENSSL_malloc(0));
            *outlen = 0;
            return;
        }
        
        // Generiere zufällige Daten
        RAND_bytes(*out, length);
        
        *outlen = length;
    }
    
    // Hilfsmethode zum Protokollieren von OpenSSL-Fehlern
    void log_ssl_errors(const std::string& prefix);
};

#endif // UTLS_CLIENT_CONFIGURATOR_HPP
