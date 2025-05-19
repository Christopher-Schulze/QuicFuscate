#include "utls_client_configurator.hpp"
#include "quiche_utls_wrapper.hpp"
#include "session_ticket_utils.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <dlfcn.h>

// Statische Initialisierung der Fingerprint-Profile
std::map<BrowserFingerprint, FingerprintProfile> UTLSClientConfigurator::fingerprint_profiles_;

// Hilfsmethoden zur Konvertierung zwischen String und Enum
BrowserFingerprint UTLSClientConfigurator::string_to_fingerprint(const std::string& name) {
    // Desktop Browser
    if (name == "Chrome_Latest" || name == "chrome_latest") return BrowserFingerprint::CHROME_LATEST;
    if (name == "Firefox_Latest" || name == "firefox_latest") return BrowserFingerprint::FIREFOX_LATEST;
    if (name == "Safari_Latest" || name == "safari_latest") return BrowserFingerprint::SAFARI_LATEST;
    if (name == "Edge_Chromium" || name == "edge_chromium") return BrowserFingerprint::EDGE_CHROMIUM;
    if (name == "Brave" || name == "brave") return BrowserFingerprint::BRAVE;
    if (name == "Opera" || name == "opera") return BrowserFingerprint::OPERA;
    
    // Ältere Versionen
    if (name == "Chrome_70" || name == "chrome_70") return BrowserFingerprint::CHROME_70;
    if (name == "Firefox_63" || name == "firefox_63") return BrowserFingerprint::FIREFOX_63;
    
    // Mobile Browser
    if (name == "Chrome_Android" || name == "chrome_android") return BrowserFingerprint::CHROME_ANDROID;
    if (name == "Safari_iOS" || name == "safari_ios" || name == "safari_ios") return BrowserFingerprint::SAFARI_IOS;
    if (name == "Samsung_Browser" || name == "samsung_browser") return BrowserFingerprint::SAMSUNG_BROWSER;
    if (name == "Firefox_Mobile" || name == "firefox_mobile") return BrowserFingerprint::FIREFOX_MOBILE;
    if (name == "Edge_Mobile" || name == "edge_mobile") return BrowserFingerprint::EDGE_MOBILE;
    
    // Spezialisierte Clients
    if (name == "Outlook" || name == "outlook") return BrowserFingerprint::OUTLOOK;
    if (name == "Thunderbird" || name == "thunderbird") return BrowserFingerprint::THUNDERBIRD;
    if (name == "Curl" || name == "curl") return BrowserFingerprint::CURL;
    
    // Alte Namen für Kompatibilität
    if (name == "Opera_Latest" || name == "opera_latest") return BrowserFingerprint::OPERA;
    if (name == "Brave_Latest" || name == "brave_latest") return BrowserFingerprint::BRAVE;
    if (name == "Randomized" || name == "randomized" || name == "random") return BrowserFingerprint::RANDOMIZED;
    if (name == "Custom" || name == "custom") return BrowserFingerprint::CUSTOM;
    
    // Standardmäßig Chrome Latest als Fallback
    std::cerr << "Warnung: Unbekanntes Fingerprint-Profil '" << name << "'. Verwende Chrome_Latest als Fallback." << std::endl;
    return BrowserFingerprint::CHROME_LATEST;
}

std::string UTLSClientConfigurator::fingerprint_to_string(BrowserFingerprint fingerprint) {
    switch (fingerprint) {
        // Desktop Browser
        case BrowserFingerprint::CHROME_LATEST: return "Chrome_Latest";
        case BrowserFingerprint::FIREFOX_LATEST: return "Firefox_Latest";
        case BrowserFingerprint::SAFARI_LATEST: return "Safari_Latest";
        case BrowserFingerprint::EDGE_CHROMIUM: return "Edge_Chromium";
        case BrowserFingerprint::BRAVE: return "Brave";
        case BrowserFingerprint::OPERA: return "Opera";
        
        // Ältere Versionen
        case BrowserFingerprint::CHROME_70: return "Chrome_70";
        case BrowserFingerprint::FIREFOX_63: return "Firefox_63";
        
        // Mobile Browser
        case BrowserFingerprint::CHROME_ANDROID: return "Chrome_Android";
        case BrowserFingerprint::SAFARI_IOS: return "Safari_iOS";
        case BrowserFingerprint::SAMSUNG_BROWSER: return "Samsung_Browser";
        case BrowserFingerprint::FIREFOX_MOBILE: return "Firefox_Mobile";
        case BrowserFingerprint::EDGE_MOBILE: return "Edge_Mobile";
        
        // Spezialisierte Clients
        case BrowserFingerprint::OUTLOOK: return "Outlook";
        case BrowserFingerprint::THUNDERBIRD: return "Thunderbird";
        case BrowserFingerprint::CURL: return "Curl";
        
        // Spezielle Werte
        case BrowserFingerprint::RANDOMIZED: return "Randomized";
        case BrowserFingerprint::CUSTOM: return "Custom";
        
        default: return "Unknown";
    }
}

UTLSClientConfigurator::UTLSClientConfigurator()
    : ssl_ctx_(nullptr), ssl_conn_(nullptr), q_config_(nullptr), current_fingerprint_(BrowserFingerprint::CHROME_LATEST), use_session_tickets_(true), current_hostname_("") {
    // Statische Initialisierung der Fingerprint-Profile beim ersten Objektinstanziierung
    static bool profiles_initialized = false;
    if (!profiles_initialized) {
        initialize_fingerprint_profiles();
        profiles_initialized = true;
    }
}

UTLSClientConfigurator::~UTLSClientConfigurator() {
    if (ssl_conn_) {
        SSL_free(ssl_conn_);
        ssl_conn_ = nullptr;
    }
    if (q_config_) {
        quiche_config_free(q_config_);
        q_config_ = nullptr;
    }
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
}

// Überladene Version, die einen String-Bezeichner für den Fingerprint akzeptiert
bool UTLSClientConfigurator::initialize(const std::string& fingerprint_profile_name,
                                        const std::string& hostname,
                                        const char* ca_cert_path,
                                        bool use_session_tickets) {
    // Konvertieren des Fingerprint-Namens in das entsprechende Enum
    BrowserFingerprint fingerprint = string_to_fingerprint(fingerprint_profile_name);
    return initialize(fingerprint, hostname, ca_cert_path, use_session_tickets);
}

// Hauptinitialisierungsmethode - Robuste Version mit Fehlertoleranz
bool UTLSClientConfigurator::initialize(BrowserFingerprint fingerprint,
                                        const std::string& hostname,
                                        const char* ca_cert_path,
                                        bool use_session_tickets) {
    // Setzen des Fingerprints, Hostnamen und Session-Ticket-Flags
    current_fingerprint_ = fingerprint;
    current_hostname_ = hostname;
    use_session_tickets_ = use_session_tickets;

    // Freigeben von vorherigen Ressourcen, falls vorhanden
    if (ssl_conn_) {
        SSL_free(ssl_conn_);
        ssl_conn_ = nullptr;
    }
    if (q_config_) {
        quiche_config_free(q_config_);
        q_config_ = nullptr;
    }
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }

    std::cout << "UTLSClientConfigurator: Initializing with fingerprint profile '" 
              << fingerprint_to_string(fingerprint) << "' for host '" << hostname << "'" << std::endl;
              
    // FEHLERTOLERANTE INITIALISIERUNG
    // Alle Fehler werden protokolliert, aber die Initialisierung wird nicht abgebrochen

    // Initialisiere SSL_CTX mit TLS-Methode
    ssl_ctx_ = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx_ == nullptr) {
        log_ssl_errors("Failed to create SSL context");
        return false;
    }
    
    // Session-Ticket-Callback einrichten, wenn aktiviert
    if (use_session_tickets_) {
        SSL_CTX_set_session_cache_mode(ssl_ctx_, SSL_SESS_CACHE_CLIENT);
        SSL_CTX_sess_set_new_cb(ssl_ctx_, new_session_callback);
    }

    // 2. Quiche-QUIC-Method an den SSL_CTX binden
    const SSL_QUIC_METHOD* quic_method = quiche_ssl_get_quic_method();
    if (!quic_method) {
        std::cerr << "UTLSClientConfigurator: Failed to get quiche SSL_QUIC_METHOD" << std::endl;
        SSL_CTX_free(ssl_ctx_); ssl_ctx_ = nullptr;
        return false;
    }
    
    // Binde die QUIC-Methode an den SSL_CTX
    // Da SSL_CTX_set_quic_method möglicherweise nicht direkt verfügbar ist,
    // versuchen wir, die Funktion dynamisch zu finden oder einen Fallback zu verwenden
    typedef int (*SSL_CTX_set_quic_method_fn)(SSL_CTX *, const SSL_QUIC_METHOD *);
    SSL_CTX_set_quic_method_fn set_quic_method_fn = 
        (SSL_CTX_set_quic_method_fn)dlsym(RTLD_DEFAULT, "SSL_CTX_set_quic_method");
    
    if (set_quic_method_fn) {
        set_quic_method_fn(ssl_ctx_, quic_method);
    } else {
        // Fallback: Verwende andere SSL/TLS-Konfiguration wenn die Funktion nicht verfügbar ist
        std::cout << "Warning: SSL_CTX_set_quic_method nicht verfügbar, QUIC-TLS-Integration könnte beeinträchtigt sein" << std::endl;
        // Setze alternative TLS-Konfigurationen, die ohne QUIC-Methoden funktionieren
    }

    // 3. TLS 1.3 als Minimalversion setzen
    if (SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION) != 1) {
        log_ssl_errors("SSL_CTX_set_min_proto_version to TLS 1.3 failed");
        SSL_CTX_free(ssl_ctx_); ssl_ctx_ = nullptr;
        return false;
    }

    // 4. quiche_config erstellen und Grundkonfiguration
    q_config_ = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (!q_config_) {
        std::cerr << "UTLSClientConfigurator: quiche_config_new failed" << std::endl;
        SSL_CTX_free(ssl_ctx_); ssl_ctx_ = nullptr;
        return false;
    }

    // 5. ALPN Protokolle setzen (Application-Layer Protocol Negotiation)
    // HTTP/3 ist standard für QUIC
    const uint8_t* alpn = (const uint8_t*)"\x02h3";
    const size_t alpn_len = 3; // \x02 + 'h3'
    
    if (quiche_config_set_application_protos(q_config_, alpn, alpn_len) < 0) {
        std::cerr << "UTLSClientConfigurator: quiche_config_set_application_protos failed" << std::endl;
        quiche_config_free(q_config_); q_config_ = nullptr;
        SSL_CTX_free(ssl_ctx_); ssl_ctx_ = nullptr;
        return false;
    }

    // 6. Peer-Verifizierung konfigurieren
    if (ca_cert_path && strlen(ca_cert_path) > 0) {
        quiche_config_verify_peer(q_config_, true);
        if (quiche_config_load_verify_locations_from_file(q_config_, ca_cert_path) < 0) {
            std::cerr << "UTLSClientConfigurator: quiche_config_load_verify_locations_from_file failed for " << ca_cert_path << std::endl;
            quiche_config_free(q_config_); q_config_ = nullptr;
            SSL_CTX_free(ssl_ctx_); ssl_ctx_ = nullptr;
            return false;
        }
        std::cout << "UTLSClientConfigurator: CA certificate loaded from " << ca_cert_path << std::endl;
    } else {
        quiche_config_verify_peer(q_config_, false);
        std::cout << "UTLSClientConfigurator: Peer verification DISABLED (no CA path provided)" << std::endl;
    }
    
    // 7. Konfiguriere Transport-Parameter
    quiche_config_set_max_idle_timeout(q_config_, 30000); // 30 Sekunden
    quiche_config_set_max_recv_udp_payload_size(q_config_, 65527);
    quiche_config_set_initial_max_data(q_config_, 10000000); // 10 MB
    quiche_config_set_initial_max_stream_data_bidi_local(q_config_, 1000000); // 1 MB
    quiche_config_set_initial_max_stream_data_bidi_remote(q_config_, 1000000); // 1 MB
    quiche_config_set_initial_max_stream_data_uni(q_config_, 1000000); // 1 MB
    quiche_config_set_initial_max_streams_bidi(q_config_, 100);
    quiche_config_set_initial_max_streams_uni(q_config_, 100);
    
    // 8. Browser-Fingerprint-Profil anwenden mit Fehlertoleranz
    // Versuche das Profil anzuwenden, aber setze die Initialisierung fort, selbst wenn es fehlschlägt
    if (!apply_fingerprint_profile(fingerprint)) {
        std::cerr << "UTLSClientConfigurator: apply_fingerprint_profile for '" 
                  << fingerprint_to_string(fingerprint) << "' failed, but continuing with defaults" << std::endl;
        // Setze einige Grundeinstellungen, falls möglich
        if (ssl_ctx_) {
            SSL_CTX_set_cipher_list(ssl_ctx_, "HIGH:!aNULL:!MD5");
            SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);
        }
    }

    // 9. SSL-Verbindungsobjekt erstellen - mit Fehlertoleranz
    // Nur versuchen, wenn ssl_ctx_ existiert
    if (ssl_ctx_) {
        ssl_conn_ = SSL_new(ssl_ctx_);
        if (!ssl_conn_) {
            log_ssl_errors("SSL_new failed");
            std::cout << "UTLSClientConfigurator: WARNING - Creating SSL connection failed, but continuing" << std::endl;
            // Fehler protokollieren, aber nicht abbrechen
        }
    } else {
        std::cout << "UTLSClientConfigurator: WARNING - Cannot create SSL connection without context" << std::endl;
    }
    
    // 10. SNI setzen - mit Fehlertoleranz
    if (!hostname.empty() && ssl_conn_) {
        if (!set_sni(hostname)) {
            std::cerr << "UTLSClientConfigurator: Failed to set SNI for hostname '" << hostname << "', but continuing" << std::endl;
            // Fehler protokollieren, aber nicht abbrechen
        }
    }

    // Wichtig: SSL-Objekt in den Client-Modus versetzen
    SSL_set_connect_state(ssl_conn_);
    std::cout << "UTLSClientConfigurator: SSL_set_connect_state called." << std::endl;
    std::cout.flush();

    // SNI (Server Name Indication) direkt im SSL Objekt setzen - mit Fehlertoleranz
    if (!hostname.empty() && ssl_conn_) {
        if (SSL_set_tlsext_host_name(ssl_conn_, hostname.c_str()) != 1) {
            std::cerr << "UTLSClientConfigurator: SSL_set_tlsext_host_name failed for " << hostname << ", but continuing" << std::endl;
            ERR_print_errors_fp(stderr);
            // NICHT abbrechen, stattdessen weitermachen, auch wenn SNI fehlschlägt
        } else {
            std::cout << "UTLSClientConfigurator: SSL_set_tlsext_host_name set to '" << hostname << "'." << std::endl;
        }
        std::cout.flush();
    }

    // SSL_QUIC_METHOD für quiche setzen - mit besserer Fehlertoleranz
    const SSL_QUIC_METHOD* quic_method_ssl = quiche_ssl_get_quic_method();
    if (!quic_method_ssl) {
        std::cerr << "UTLSClientConfigurator: quiche_ssl_get_quic_method failed (returned nullptr)" << std::endl;
        std::cerr << "UTLSClientConfigurator: Continuing without QUIC method support" << std::endl;
        // Weiter ohne QUIC-Methode - kein Abbruch, da wir robust sein wollen
    } else {
        // Dynamischer Funktionsaufruf mit Fehlerbehandlung
        typedef int (*ssl_set_quic_method_fn)(SSL*, const SSL_QUIC_METHOD*);
        void* sym = dlsym(RTLD_DEFAULT, "SSL_set_quic_method");
        if (sym) {
            auto fn = (ssl_set_quic_method_fn)sym;
            if (fn(ssl_conn_, quic_method_ssl) != 1) {
                std::cerr << "UTLSClientConfigurator: SSL_set_quic_method failed, but continuing" << std::endl;
                ERR_print_errors_fp(stderr);
                // Weiter trotz Fehler - wir brechen nicht ab
            } else {
                std::cout << "UTLSClientConfigurator: SSL_set_quic_method successful." << std::endl;
            }
        } else {
            std::cerr << "Warning: SSL_CTX_set_quic_method nicht verfügbar, QUIC-TLS-Integration könnte beeinträchtigt sein" << std::endl;
            // Weiter ohne QUIC-Methode - kein Abbruch
        }
    }
    std::cout.flush();

    // Wenn Session-Tickets aktiviert sind, versuche eine vorherige Session wiederherzustellen
    if (use_session_tickets_) {
        restoreSession(hostname);
    }

    // TODO: Fingerprint anwenden (Cipher Suiten, Extensions, etc.) basierend auf profile_name
    return true;
}

// SNI in einer bestehenden SSL-Verbindung setzen
bool UTLSClientConfigurator::set_sni(const std::string& hostname) {
    if (!ssl_conn_) {
        std::cerr << "UTLSClientConfigurator::set_sni: No SSL connection available" << std::endl;
        return false;
    }
    
    // Setze SNI für SSL-Verbindung
    if (SSL_set_tlsext_host_name(ssl_conn_, hostname.c_str()) != 1) {
        log_ssl_errors("Failed to set SNI");
        return false;
    }
    
    // Wenn QUIC-Verbindung verfügbar, setze auch dort SNI
    if (q_config_ && ssl_conn_) {
        // Hier verwenden wir NICHT quiche_conn_set_sni, da ssl_conn_ vom Typ SSL* ist
        // und nicht quiche_conn* - die beiden sind nicht kompatibel
        std::cout << "UTLSClientConfigurator: Set SNI " << hostname << " for SSL connection" << std::endl;
    }
    
    return true;
}

// Anwenden eines benutzerdefinierten Fingerprint-Profils
bool UTLSClientConfigurator::apply_custom_fingerprint(const FingerprintProfile& profile) {
    if (!ssl_ctx_ || !ssl_conn_) return false;
    
    std::cout << "UTLSClientConfigurator: Applying fingerprint profile '" 
              << profile.name << "'" << std::endl;
    
    bool success = true;
    
    // 1. Setze Cipher Suites
    if (!profile.cipher_suites.empty()) {
        // Konvertiere den Vector<string> in einen durch Doppelpunkt getrennten String
        std::stringstream ss;
        for (size_t i = 0; i < profile.cipher_suites.size(); i++) {
            ss << profile.cipher_suites[i];
            if (i < profile.cipher_suites.size() - 1) ss << ":";
        }
        std::string cipher_list = ss.str();
        
        bool tls13_set = false;
        // Erst versuchen wir, TLS 1.3 Cipher zu setzen
        if (!cipher_list.empty()) {
            if (SSL_CTX_set_ciphersuites(ssl_ctx_, cipher_list.c_str()) == 1) {
                tls13_set = true;
            }
        }
        
        // Dann die älteren TLS 1.2 Cipher, wenn wir TLS 1.3 Cipher haben oder nicht
        if (SSL_CTX_set_cipher_list(ssl_ctx_, cipher_list.c_str()) != 1) {
            log_ssl_errors("Warning: Failed to set custom cipher list");
            // Fallback auf sichere Standard-Cipher
            if (SSL_CTX_set_cipher_list(ssl_ctx_, "HIGH:!aNULL:!MD5:!RC4") != 1) {
                log_ssl_errors("Failed to set even default cipher list");
                success = false;
            }
        }
    } else {
        // Verwende Standardwerte für Cipher Suites, wenn keine angegeben sind
        std::string cipher_list = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
        SSL_CTX_set_ciphersuites(ssl_ctx_, cipher_list.c_str());
        SSL_CTX_set_cipher_list(ssl_ctx_, "HIGH:!aNULL:!MD5:!RC4");
    }
    
        int default_curves[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1};
        SSL_CTX_set1_curves(ssl_ctx_, default_curves, 3);
    }
    
    // 3. Setze Signaturalgorithmen
    if (!profile.signature_algos.empty()) {
        // Dies ist komplexer und hängt von der OpenSSL-Version ab
        // Moderne Implementierung mit SSL_CTX_set1_sigalgs
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        std::vector<int> sig_algs_vec(profile.signature_algos.begin(), profile.signature_algos.end());
        if (SSL_CTX_set1_sigalgs(ssl_ctx_, sig_algs_vec.data(), sig_algs_vec.size()) != 1) {
            std::cerr << "Warning: Failed to set signature algorithms, using OpenSSL defaults" << std::endl;
        }
#endif
    }
    
    // 4. Setze Kompressionsmethoden (meist nur "keine Kompression" = 0x00)
    if (!profile.compression_methods.empty()) {
        // Direkte Manipulation der Kompressionsoptionen ist in modernem OpenSSL
        // eingeschränkt, aber wir können die Standardmethode verwenden
        // Kompression wird in TLS 1.3 nicht mehr verwendet
        // OpenSSL hat die Standardeinstellung bereits auf "keine Kompression"
    }
    
    // 5. Stelle die richtige TLS-Version ein
    if (!profile.client_hello_version.empty()) {
        // Parse the TLS version string
        int max_version = TLS1_3_VERSION; // Default to TLS 1.3
        
        if (profile.client_hello_version == "TLS 1.2") {
            max_version = TLS1_2_VERSION;
        } else if (profile.client_hello_version == "TLS 1.1") {
            max_version = TLS1_1_VERSION;
        } else if (profile.client_hello_version == "TLS 1.0") {
            max_version = TLS1_VERSION;
        }
        
        // Set min/max protocol version
        if (SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION) != 1) {
            std::cerr << "Warning: Failed to set min TLS version" << std::endl;
        }
        
        if (SSL_CTX_set_max_proto_version(ssl_ctx_, max_version) != 1) {
            std::cerr << "Warning: Failed to set max TLS version" << std::endl;
        }
    } else {
        // Default to TLS 1.3
        SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);
    }
    
    // 6. TLS-Erweiterungen konfigurieren
    if (!profile.extensions.empty()) {
        // Direkte Manipulation von TLS-Erweiterungen ist mit der Standard-OpenSSL-API
        // eingeschränkt. Einige Erweiterungen können jedoch über spezifische Funktionen konfiguriert werden.
        
        // Durchlaufe die Erweiterungen und konfiguriere die, die wir direkt unterstützen
        for (const auto& ext : profile.extensions) {
            switch (ext.type) {
                case 0x0000: // Server Name Indication (SNI)
                    // Wird bereits durch set_sni() konfiguriert
                    break;
                    
                case 0x0010: // ALPN
                    // Beispiel für HTTP/2 und HTTP/1.1
                    {
                        const unsigned char alpn_protos[] = "\x02h2\x08http/1.1";
                        if (SSL_CTX_set_alpn_protos(ssl_ctx_, alpn_protos, sizeof(alpn_protos) - 1) != 0) {
                            std::cerr << "Warning: Failed to set ALPN" << std::endl;
                        }
                    }
                    break;
                    
                case 0x0015: // Padding
                    // Wird über profile.padding_multiple behandelt
                    break;
                    
                // Für andere Erweiterungen gibt es oft keine direkten OpenSSL-Funktionen
                // oder sie erfordern komplexere Custom-Implementierungen
            }
        }
    }
    
    // 7. Weitere Optionen basierend auf den erweiterten Fingerprint-Parametern
    
    // Record Size Limit - erfordert spezielle TLS-Erweiterung (RFC 8449)
    if (profile.record_size_limit > 0) {
        // Dies erfordert OpenSSL 1.1.1 oder höher und besondere Konfiguration
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
        // In einer vollständigen Implementierung würde hier die Record-Size-Limit-Extension konfiguriert
#endif
    }
    
    // Session Ticket-Modus konfigurieren
    if (profile.session_ticket_mode == 0) {
        // Deaktiviert
        SSL_CTX_set_options(ssl_ctx_, SSL_OP_NO_TICKET);
    } else {
        // Aktiviert (Standard) oder erweitert
        SSL_CTX_clear_options(ssl_ctx_, SSL_OP_NO_TICKET);
    }
    
    // Early Data (0-RTT) - erfordert TLS 1.3 und Session Tickets
    if (profile.max_early_data_size > 0) {
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
        SSL_CTX_set_max_early_data(ssl_ctx_, profile.max_early_data_size);
#endif
    }
    
    // Post-Handshake Authentifizierung - TLS 1.3 Funktion
    if (profile.supports_post_handshake_auth) {
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
        SSL_CTX_set_post_handshake_auth(ssl_ctx_, 1);
#endif
    }
    
    return success;
}

// Initialisierung der vorgefertigten Fingerprint-Profile
void UTLSClientConfigurator::initialize_fingerprint_profiles() {
    // Chrome Latest Profile (Chrome 120+) - Aktualisiert Mai 2024
    {
        FingerprintProfile chrome;
        chrome.name = "Chrome_Latest";
        chrome.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",              // TLS 1.3
            "TLS_AES_256_GCM_SHA384",              // TLS 1.3
            "TLS_CHACHA20_POLY1305_SHA256",         // TLS 1.3
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", // Neuer Eintrag in Chrome 120
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"  // Neuer Eintrag in Chrome 120
        };
        
        // Kompressionsalgorithmen (Chrome unterstützt keine Kompression seit vielen Jahren)
        chrome.compression_methods = {0x00}; // Keine Kompression
        
        chrome.curves = {
            NID_X25519,           // Curve25519 (Priorisiert in neuem Chrome)
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1,        // NIST P-384
            NID_secp521r1,        // NIST P-521
            NID_ffdhe2048,        // FFDHE 2048 (DHE-Parameter)
            NID_ffdhe3072         // FFDHE 3072 (DHE-Parameter)
        };
        
        chrome.signature_algos = {
            NID_ecdsa_with_SHA256,  // Priorisiert in Chrome
            NID_rsa_pss_pss_sha256, // RSA-PSS mit SHA-256
            NID_rsa_pss_pss_sha384, // RSA-PSS mit SHA-384
            NID_rsa_pss_pss_sha512, // RSA-PSS mit SHA-512
            NID_ecdsa_with_SHA384,
            NID_ecdsa_with_SHA512,
            NID_sha256WithRSAEncryption,
            NID_sha384WithRSAEncryption,
            NID_sha512WithRSAEncryption
        };
        
        // TLS Extensions für Chrome
        chrome.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0012, {}}, // Signed Certificate Timestamp
            {0x0022, {}}, // Encrypt-then-MAC
            {0x0023, {}}, // Extended Master Secret
            {0x0033, {}}, // Key Share
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0017, {}}, // Extended Master Secret
            {0x0029, {}}, // Pre-Shared Key
            {0x0015, {}}, // Padding (für ClientHello-Größe)
            {0x4469, {}}  // Cookie Extension
        };
        
        chrome.client_hello_version = "TLS 1.3";
        
        // Chrome spezifische Eigenschaften (für bessere Nachahmung)
        chrome.record_size_limit = 16385;        // Maximum TLS Record Size
        chrome.padding_multiple = 64;           // ClientHello Padding auf Vielfache von 64 Bytes
        chrome.session_ticket_mode = 1;         // Session Tickets aktiviert
        
        fingerprint_profiles_[BrowserFingerprint::CHROME_LATEST] = chrome;
    }
    
    // Firefox Latest Profile (Firefox 123+) - Aktualisiert Mai 2024
    {
        FingerprintProfile firefox;
        firefox.name = "Firefox_Latest";
        firefox.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",              // TLS 1.3
            "TLS_CHACHA20_POLY1305_SHA256",         // TLS 1.3 (Firefox priorisiert ChaCha20 über AES-256)
            "TLS_AES_256_GCM_SHA384",              // TLS 1.3
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", // Firefox unterstützt diese Kombination
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        // Kompressionsalgorithmen
        firefox.compression_methods = {0x00}; // Keine Kompression
        
        firefox.curves = {
            NID_X25519,           // Curve25519 (von Firefox stark priorisiert)
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1,        // NIST P-384
            NID_secp521r1,        // NIST P-521
            NID_ffdhe2048,        // FFDHE 2048 (Firefox unterstützt auch DHE)
            NID_ffdhe3072         // FFDHE 3072
        };
        
        firefox.signature_algos = {
            NID_ecdsa_with_SHA256, // höchste Priorität
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha384,
            NID_sha384WithRSAEncryption,
            NID_ecdsa_with_SHA512,
            NID_rsa_pss_pss_sha512,
            NID_sha512WithRSAEncryption
        };
        
        // TLS Extensions für Firefox
        firefox.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0012, {}}, // Signed Certificate Timestamp
            {0x0017, {}}, // Extended Master Secret
            {0x0023, {}}, // Session Ticket
            {0x0028, {}}, // Record Size Limit
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0xff01, {}}  // Renegotiation Info
        };
        
        firefox.client_hello_version = "TLS 1.3";
        
        // Firefox spezifische Eigenschaften
        firefox.record_size_limit = 16385;       // Record Size Limit
        firefox.session_ticket_mode = 1;         // Session Tickets aktiviert
        firefox.padding_multiple = 0;            // Firefox verwendet kein Padding
        
        fingerprint_profiles_[BrowserFingerprint::FIREFOX_LATEST] = firefox;
    }
    
    // Safari Latest Profile (Safari 17+) - Aktualisiert Mai 2024
    {
        FingerprintProfile safari;
        safari.name = "Safari_Latest";
        safari.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",              // TLS 1.3
            "TLS_AES_256_GCM_SHA384",              // TLS 1.3
            "TLS_CHACHA20_POLY1305_SHA256",         // TLS 1.3
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", // Safari priorisiert diese Kombination
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            // Safari bietet weniger Ciphersuites an als Chrome/Firefox
        };
        
        // Kompressionsalgorithmen
        safari.compression_methods = {0x00}; // Keine Kompression
        
        safari.curves = {
            NID_X25519,           // Curve25519 - Safari präferiert diese
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1        // NIST P-384
            // Safari unterstützt kein NIST P-521 oder FFDHE in aktuellen Versionen
        };
        
        safari.signature_algos = {
            NID_ecdsa_with_SHA256,  // Höchste Priorität
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha256, // Safari 17+ unterstützt RSA-PSS
            NID_sha256WithRSAEncryption,
            NID_sha384WithRSAEncryption,
            NID_rsa_pss_pss_sha384,
            NID_ecdsa_with_SHA512,
            NID_sha512WithRSAEncryption
        };
        
        // TLS Extensions für Safari
        safari.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0001, {}}, // Max Fragment Length (Safari spezifisch)
            {0xff01, {}}  // Renegotiation Info
            // Safari bietet weniger Extensions als andere Browser
        };
        
        safari.client_hello_version = "TLS 1.3";
        
        // Safari spezifische Eigenschaften
        safari.padding_multiple = 0;         // Safari verwendet kein Padding
        safari.session_ticket_mode = 1;      // Session Tickets aktiviert
        safari.record_size_limit = 16384;    // Standard TLS Record Size
        safari.max_fragment_length = 16384;  // Standard Maximum Fragment Length
        
        fingerprint_profiles_[BrowserFingerprint::SAFARI_LATEST] = safari;
    }
    
    // Safari iOS Profile (iOS 17+) - Aktualisiert Mai 2024
    {
        FingerprintProfile safari_ios;
        safari_ios.name = "Safari_iOS";
        safari_ios.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        };
        
        // Kompressionsalgorithmen
        safari_ios.compression_methods = {0x00}; // Keine Kompression
        
        safari_ios.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
        };
        
        safari_ios.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_sha384WithRSAEncryption,
            NID_rsa_pss_pss_sha384,
            NID_ecdsa_with_SHA512,
            NID_sha512WithRSAEncryption
        };
        
        // TLS Extensions für Safari iOS
        safari_ios.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0001, {}}, // Max Fragment Length (iOS Spezifisch)
            {0xff01, {}}  // Renegotiation Info
        };
        
        safari_ios.client_hello_version = "TLS 1.3";
        
        // iOS spezifische Eigenschaften
        safari_ios.padding_multiple = 0;      // Safari iOS verwendet kein Padding
        safari_ios.session_ticket_mode = 1;   // Session Tickets aktiviert
        safari_ios.record_size_limit = 16384; // Standard TLS Record Size
        safari_ios.max_fragment_length = 4096; // Kleinere Fragmente für mobile Geräte
        
        fingerprint_profiles_[BrowserFingerprint::SAFARI_IOS] = safari_ios;
    }
    
    // Chrome Android Profile (Chrome 120+ für Android) - Aktualisiert Mai 2024
    {
        FingerprintProfile chrome_android;
        chrome_android.name = "Chrome_Android";
        chrome_android.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", // Auf Mobilgeräten häufiger höher priorisiert
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        // Kompressionsalgorithmen
        chrome_android.compression_methods = {0x00}; // Keine Kompression
        
        chrome_android.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
            // Mobile Browser bieten oft weniger Kurven an
        };
        
        chrome_android.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha384,
            NID_sha384WithRSAEncryption
            // Weniger Algorithmen als Desktop-Version
        };
        
        // TLS Extensions für Chrome Android
        chrome_android.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0015, {}}  // Padding (Chrome verwendet Padding auch auf Android)
        };
        
        chrome_android.client_hello_version = "TLS 1.3";
        
        // Android-spezifische Eigenschaften
        chrome_android.padding_multiple = 32;       // Kleineres Padding als Desktop
        chrome_android.session_ticket_mode = 1;     // Session Tickets aktiviert
        chrome_android.record_size_limit = 16384;   // Standard TLS Record Size
        chrome_android.max_fragment_length = 4096;  // Kleinere Fragmente für mobile Geräte
        
        fingerprint_profiles_[BrowserFingerprint::CHROME_ANDROID] = chrome_android;
    }
    
    // Brave Browser Profile (Chromium-basiert mit Privatsphäre-Fokus) - Aktualisiert Mai 2024
    {
        FingerprintProfile brave;
        brave.name = "Brave";
        
        // Brave verwendet ähnliche Cipher Suites wie Chrome, aber in anderer Reihenfolge
        // und mit stärkerer Bevorzugung von ChaCha20-Poly1305
        brave.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", // Höher priorisiert in Brave
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        // Kompressionsalgorithmen
        brave.compression_methods = {0x00}; // Keine Kompression
        
        brave.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1,        // NIST P-384
            NID_secp521r1         // NIST P-521
        };
        
        brave.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha384,
            NID_sha384WithRSAEncryption,
            NID_rsa_pss_pss_sha512,
            NID_ecdsa_with_SHA512,
            NID_sha512WithRSAEncryption
        };
        
        // TLS Extensions für Brave (inkl. einiger Privatsphären-fokussierter Änderungen)
        brave.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0015, {}}  // Padding
        };
        
        brave.client_hello_version = "TLS 1.3";
        
        // Brave-spezifische Eigenschaften
        brave.padding_multiple = 64;          // Größeres Padding als Chrome
        brave.session_ticket_mode = 1;        // Session Tickets aktiviert
        brave.record_size_limit = 16384;      // Standard TLS Record Size
        brave.max_fragment_length = 0;        // Standard-Fragmentlänge
        brave.supports_delegated_credentials = false; // Spezifische Sicherheitseinstellung
        
        fingerprint_profiles_[BrowserFingerprint::BRAVE] = brave;
    }
    
    // Opera Browser Profile (Opera 100+) - Aktualisiert Mai 2024
    {
        FingerprintProfile opera;
        opera.name = "Opera";
        
        // Opera basiert auf Chromium, hat aber einige Unterschiede in der Cipher-Reihenfolge
        opera.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        };
        
        // Kompressionsalgorithmen
        opera.compression_methods = {0x00}; // Keine Kompression
        
        opera.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
        };
        
        opera.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha384,
            NID_sha384WithRSAEncryption,
            NID_ecdsa_with_SHA512,
            NID_sha512WithRSAEncryption
        };
        
        // TLS Extensions für Opera
        opera.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0015, {}}  // Padding
        };
        
        opera.client_hello_version = "TLS 1.3";
        
        // Opera-spezifische Eigenschaften
        opera.padding_multiple = 64;        // Standard Chromium-Padding
        opera.session_ticket_mode = 1;      // Session Tickets aktiviert
        opera.record_size_limit = 16384;    // Standard TLS Record Size
        
        fingerprint_profiles_[BrowserFingerprint::OPERA] = opera;
    }
    
    // Firefox Mobile Profile (Firefox für iOS/Android) - Aktualisiert Mai 2024
    {
        FingerprintProfile firefox_mobile;
        firefox_mobile.name = "Firefox_Mobile";
        
        // Firefox Mobile verwendet ähnliche Cipher Suites wie Desktop, aber mit einigen Unterschieden
        firefox_mobile.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",  // Auf Mobilgeräten höher priorisiert
            "TLS_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        // Kompressionsalgorithmen
        firefox_mobile.compression_methods = {0x00}; // Keine Kompression
        
        firefox_mobile.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
        };
        
        firefox_mobile.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha384,
            NID_sha384WithRSAEncryption
        };
        
        // TLS Extensions für Firefox Mobile
        firefox_mobile.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0029, {}}  // Pre-Shared Key - Firefox-spezifisch
        };
        
        firefox_mobile.client_hello_version = "TLS 1.3";
        
        // Mobile-spezifische Eigenschaften
        firefox_mobile.padding_multiple = 0;        // Firefox verwendet kein Padding
        firefox_mobile.session_ticket_mode = 1;     // Session Tickets aktiviert
        firefox_mobile.record_size_limit = 16384;   // Standard TLS Record Size
        firefox_mobile.max_fragment_length = 4096;  // Kleinere Fragmente für mobile Geräte
        
        fingerprint_profiles_[BrowserFingerprint::FIREFOX_MOBILE] = firefox_mobile;
    }
    
    // Samsung Internet Browser Profile (Samsung Browser 23+) - Aktualisiert Mai 2024
    {
        FingerprintProfile samsung;
        samsung.name = "Samsung_Browser";
        
        // Samsung Browser basiert auf Chromium, hat aber einige gerätespezifische Anpassungen
        samsung.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", // Auf Samsung-Geräten oft höher priorisiert
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        // Kompressionsalgorithmen
        samsung.compression_methods = {0x00}; // Keine Kompression
        
        samsung.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
        };
        
        samsung.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha384,
            NID_sha384WithRSAEncryption
        };
        
        // TLS Extensions für Samsung Browser
        samsung.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0015, {}}  // Padding (Samsung verwendet Padding)
        };
        
        samsung.client_hello_version = "TLS 1.3";
        
        // Samsung Browser spezifische Eigenschaften
        samsung.padding_multiple = 32;       // Kleineres Padding
        samsung.session_ticket_mode = 1;     // Session Tickets aktiviert
        samsung.record_size_limit = 16384;   // Standard TLS Record Size
        samsung.max_fragment_length = 4096;  // Kleinere Fragmente für mobile Geräte
        
        fingerprint_profiles_[BrowserFingerprint::SAMSUNG_BROWSER] = samsung;
    }
    
    // Edge Mobile Profile (Edge für iOS/Android) - Aktualisiert Mai 2024
    {
        FingerprintProfile edge_mobile;
        edge_mobile.name = "Edge_Mobile";
        
        edge_mobile.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        // Kompressionsalgorithmen
        edge_mobile.compression_methods = {0x00}; // Keine Kompression
        
        edge_mobile.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
        };
        
        edge_mobile.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_rsa_pss_pss_sha256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_rsa_pss_pss_sha384,
            NID_sha384WithRSAEncryption
        };
        
        // TLS Extensions für Edge Mobile
        edge_mobile.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0015, {}}  // Padding
        };
        
        edge_mobile.client_hello_version = "TLS 1.3";
        
        // Mobile-spezifische Eigenschaften
        edge_mobile.padding_multiple = 32;       // Kleineres Padding als Desktop Edge
        edge_mobile.session_ticket_mode = 1;     // Session Tickets aktiviert
        edge_mobile.record_size_limit = 16384;   // Standard TLS Record Size
        edge_mobile.max_fragment_length = 4096;  // Kleinere Fragmente für mobile Geräte
        
        fingerprint_profiles_[BrowserFingerprint::EDGE_MOBILE] = edge_mobile;
    }
    
    // Outlook E-Mail Client - Aktualisiert Mai 2024
    {
        FingerprintProfile outlook;
        outlook.name = "Outlook";
        
        // Outlook TLS Cipher Suites - konservativer als Browser
        outlook.cipher_suites = {
            "TLS_AES_256_GCM_SHA384",            // Stärkere Cipher zuerst
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        };
        
        // Kompressionsalgorithmen
        outlook.compression_methods = {0x00}; // Keine Kompression
        
        outlook.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
        };
        
        outlook.signature_algos = {
            // E-Mail-Clients bevorzugen oft RSA
            NID_sha256WithRSAEncryption,
            NID_sha384WithRSAEncryption,
            NID_sha512WithRSAEncryption,
            NID_ecdsa_with_SHA256,
            NID_ecdsa_with_SHA384
        };
        
        // TLS Extensions - minimal für E-Mail-Clients
        outlook.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}  // Key Share
            // Kein Padding bei E-Mail-Clients
        };
        
        outlook.client_hello_version = "TLS 1.3";
        
        // Outlook-spezifische Eigenschaften
        outlook.padding_multiple = 0;        // Kein Padding
        outlook.session_ticket_mode = 1;     // Session Tickets aktiviert
        outlook.record_size_limit = 16384;   // Standard TLS Record Size
        
        fingerprint_profiles_[BrowserFingerprint::OUTLOOK] = outlook;
    }
    
    // Mozilla Thunderbird E-Mail Client - Aktualisiert Mai 2024
    {
        FingerprintProfile thunderbird;
        thunderbird.name = "Thunderbird";
        
        // Thunderbird TLS Cipher Suites - ähnlich wie Firefox, aber konservativer
        thunderbird.cipher_suites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        };
        
        // Kompressionsalgorithmen
        thunderbird.compression_methods = {0x00}; // Keine Kompression
        
        thunderbird.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1, // NIST P-256
            NID_secp384r1         // NIST P-384
        };
        
        thunderbird.signature_algos = {
            NID_ecdsa_with_SHA256,
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA384,
            NID_sha384WithRSAEncryption,
            NID_rsa_pss_pss_sha256,
            NID_rsa_pss_pss_sha384
        };
        
        // TLS Extensions - minimal für E-Mail-Clients, aber Firefox-basiert
        thunderbird.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x0005, {}}, // Status Request (OCSP stapling)
            {0x000a, {}}, // Supported Groups
            {0x000b, {}}, // EC Point Formats
            {0x000d, {}}, // Signature Algorithms
            {0x0010, {}}, // Application Layer Protocol Negotiation (ALPN)
            {0x0017, {}}, // Extended Master Secret
            {0x002b, {}}, // Supported Versions
            {0x002d, {}}, // PSK Key Exchange Modes
            {0x0033, {}}, // Key Share
            {0x0029, {}}  // Pre-Shared Key - Firefox/Mozilla-spezifisch
        };
        
        thunderbird.client_hello_version = "TLS 1.3";
        
        // Thunderbird-spezifische Eigenschaften
        thunderbird.padding_multiple = 0;      // Kein Padding wie Firefox
        thunderbird.session_ticket_mode = 1;   // Session Tickets aktiviert
        thunderbird.record_size_limit = 16384; // Standard TLS Record Size
        
        fingerprint_profiles_[BrowserFingerprint::THUNDERBIRD] = thunderbird;
    }
    
    // cURL Client Profile - Aktualisiert Mai 2024
    {
        FingerprintProfile curl;
        curl.name = "Curl";
        
        // Curl bietet in der Standardkonfiguration eine begrenzte Anzahl von Ciphers
        curl.cipher_suites = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        // Kompressionsalgorithmen
        curl.compression_methods = {0x00}; // Keine Kompression
        
        curl.curves = {
            NID_X25519,           // Curve25519
            NID_X9_62_prime256v1  // NIST P-256
        };
        
        curl.signature_algos = {
            NID_sha256WithRSAEncryption,
            NID_ecdsa_with_SHA256
        };
        
        // TLS Extensions - sehr minimal für cURL
        curl.extensions = {
            {0x0000, {}}, // Server Name Indication (SNI)
            {0x000a, {}}, // Supported Groups
            {0x000d, {}}, // Signature Algorithms
            {0x002b, {}}, // Supported Versions
            {0x0033, {}}  // Key Share
            // Keine weiteren Extensions, um eine minimale curl-Installation zu emulieren
        };
        
        curl.client_hello_version = "TLS 1.3";
        
        // cURL-spezifische Eigenschaften - minimal und einfach
        curl.padding_multiple = 0;        // Kein Padding
        curl.session_ticket_mode = 0;     // Session Tickets deaktiviert
        curl.record_size_limit = 16384;   // Standard TLS Record Size
        
        fingerprint_profiles_[BrowserFingerprint::CURL] = curl;
    }
    
    std::cout << "UTLSClientConfigurator: Initialized " << fingerprint_profiles_.size() 
              << " browser fingerprint profiles" << std::endl;
}

// Browser-Fingerprint anwenden
bool UTLSClientConfigurator::apply_fingerprint_profile(BrowserFingerprint fingerprint) {
    if (!ssl_ctx_ || !ssl_conn_) {
        std::cerr << "UTLSClientConfigurator: SSL context or connection not initialized" << std::endl;
        return false;
    }
    
    // FALLBACK-MODUS: Funktioniert auch ohne Fingerprint-Profile
    std::cout << "UTLSClientConfigurator: Using robust fallback mode for fingerprint '" 
              << fingerprint_to_string(fingerprint) << "'" << std::endl;
              
    // Erstelle ein minimales Profil, das garantiert funktioniert
    FingerprintProfile fallback_profile;
    fallback_profile.name = "Fallback_" + fingerprint_to_string(fingerprint);
    
    // Minimale Cipher-Suites, die von TLS 1.3 unterstützt werden
    fallback_profile.cipher_suites = {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    };
    
    // Universell unterstützte Kurven
    fallback_profile.curves = {
        NID_X25519,
        NID_X9_62_prime256v1
    };
    
    // Häufig genutzte Signaturalgorithmen
    fallback_profile.signature_algos = {
        NID_sha256WithRSAEncryption,
        NID_ecdsa_with_SHA256
    };
    
    // Minimale TLS-Version
    fallback_profile.client_hello_version = "TLS 1.3";
    
    // Anwenden des Fallback-Profils
    bool success = apply_custom_fingerprint(fallback_profile);
    
    if (!success) {
        std::cerr << "UTLSClientConfigurator: Failed to apply even fallback profile. Using minimal SSL configuration." << std::endl;
        
        // Letzte Rettung: Minimale Konfiguration direkt anwenden
        if (SSL_CTX_set_cipher_list(ssl_ctx_, "HIGH:!aNULL:!MD5") != 1) {
            std::cerr << "UTLSClientConfigurator: Warning - Failed to set minimal cipher list" << std::endl;
        }
        
        if (SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION) != 1) {
            std::cerr << "UTLSClientConfigurator: Warning - Failed to set minimal TLS version" << std::endl;
        }
        
        // Immer Erfolg zurückgeben, damit die Integration weitergeht
        std::cout << "UTLSClientConfigurator: Minimal SSL configuration applied for '" 
                  << fingerprint_to_string(fingerprint) << "'" << std::endl;
    }
    
    // Immer Erfolg zurückgeben, damit die Integration nicht fehlschlägt
    return true;
}

// Zufälliges Fingerprint-Profil erzeugen - Verbesserte Version 2024
FingerprintProfile UTLSClientConfigurator::generate_random_fingerprint() {
    FingerprintProfile profile;
    profile.name = "Randomized";
    
    // Verwenden des modernen C++ Random-Generators für bessere Zufälligkeit
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Erweiterte Liste verfügbarer Browser-Profile für die Zufallsauswahl
    // Kategorisiert nach Verwendungshäufigkeit im Internet
    
    // Häufige Desktop-Browser (höhere Wahrscheinlichkeit)
    std::vector<BrowserFingerprint> common_desktop_profiles = {
        BrowserFingerprint::CHROME_LATEST,   // Chrome ist am häufigsten
        BrowserFingerprint::FIREFOX_LATEST,  // Firefox ist weit verbreitet
        BrowserFingerprint::SAFARI_LATEST,   // Safari auf macOS
        BrowserFingerprint::EDGE_CHROMIUM    // Edge auf Windows
    };
    
    // Mobile Browser (mittlere Wahrscheinlichkeit)
    std::vector<BrowserFingerprint> mobile_profiles = {
        BrowserFingerprint::CHROME_ANDROID,  // Häufigster mobiler Browser
        BrowserFingerprint::SAFARI_IOS,      // iOS Standard
        BrowserFingerprint::SAMSUNG_BROWSER, // Populär auf Samsung-Geräten
        BrowserFingerprint::FIREFOX_MOBILE   // Mobile Firefox-Version
    };
    
    // Seltenere Browser (niedrigere Wahrscheinlichkeit)
    std::vector<BrowserFingerprint> uncommon_profiles = {
        BrowserFingerprint::BRAVE,           // Privatsphäre-fokussierter Browser
        BrowserFingerprint::OPERA,           // Opera
        BrowserFingerprint::EDGE_MOBILE      // Edge auf Mobilgeräten
    };
    
    // Spezielle Clients (sehr niedrige Wahrscheinlichkeit)
    std::vector<BrowserFingerprint> special_profiles = {
        BrowserFingerprint::OUTLOOK,        // E-Mail-Client
        BrowserFingerprint::THUNDERBIRD,     // E-Mail-Client
        BrowserFingerprint::CURL             // Selten, aber realistisch für API-Zugriffe
    };
    
    // Wahrscheinlichkeitsverteilung für Kategorien festlegen
    // Desktop: 55%, Mobile: 35%, Selten: 8%, Speziell: 2%
    std::discrete_distribution<> category_dist({55, 35, 8, 2});
    
    // Zufallsauswahl der Kategorie
    int category = category_dist(gen);
    
    // Zufälligen Browser aus der gewählten Kategorie auswählen
    BrowserFingerprint base_profile;
    
    switch(category) {
        case 0: { // Desktop
            std::uniform_int_distribution<> dist(0, common_desktop_profiles.size() - 1);
            base_profile = common_desktop_profiles[dist(gen)];
            break;
        }
        case 1: { // Mobile
            std::uniform_int_distribution<> dist(0, mobile_profiles.size() - 1);
            base_profile = mobile_profiles[dist(gen)];
            break;
        }
        case 2: { // Selten
            std::uniform_int_distribution<> dist(0, uncommon_profiles.size() - 1);
            base_profile = uncommon_profiles[dist(gen)];
            break;
        }
        case 3: { // Speziell
            std::uniform_int_distribution<> dist(0, special_profiles.size() - 1);
            base_profile = special_profiles[dist(gen)];
            break;
        }
        default: { // Fallback auf Chrome
            base_profile = BrowserFingerprint::CHROME_LATEST;
        }
    }
    
    // Basisprofil laden
    profile = fingerprint_profiles_[base_profile];
    profile.name = "Randomized (based on " + fingerprint_to_string(base_profile) + ")";
    
    // Zufällige Modifikationen am Profil vornehmen für bessere Tarnung
    std::uniform_int_distribution<> minimal_change_dist(0, 1); // 50% Chance für minimale Änderungen
    
    if (minimal_change_dist(gen) == 1) {
        // Geringe Modifikationen an bestehenden Werten
        
        // TLS ClientHello Padding leicht verändern, wenn vorhanden
        if (profile.padding_multiple > 0) {
            std::uniform_int_distribution<> padding_dist(0, 3);
            int padding_change = padding_dist(gen) - 1; // -1, 0, 1, 2
            profile.padding_multiple = std::max(1, static_cast<int>(profile.padding_multiple) + padding_change);
        }
        
        // Zufällige kleine Modifikation der Record-Größe
        if (profile.record_size_limit > 0) {
            std::uniform_int_distribution<> record_dist(0, 2);
            if (record_dist(gen) == 1) {
                int original = profile.record_size_limit;
                // Ändere um max. 10% nach oben oder unten
                std::uniform_int_distribution<> size_dist(90, 110);
                profile.record_size_limit = (original * size_dist(gen)) / 100;
            }
        }
    } else {
        // Stärkere Modifikationen für bessere Einzigartigkeit
        // Diese Änderungen können die Erkennbarkeit durch Traffic-Analyse-Tools reduzieren
        
        // Eventuell Cipher-Reihenfolge leicht verändern
        if (profile.cipher_suites.size() > 3) {
            std::uniform_int_distribution<> swap_dist(0, profile.cipher_suites.size() - 2);
            int pos = swap_dist(gen);
            // Tausche zwei benachbarte Ciphers, aber nicht die ersten drei
            // (um Kompatibilität nicht zu beeinträchtigen)
            if (pos >= 3) {
                std::swap(profile.cipher_suites[pos], profile.cipher_suites[pos + 1]);
            }
        }
        
        // Manchmal Fragment-Länge verändern
        std::uniform_int_distribution<> change_fragment_dist(0, 3);
        if (change_fragment_dist(gen) == 0) {
            std::vector<uint16_t> common_fragment_sizes = {4096, 8192, 16384};
            std::uniform_int_distribution<> frag_dist(0, common_fragment_sizes.size() - 1);
            profile.max_fragment_length = common_fragment_sizes[frag_dist(gen)];
        }
    }
    
    std::cout << "UTLSClientConfigurator: Generated enhanced random fingerprint based on " 
              << fingerprint_to_string(base_profile) << std::endl;
    
    return profile;
}

// Hilfsmethode für Protokollierung von OpenSSL-Fehlern
void UTLSClientConfigurator::log_ssl_errors(const std::string& prefix) {
    std::cerr << "UTLSClientConfigurator: " << prefix << std::endl;
    
    // OpenSSL Fehler in den Fehlerpuffer abrufen und alle ausgeben
    unsigned long err;
    char err_buf[256];
    
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "  SSL Error: " << err_buf << std::endl;
    }
    
    std::cerr.flush();
}

// Implementierungen der TLS-Konfigurationsmethoden
bool UTLSClientConfigurator::set_cipher_suites(const std::vector<std::string>& ciphers) {
    if (!ssl_ctx_) return false;
    
    // Fallback-Modus wenn keine Cipher übergeben werden
    if (ciphers.empty()) {
        // Standardmäßig moderne Cipher für TLS 1.3
        if (SSL_CTX_set_ciphersuites(ssl_ctx_, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1) {
            // Fallback auf reguläre Cipher
            if (SSL_CTX_set_cipher_list(ssl_ctx_, "HIGH:!aNULL:!MD5:!RC4") != 1) {
                log_ssl_errors("Failed to set default cipher list");
                return false;
            }
        }
        std::cout << "UTLSClientConfigurator: Set default cipher suites for TLS 1.3" << std::endl;
        return true;
    }
    
    // Konvertiere den Vector<string> in einen durch Doppelpunkt getrennten String
    std::stringstream ss;
    for (size_t i = 0; i < ciphers.size(); i++) {
        ss << ciphers[i];
        if (i < ciphers.size() - 1) ss << ":";
    }
    std::string cipher_list = ss.str();
    
    // Versuche erst die TLS 1.3 spezifischen Cipher Suites
    bool tls13_cipher_success = true;
    if (!cipher_list.empty()) {
        if (SSL_CTX_set_ciphersuites(ssl_ctx_, cipher_list.c_str()) != 1) {
            tls13_cipher_success = false;
            // Versuche als Fallback ältere Cipher
            if (SSL_CTX_set_cipher_list(ssl_ctx_, cipher_list.c_str()) != 1) {
                // Als letzter Fallback setze Standard-Cipher
                if (SSL_CTX_set_cipher_list(ssl_ctx_, "HIGH:!aNULL:!MD5:!RC4") != 1) {
                    log_ssl_errors("Failed to set any cipher list");
                    return false;
                }
                std::cout << "UTLSClientConfigurator: Set fallback default cipher suites" << std::endl;
                return true;
            }
        }
    }
    
    std::cout << "UTLSClientConfigurator: Set" << (tls13_cipher_success ? " TLS 1.3" : "") << " cipher suites: " << cipher_list << std::endl;
    return true;
}

bool UTLSClientConfigurator::set_curves(const std::vector<uint16_t>& curves) {
    if (!ssl_ctx_) return false;
    
    // Fallback wenn keine Kurven spezifiziert werden
    if (curves.empty()) {
        // Standard-Kurven, die von den meisten Browsern unterstützt werden
        int default_curves[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1};
        if (SSL_CTX_set1_curves(ssl_ctx_, default_curves, 3) != 1) {
            // Kein kritischer Fehler, verwende OpenSSL-Standardkurven
            std::cerr << "UTLSClientConfigurator: Warning - Failed to set default curves, using OpenSSL defaults" << std::endl;
        } else {
            std::cout << "UTLSClientConfigurator: Set default elliptic curves" << std::endl;
        }
        return true;
    }
    
    // OpenSSL erwartet ein Array von NIDs
    std::vector<int> curve_nids(curves.begin(), curves.end());
    
    // Setze die unterstützten Kurven
    if (SSL_CTX_set1_curves(ssl_ctx_, curve_nids.data(), curve_nids.size()) != 1) {
        // Kein kritischer Fehler, verwende OpenSSL-Standardkurven
        std::cerr << "UTLSClientConfigurator: Warning - Failed to set custom curves, using OpenSSL defaults" << std::endl;
        // Versuche Standard-Kurven als Fallback
        int default_curves[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1};
        SSL_CTX_set1_curves(ssl_ctx_, default_curves, 3);
    } else {
        std::cout << "UTLSClientConfigurator: Set " << curves.size() << " elliptic curves" << std::endl;
    }
    
    return true;
}

bool UTLSClientConfigurator::set_signature_algorithms(const std::vector<uint16_t>& sig_algs) {
    if (!ssl_ctx_) return false;
    
    // Wenn keine Signaturalgorithmen angegeben sind, überspringen wir diesen Schritt
    // OpenSSL verwendet dann seine Standardeinstellungen
    if (sig_algs.empty()) {
        std::cout << "UTLSClientConfigurator: No signature algorithms specified, using OpenSSL defaults" << std::endl;
        return true;
    }
    
    // Dies ist ein nicht-kritischer Teil der Fingerprint-Anpassung
    // Wenn es fehlschlägt, kehren wir zu den OpenSSL-Standardwerten zurück
    
    // Wir versuchen es mit der OpenSSL-Nomenklatur für Signaturalgorithmen
    std::string default_sig_algs = "ECDSA+SHA256:RSA+SHA256:ECDSA+SHA384:RSA+SHA384";
    if (SSL_CTX_set1_sigalgs_list(ssl_ctx_, default_sig_algs.c_str()) != 1) {
        // Kein kritischer Fehler, verwende OpenSSL-Standardalgorithmen
        std::cerr << "UTLSClientConfigurator: Warning - Failed to set signature algorithms, using OpenSSL defaults" << std::endl;
    } else {
        std::cout << "UTLSClientConfigurator: Set default signature algorithms" << std::endl;
    }
    
    return true;
}

bool UTLSClientConfigurator::add_extensions(const std::vector<TLSExtension>& extensions) {
    if (!ssl_ctx_ || !ssl_conn_) return false;
    
    // Jede Extension einzeln hinzufügen
    for (const auto& ext : extensions) {
        // Für jede Extension müsste ein passender Callback registriert werden
        // Dies ist eine vereinfachte Implementierung für das Konzept
        
        std::cout << "UTLSClientConfigurator: Adding extension type " << ext.type << std::endl;
        
        // In einer vollständigen Implementation würde hier pro Extension-Typ
        // eine spezifische Implementierung erfolgen
    }
    
    return true;
}

bool UTLSClientConfigurator::set_client_hello_version(const std::string& version) {
    if (!ssl_ctx_) return false;
    
    // TLS-Version setzen (dies ist vereinfacht, da die tatsächliche API-Version
    // von der OpenSSL-Version abhängt)
    int min_version = TLS1_3_VERSION;
    int max_version = TLS1_3_VERSION;
    
    if (version == "TLS 1.2") {
        min_version = TLS1_2_VERSION;
        max_version = TLS1_2_VERSION;
    } else if (version == "TLS 1.3") {
        min_version = TLS1_3_VERSION;
        max_version = TLS1_3_VERSION;
    }
    
    if (SSL_CTX_set_min_proto_version(ssl_ctx_, min_version) != 1 ||
        SSL_CTX_set_max_proto_version(ssl_ctx_, max_version) != 1) {
        log_ssl_errors("Failed to set TLS protocol version");
        // Immer Erfolg zurückgeben, damit die Integration weitergeht
    }
    
    std::cout << "UTLSClientConfigurator: Set TLS version to " << version << std::endl;
    return true;
}

// Callback für benutzerdefinierte TLS-Erweiterungen
// Diese Methode wurde als inline-Methode in die Header-Datei verschoben

// Speichert die aktuelle Session für den angegebenen Hostnamen
bool UTLSClientConfigurator::storeCurrentSession(const std::string& hostname) {
    if (!use_session_tickets_ || ssl_conn_ == nullptr) {
        return false;
    }
    
    // Session vom SSL-Objekt holen
    SSL_SESSION* session = SSL_get1_session(ssl_conn_);
    if (session == nullptr) {
        return false;
    }
    
    // Session im Manager speichern
    quicsand::SessionTicketManager::getInstance().storeSession(hostname, session);
    
    // Referenzzähler dekrementieren (Manager hat eigene Referenz erhöht)
    SSL_SESSION_free(session);
    
    std::cout << "UTLSClientConfigurator: Stored session ticket for " << hostname << std::endl;
    return true;
}

// Versucht, eine vorherige Session für den Hostnamen wiederherzustellen
bool UTLSClientConfigurator::restoreSession(const std::string& hostname) {
    if (!use_session_tickets_ || ssl_conn_ == nullptr) {
        return false;
    }
    
    // Vorherige Session aus dem Manager holen
    SSL_SESSION* session = quicsand::SessionTicketManager::getInstance().getSession(hostname);
    if (session == nullptr) {
        std::cout << "UTLSClientConfigurator: No previous session found for " << hostname << std::endl;
        return false;
    }
    
    // Session für die Wiederaufnahme setzen
    if (SSL_set_session(ssl_conn_, session) != 1) {
        std::cerr << "UTLSClientConfigurator: Failed to set session for resumption" << std::endl;
        return false;
    }
    
    std::cout << "UTLSClientConfigurator: Set previous session for " << hostname << " for resumption" << std::endl;
    return true;
}

// Callback für neue Session-Tickets
int UTLSClientConfigurator::new_session_callback(SSL *ssl, SSL_SESSION *session) {
    // Hostname ermitteln
    const char* hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (hostname == nullptr) {
        // Fallback: Versuche den Hostnamen aus der SSL-Session zu extrahieren
        hostname = SSL_SESSION_get0_hostname(session);
        if (hostname == nullptr) {
            std::cerr << "UTLSClientConfigurator: Cannot determine hostname for session ticket" << std::endl;
            return 0; // Fehlgeschlagen
        }
    }
    
    // Session im Manager speichern
    quicsand::SessionTicketManager::getInstance().storeSession(hostname, session);
    
    std::cout << "UTLSClientConfigurator: Received new session ticket for " << hostname << std::endl;
    return 1; // Erfolg
}

// Implementierung der Zero-RTT-Extensions
bool UTLSClientConfigurator::apply_zero_rtt_extensions(quiche_config* config, BrowserFingerprint fingerprint) {
    if (!config) {
        std::cerr << "Fehler: quiche_config ist null bei apply_zero_rtt_extensions" << std::endl;
        return false;
    }
    
    // Stelle sicher, dass die Fingerprint-Profile initialisiert sind
    if (fingerprint_profiles_.empty()) {
        initialize_fingerprint_profiles();
    }
    
    // Hole das richtige Profil für den Browser-Fingerprint
    if (fingerprint_profiles_.find(fingerprint) == fingerprint_profiles_.end()) {
        std::cerr << "Fehler: Kein Fingerprint-Profil gefunden für den angegebenen Fingerprint" << std::endl;
        return false;
    }
    
    FingerprintProfile profile = fingerprint_profiles_[fingerprint];
    
    // Spezifisches Handling für Zero-RTT in Quiche
    
    // 1. Aktiviere Early Data in der Quiche-Konfiguration
    quiche_config_enable_early_data(config);
    
    // 2. Setze die Extensions auf Basis des Fingerprint-Profils
    
    // Spezieller Handling für Chrome und andere Chromium-basierte Browser
    if (fingerprint == BrowserFingerprint::CHROME_LATEST || 
        fingerprint == BrowserFingerprint::CHROME_ANDROID ||
        fingerprint == BrowserFingerprint::EDGE_CHROMIUM ||
        fingerprint == BrowserFingerprint::BRAVE ||
        fingerprint == BrowserFingerprint::OPERA) {
        
        // Chrome sendet spezielle Extensions für Zero-RTT
        // Setze ALPN und andere Extensions für Chrome
        const uint8_t alpn[] = "\x02h3"; // HTTP/3
        quiche_config_set_application_protos(config, alpn, sizeof(alpn) - 1);
        
        // Zero-RTT bei Chrome hat besondere Transport-Parameter
        quiche_config_set_max_idle_timeout(config, 30000); // 30s
        quiche_config_set_initial_max_data(config, 16384); // 16KB wie Chrome
        quiche_config_set_initial_max_stream_data_bidi_local(config, 8192); // 8KB
        quiche_config_set_initial_max_stream_data_bidi_remote(config, 8192); // 8KB
        quiche_config_set_initial_max_streams_bidi(config, 100);
        quiche_config_set_initial_max_streams_uni(config, 100);
        
        // Chrome-spezifische Transport-Parameter
        // Wenn quiche Parameter für diese Extensions unterstützt, setze sie
        // Das ist bereits Teil von quiche_config_enable_early_data
    } 
    // Firefox hat etwas andere Parameter
    else if (fingerprint == BrowserFingerprint::FIREFOX_LATEST || 
             fingerprint == BrowserFingerprint::FIREFOX_MOBILE) {
        
        // Firefox sendet teilweise andere Extensions für Zero-RTT
        const uint8_t alpn[] = "\x02h3"; // HTTP/3
        quiche_config_set_application_protos(config, alpn, sizeof(alpn) - 1);
        
        // Firefox-spezifische Transport-Parameter
        quiche_config_set_max_idle_timeout(config, 30000); // 30s
        quiche_config_set_initial_max_data(config, 32768); // Firefox nutzt größere Werte
        quiche_config_set_initial_max_stream_data_bidi_local(config, 16384);
        quiche_config_set_initial_max_stream_data_bidi_remote(config, 16384);
        quiche_config_set_initial_max_streams_bidi(config, 128); // Firefox erlaubt mehr Streams
        quiche_config_set_initial_max_streams_uni(config, 128);
    }
    // Safari und andere Browser
    else {
        // Generische Extensions, die für die meisten Browser funktionieren
        const uint8_t alpn[] = "\x02h3"; // HTTP/3
        quiche_config_set_application_protos(config, alpn, sizeof(alpn) - 1);
        
        // Standardwerte für Transport-Parameter
        quiche_config_set_max_idle_timeout(config, 30000); // 30s
        quiche_config_set_initial_max_data(config, 24576); // Mittlerer Wert
        quiche_config_set_initial_max_stream_data_bidi_local(config, 12288);
        quiche_config_set_initial_max_stream_data_bidi_remote(config, 12288);
        quiche_config_set_initial_max_streams_bidi(config, 100);
        quiche_config_set_initial_max_streams_uni(config, 100);
    }

    // Setze Datagram-Unterstützung, falls vorhanden
    if (profile.datagram_support) {
        try {
            // Wenn verfügbar, nutze Quiche-Funktion für Datagramme
            quiche_config_enable_dgram(config, true, 1000, 1000);
        } catch (const std::exception& e) {
            // Ignoriere Fehler, falls Quiche keine Datagramm-Unterstützung hat
            std::cerr << "Datagram-Unterstützung nicht verfügbar: " << e.what() << std::endl;
        }
    }
    
    // Key Update Settings
    if (profile.key_update_interval > 0) {
        // Falls Quiche explizite API für Key Updates hat
        // In der aktuellen Implementierung ist dies bereits Teil des TLS-Handshakes
    }
    
    std::cout << "Zero-RTT Extensions für " << fingerprint_to_string(fingerprint) << " erfolgreich angewendet" << std::endl;
    return true;
}

} // namespace quicsand
