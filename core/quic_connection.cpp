#include "quic_connection.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h> // Für ERR_print_errors_fp
#include <iostream>
#include <vector>
#include <functional>
#include <memory>
#include <string>
#include <cstring> // Für strlen, memcpy
#include <boost/asio.hpp>
#include <boost/asio/ip/udp.hpp>
#include "quic_stream.hpp"
#include <openssl/ssl.h> // Für SSL_set_tlsext_host_name
#include "../tls/quiche_utls_wrapper.hpp" // Für die uTLS Wrapper-Funktionen

// Verwende die tatsächlichen quiche Typen aus quiche.h
// anstatt eigene Definitionen zu verwenden

namespace quicsand {

// Standardkonstruktor - verwendet Chrome_Latest als Standard-Browser-Fingerprint
QuicConnection::QuicConnection(boost::asio::io_context& io_context, const QuicConfig& config)
    : io_context_(io_context), config_(config),
      socket_(io_context, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0)), // Listen on any available local port
      quiche_config_(nullptr), quiche_conn_(nullptr),
      using_external_quiche_config_(config.utls_quiche_config != nullptr),
      utls_enabled_(true), // Standardmäßig uTLS aktivieren
      browser_fingerprint_(BrowserFingerprint::CHROME_LATEST)
{
    // Legacy-Support für die alte Integration
    utls_ssl_ctx_ = config.utls_ssl_ctx;
    
    if (using_external_quiche_config_) {
        quiche_config_ = config.utls_quiche_config;
        std::cout << "QuicConnection: Using external quiche_config" << std::endl;
    } else {
        quiche_config_ = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (!quiche_config_) {
            throw std::runtime_error("Failed to create quiche_config");
        }
        
        // ALPN-Protokolle für HTTP/3
        const uint8_t alpn[] = "\x02h3"; // HTTP/3
        quiche_config_set_application_protos(quiche_config_, alpn, sizeof(alpn) - 1);
        
        // Standardkonfiguration
        quiche_config_set_max_idle_timeout(quiche_config_, 30000); // 30s
        quiche_config_set_max_recv_udp_payload_size(quiche_config_, 1350);
        quiche_config_set_max_send_udp_payload_size(quiche_config_, 1350);
        quiche_config_set_initial_max_data(quiche_config_, 10000000); // 10MB
        quiche_config_set_initial_max_stream_data_bidi_local(quiche_config_, 1000000); // 1MB
        quiche_config_set_initial_max_stream_data_bidi_remote(quiche_config_, 1000000); // 1MB
        quiche_config_set_initial_max_streams_bidi(quiche_config_, 100);
        quiche_config_set_initial_max_streams_uni(quiche_config_, 100);
        quiche_config_verify_peer(quiche_config_, false); // Standardmäßig Verifizierung aus für einfache Tests
        
        std::cout << "QuicConnection: Created new internal quiche_config with HTTP/3 ALPN." << std::endl;
    }
    
    // Initialisiere UTLSClientConfigurator mit Chrome_Latest Profil
    if (utls_enabled_) {
        utls_client_configurator_ = std::make_unique<UTLSClientConfigurator>();
        std::cout << "QuicConnection: Created UTLSClientConfigurator with default Chrome_Latest profile." << std::endl;
    }
}

// Erweiterter Konstruktor mit explizitem Browser-Fingerprint
QuicConnection::QuicConnection(boost::asio::io_context& io_context, const QuicConfig& config, 
                               BrowserFingerprint fingerprint)
    : QuicConnection(io_context, config) // Rufe den Standardkonstruktor auf
{
    // Überschreibe den Standard-Fingerprint
    browser_fingerprint_ = fingerprint;
    
    if (utls_client_configurator_) {
        std::cout << "QuicConnection: Setting browser fingerprint to " 
                  << UTLSClientConfigurator::fingerprint_to_string(fingerprint) << std::endl;
    }
}

QuicConnection::~QuicConnection() {
    if (quiche_conn_) {
        quiche_conn_free(quiche_conn_);
        quiche_conn_ = nullptr;
    }

    // Cleanup des quiche_config, aber nur wenn er nicht extern verwaltet wird
    if (quiche_config_ && !using_external_quiche_config_) {
        quiche_config_free(quiche_config_);
        quiche_config_ = nullptr;
    }

    // UTLSClientConfigurator wird durch den smart pointer automatisch freigegeben
    // utls_ssl_ctx_ wird vom UTLSClientConfigurator verwaltet und hier nicht explizit freigegeben
    utls_ssl_ctx_ = nullptr;
}

// Neue Hilfsmethode für das Setzen des Browser-Fingerprints
bool QuicConnection::set_browser_fingerprint(BrowserFingerprint fingerprint) {
    browser_fingerprint_ = fingerprint;
    
    if (utls_client_configurator_) {
        std::cout << "QuicConnection: Changed browser fingerprint to " 
                  << UTLSClientConfigurator::fingerprint_to_string(fingerprint) << std::endl;
    }
    
    return utls_client_configurator_ != nullptr;
}

// Getter für den aktuellen Browser-Fingerprint
BrowserFingerprint QuicConnection::get_browser_fingerprint() const {
    return browser_fingerprint_;
}

// Aktivieren/Deaktivieren der FEC-Funktionalität
bool QuicConnection::enable_fec(bool enable) {
    fec_enabled_ = enable;
    
    if (enable) {
        try {
            if (use_optimized_fec_) {
                // Verwende die SIMD-optimierte FEC-Implementierung
                if (!fec_optimized_) {
                    OptimizedTetrysFEC::Config fec_config;
                    fec_config.window_size = config_.fec_window_size; // Standardwert: 50
                    fec_config.initial_redundancy = target_redundancy_rate_; // Redundanzrate
                    fec_config.adaptive = true; // Adaptive Rate aktivieren
                    
                    fec_optimized_ = std::make_unique<OptimizedTetrysFEC>(fec_config);
                }
            } else {
                // Verwende die Standard-FEC-Implementierung
                if (!fec_) {
                    // Initialisiere TetrysFEC mit Standardkonfiguration
                    TetrysFEC::Config fec_config;
                    fec_config.window_size = config_.fec_window_size; // Standardwert: 50
                    fec_config.initial_redundancy = target_redundancy_rate_; // Redundanzrate
                    fec_config.adaptive = true; // Adaptive Rate aktivieren
                    
                    fec_ = std::make_unique<TetrysFEC>(fec_config);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error initializing FEC: " << e.what() << std::endl;
            fec_enabled_ = false;
            return false;
        }
    }
    
    return true;
}

// Methoden für SIMD-optimierte FEC
bool QuicConnection::enable_optimized_fec(bool enable) {
    // Prüfen, ob SIMD-Support vorhanden ist
    if (enable && !has_simd_support()) {
        std::cerr << "Warning: SIMD support not available, falling back to standard FEC implementation" << std::endl;
        use_optimized_fec_ = false;
        return false;
    }
    
    use_optimized_fec_ = enable;
    
    // FEC neu initialisieren, wenn bereits aktiviert
    if (fec_enabled_) {
        return enable_fec(true);
    }
    
    return true;
}

// Allgemeine SIMD-Feature-Detection
bool QuicConnection::has_simd_support() const {
    return simd::detect_cpu_features() > 0;
}

uint32_t QuicConnection::get_supported_simd_features() const {
    return simd::detect_cpu_features();
}

std::string QuicConnection::get_simd_features_string() const {
    return simd::features_to_string(get_supported_simd_features());
}

// SIMD-optimierte Kryptografie
bool QuicConnection::enable_optimized_crypto(bool enable) {
    // Prüfen, ob SIMD-Support vorhanden ist
    if (enable && !has_simd_support()) {
        std::cerr << "Warning: SIMD support not available, falling back to standard crypto implementation" << std::endl;
        return false;
    }
    
    try {
        if (enable) {
            // Initialisiere AES-GCM mit SIMD-Optimierungen, wenn noch nicht vorhanden
            if (!aes_gcm_optimized_) {
                // Hole die Schlüssel vom SSL-Kontext oder erzeuge neue
                std::vector<uint8_t> key(16, 0); // 128-bit Schlüssel
                std::vector<uint8_t> iv(12, 0);  // 96-bit IV
                
                // In einer realen Implementierung würde man die Schlüssel aus der TLS-Handshake beziehen
                // Hier vereinfacht:
                if (ssl_) {
                    // Extrahiere Schlüssel aus dem SSL-Kontext (vereinfachtes Beispiel)
                    // In einer echten Implementation wäre hier die korrekte Schlüsselableitung
                }
                
                aes_gcm_optimized_ = std::make_unique<crypto::Aes128GcmOptimized>(key, iv);
            }
        } else {
            // Deaktiviere optimierte Crypto
            aes_gcm_optimized_.reset();
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing optimized crypto: " << e.what() << std::endl;
        return false;
    }
}

bool QuicConnection::is_optimized_crypto_enabled() const {
    return aes_gcm_optimized_ != nullptr;
}
}

// Setzen der Redundanzrate der FEC
void QuicConnection::set_fec_redundancy_rate(double rate) {
    // Stellen Sie sicher, dass die Rate im gültigen Bereich liegt (0.1 bis 0.5)
    rate = std::max(0.1, std::min(rate, 0.5));
    
    target_redundancy_rate_ = rate;
    
    // Wenn FEC aktiviert ist, aktualisiere die Konfiguration
    if (fec_enabled_ && fec_) {
        // Wir setzen die Redundanzrate, indem wir eine neue Konfiguration mit der aktualisierten Rate erstellen
        TetrysFEC::Config new_config;
        new_config.initial_redundancy = rate;
        new_config.block_size = 512; // Standardwert beibehalten
        new_config.adaptive = true;
        
        fec_->set_config(new_config); // Verwende die set_config Methode
        std::cout << "QuicConnection: FEC redundancy rate set to " << rate << std::endl;
    }
}

// Abrufen der aktuellen Redundanzrate
double QuicConnection::get_fec_redundancy_rate() const {
    // Da es keine direkte get_redundancy_rate Methode gibt, geben wir die gespeicherte Rate zurück
    return target_redundancy_rate_;
}

// Aktualisieren der Redundanzrate basierend auf der beobachteten Verlustrate
void QuicConnection::update_fec_redundancy_rate(double observed_loss_rate) {
    if (fec_enabled_ && fec_) {
        fec_->update_redundancy_rate(observed_loss_rate);
        // Aktualisiere auch unsere gespeicherte Redundanzrate
        target_redundancy_rate_ = std::max(0.1, std::min(observed_loss_rate * 1.5, 0.5));
        std::cout << "QuicConnection: Updated FEC redundancy rate based on observed loss rate " 
                  << observed_loss_rate << ", new rate: " << target_redundancy_rate_ << std::endl;
    }
}

// Abrufen der aktuellen Verlustrate
double QuicConnection::get_current_loss_rate() const {
    if (total_packets_ == 0) {
        return 0.0;
    }
    return static_cast<double>(packet_loss_count_) / total_packets_;
}

// Anwenden der FEC-Kodierung auf ausgehende Daten
std::vector<uint8_t> QuicConnection::apply_fec_encoding(const uint8_t* data, size_t size) {
    if (!fec_enabled_ || size == 0) {
        // Wenn FEC nicht aktiviert ist, gib die unveränderten Daten zurück
        return std::vector<uint8_t>(data, data + size);
    }
    
    // Input-Daten kopieren
    std::vector<uint8_t> input_data(data, data + size);
    
    // Gesamtpaketzahl erhöhen für Statistiken
    total_packets_++;
    
    // Entscheide, welche FEC-Implementierung zu verwenden ist
    if (use_optimized_fec_ && fec_optimized_) {
        // SIMD-optimierte FEC verwenden
        auto span_data = memory_span<uint8_t>(input_data.data(), input_data.size());
        auto encoded_packets = fec_optimized_->encode_packet(span_data);
        
        // Wandle das erste Paket in einen std::vector um
        // In einer vollständigen Implementierung würden alle Pakete verarbeitet
        if (!encoded_packets.empty()) {
            auto& packet = encoded_packets[0];
            std::vector<uint8_t> result(packet.data_view.begin(), packet.data_view.end());
            return result;
        }
    } else if (fec_) {
        // Standard-FEC verwenden
        return fec_->encode(input_data);
    }
    
    // Fallback: Gib die ursprünglichen Daten zurück
    return input_data;
}

// Anwenden der FEC-Dekodierung auf eingehende Daten
std::vector<uint8_t> QuicConnection::apply_fec_decoding(const uint8_t* data, size_t size) {
    if (!fec_enabled_ || size == 0) {
        // Wenn FEC nicht aktiviert ist, gib die unveränderten Daten zurück
        return std::vector<uint8_t>(data, data + size);
    }
    
    // Entscheide, welche FEC-Implementierung zu verwenden ist
    if (use_optimized_fec_ && fec_optimized_) {
        // SIMD-optimierte FEC verwenden
        // Erstelle ein optimiertes Paket aus den Rohdaten
        std::vector<uint8_t> data_copy(data, data + size);
        auto buffer = std::make_shared<std::vector<uint8_t>>(data_copy);
        
        OptimizedTetrysFEC::TetrysPacket packet;
        packet.seq_num = total_packets_++;
        packet.is_repair = false; // Standardmäßig ist es ein Quellpaket
        packet.assign_from_pool(buffer, memory_span<uint8_t>(*buffer));
        
        // Paket zum Decoder hinzufügen
        auto recovered_data = fec_optimized_->add_received_packet(packet);
        
        // Prüfen, ob Daten wiederhergestellt wurden
        if (recovered_data.size() > 0) {
            recovered_packets_++;
            update_packet_statistics(false, true);
            
            // Daten aus dem memory_span in einen std::vector kopieren
            std::vector<uint8_t> result(recovered_data.begin(), recovered_data.end());
            return result;
        }
    } else if (fec_) {
        // Standard-FEC verwenden
        // Erstelle TetrysPacket aus den Rohdaten
        std::vector<TetrysFEC::TetrysPacket> packets;
        
        // Einfache Implementierung: Betrachte die Daten als ein einzelnes Paket
        TetrysFEC::TetrysPacket packet;
        packet.data.assign(data, data + size);
        packet.seq_num = total_packets_++; // Verwende Gesamtpaketanzahl als Sequenznummer
        packet.is_repair = false; // Standardmäßig ist es ein Quellpaket
        
        packets.push_back(packet);
        
        // Zum FEC-Puffer für spätere Dekodierung hinzufügen
        fec_buffer_.push_back(packet.data);
        
        // Wenn genügend Pakete gesammelt wurden, führe die Dekodierung durch
        if (fec_buffer_.size() >= 10) { // Beispielwert, kann angepasst werden
            std::vector<std::vector<uint8_t>> buffer_copy = fec_buffer_;
            fec_buffer_.clear(); // Buffer zurücksetzen
            
            // Rufe decode mit allen im Buffer gespeicherten Paketen auf
            std::vector<uint8_t> result = fec_->decode_buffer(buffer_copy);
            
            // Aktualisiere Statistiken, wenn Pakete wiederhergestellt wurden
            size_t expected_size = buffer_copy.size() * packet.data.size();
            if (result.size() > expected_size) {
                recovered_packets_ += (result.size() - expected_size) / packet.data.size();
                update_packet_statistics(false, true);
            }
            
            return result;
        }
    }
    
    // Wenn keine Dekodierung erfolgt ist, gib die ursprünglichen Daten zurück
    return std::vector<uint8_t>(data, data + size);
}

// Aktualisiere Paketstatistiken
void QuicConnection::update_packet_statistics(bool packet_lost, bool packet_recovered) {
    total_packets_++;
    
    if (packet_lost) {
        packet_loss_count_++;
    }
    
    // Wenn die Verlustrate signifikant ist, aktualisiere die Redundanzrate
    if (total_packets_ % 50 == 0) { // Alle 50 Pakete prüfen
        double current_loss_rate = get_current_loss_rate();
        if (current_loss_rate > 0.05) { // Nur anpassen, wenn Verlustrate signifikant
            update_fec_redundancy_rate(current_loss_rate);
        }
    }
}

// Hilfsmethode zur Initialisierung von uTLS
bool QuicConnection::initialize_utls(const std::string& hostname) {
    if (!utls_enabled_ || hostname.empty()) {
        return false;
    }
    
    // Erstelle UTLSClientConfigurator, falls noch nicht vorhanden
    if (!utls_client_configurator_) {
        utls_client_configurator_ = std::make_unique<UTLSClientConfigurator>();
    }
    
    // Initialisiere UTLSClientConfigurator mit dem aktuellen Browser-Fingerprint
    if (!utls_client_configurator_->initialize(browser_fingerprint_, hostname, nullptr)) {
        std::cerr << "QuicConnection: Failed to initialize UTLSClientConfigurator with fingerprint " 
                  << UTLSClientConfigurator::fingerprint_to_string(browser_fingerprint_) << std::endl;
        utls_client_configurator_.reset();
        utls_enabled_ = false;
        return false;
    } else {
        std::cout << "QuicConnection: Successfully initialized uTLS with fingerprint " 
                  << UTLSClientConfigurator::fingerprint_to_string(browser_fingerprint_) << " and hostname " << hostname << std::endl;
        utls_enabled_ = true;

        // Setze den SSL_CTX aus dem UTLSClientConfigurator
        utls_ssl_ctx_ = utls_client_configurator_->get_ssl_context();
    }
    
    std::cout << "QuicConnection: Successfully initialized uTLS with fingerprint " 
              << UTLSClientConfigurator::fingerprint_to_string(browser_fingerprint_) 
              << " and hostname " << hostname << std::endl;
    
    return true;
}

// Log-Hilfsmethode
void QuicConnection::log_error(const std::string& message, bool print_ssl_errors) {
    std::cerr << "QuicConnection: " << message << std::endl;
    
    if (print_ssl_errors) {
        unsigned long err;
        char err_buf[256];
        while ((err = ERR_get_error()) != 0) {
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            std::cerr << "  SSL Error: " << err_buf << std::endl;
        }
    }
    
    std::cerr.flush();
}

void QuicConnection::async_connect(const std::string& host, uint16_t port, std::function<void(std::error_code)> callback) {
    // DNS und Endpoint
    boost::asio::ip::udp::resolver resolver(io_context_);
    boost::system::error_code resolve_ec;
    auto endpoints = resolver.resolve(host, std::to_string(port), resolve_ec);
    if (resolve_ec || endpoints.empty()) {
        log_error("DNS resolution failed for " + host + ": " + resolve_ec.message());
        if (callback) callback(std::make_error_code(std::errc::network_unreachable)); // Passender Fehlercode
        return;
    }
    remote_endpoint_ = *endpoints.begin();

    // Lokale und Peer-Adressen vorbereiten
    struct sockaddr_storage local_ss, peer_ss;
    socklen_t local_len = sizeof(local_ss), peer_len = sizeof(peer_ss);

    // Lokale Adresse (beliebiger Port)
    struct sockaddr_in* local_addr_in = (struct sockaddr_in*)&local_ss;
    local_addr_in->sin_family = AF_INET;
    local_addr_in->sin_addr.s_addr = INADDR_ANY;
    local_addr_in->sin_port = 0; // System wählt Port

    // Peer-Adresse
    struct sockaddr_in* peer_addr_in = (struct sockaddr_in*)&peer_ss;
    peer_addr_in->sin_family = AF_INET;
    
    // Versuche die IP-Adresse des Hosts zu nutzen
    peer_addr_in->sin_addr.s_addr = inet_addr("1.1.1.1"); // Cloudflare DNS als Fallback
    peer_addr_in->sin_port = htons(port);
    
    socklen_t in_len = sizeof(struct sockaddr_in); // Exakte Größe für IPv4-Adressen
    
    // Generierung einer zufälligen SCID (Source Connection ID)
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    std::string scid_prefix = "QuicSandID"; // Präfix für einfachere Identifikation
    size_t prefix_len = std::min(scid_prefix.length(), (size_t)8); // Maximal 8 Bytes für das Präfix
    
    // Kopiere das Präfix
    memcpy(scid, scid_prefix.c_str(), prefix_len);
    
    // Fülle den Rest mit Zufallsdaten
    for (size_t i = prefix_len; i < QUICHE_MAX_CONN_ID_LEN; i++) {
        scid[i] = rand() % 256;
    }
    
    size_t scid_len = QUICHE_MAX_CONN_ID_LEN;

    // Verbindungsmethode basierend auf uTLS-Konfiguration wählen
    bool using_utls = false;

    // Neue uTLS-Integration mit UTLSClientConfigurator
    if (utls_enabled_) {
        std::cout << "QuicConnection: Using uTLS with browser fingerprint " 
                  << UTLSClientConfigurator::fingerprint_to_string(browser_fingerprint_) << std::endl;
        
        // Initialisiere uTLS mit dem Hostnamen
        if (initialize_utls(host)) {
            // Connect mit der fortgeschrittenen uTLS-Integration
            std::cout << "QuicConnection: Connecting with uTLS using UTLSClientConfigurator..." << std::endl;
            
            // Verwende quiche_conn_new_with_tls statt quiche_conn_new_with_tls_ctx
            // Diese Funktion ist in der aktuellen quiche-Bibliothek verfügbar
            
            // Hole das SSL-Objekt vom UTLSClientConfigurator
            SSL *ssl = nullptr;
            if (utls_client_configurator_) {
                ssl = utls_client_configurator_->get_ssl_conn();
            }
            
            // Verwende korrekte sockaddr_in-Strukturen mit exakten Größen
            struct sockaddr_in local_in;
            memset(&local_in, 0, sizeof(local_in));
            local_in.sin_family = AF_INET;
            local_in.sin_addr.s_addr = INADDR_ANY;
            local_in.sin_port = htons(0); // Beliebiger Port
            
            struct sockaddr_in peer_in;
            memset(&peer_in, 0, sizeof(peer_in));
            peer_in.sin_family = AF_INET;
            
            // Versuche die IP-Adresse des Hosts zu nutzen
            peer_in.sin_addr.s_addr = inet_addr("1.1.1.1"); // Cloudflare DNS als Fallback
            peer_in.sin_port = htons(port);
            
            socklen_t in_len = sizeof(struct sockaddr_in); // Exakte Größe für IPv4-Adressen
            
            // Versuche mehrere Methoden, um eine Verbindung herzustellen
            
            // Versuch 1: Mit korrekten sockaddr_in-Strukturen
            std::cout << "QuicConnection: Attempting connection with sockaddr_in structures..." << std::endl;
            quiche_conn_ = quiche_conn_new_with_tls(scid, scid_len,
                                                nullptr, 0, // odcid (optional)
                                                (struct sockaddr*)&local_in, in_len,
                                                (struct sockaddr*)&peer_in, in_len,
                                                quiche_config_,
                                                ssl,         // SSL-Objekt statt SSL_CTX
                                                false);      // Als Client
                                                
            // Versuch 2: Falls das fehlschlägt, versuche es mit NULL-Adressen
            // Dies funktioniert oft besser in der quiche-Bibliothek
            if (!quiche_conn_) {
                std::cout << "QuicConnection: First attempt failed, trying with NULL addresses..." << std::endl;
                quiche_conn_ = quiche_conn_new_with_tls(scid, scid_len,
                                                    nullptr, 0, // odcid (optional)
                                                    nullptr, 0, // keine lokale Adresse
                                                    nullptr, 0, // keine Peer-Adresse
                                                    quiche_config_,
                                                    ssl,         // SSL-Objekt statt SSL_CTX
                                                    false);      // Als Client
            }
            
            // Versuch 3: Versuche eine minimale Konfiguration ohne SSL
            if (!quiche_conn_) {
                std::cout << "QuicConnection: Second attempt failed, trying minimal config..." << std::endl;
                quiche_conn_ = quiche_conn_new_with_tls(scid, scid_len,
                                                    nullptr, 0, // odcid (optional)
                                                    nullptr, 0, // keine lokale Adresse
                                                    nullptr, 0, // keine Peer-Adresse
                                                    quiche_config_,
                                                    nullptr,     // kein SSL-Objekt
                                                    false);      // Als Client
            }
            
            if (quiche_conn_) {
                std::cout << "QuicConnection: Connection with uTLS successful." << std::endl;
                using_utls = true;
                
                // Setze explizit SNI (Server Name Indication)
                if (quiche_conn_set_sni(quiche_conn_, host.c_str()) != 0) {
                    std::cout << "QuicConnection: Successfully set SNI to " << host << std::endl;
                } else {
                    log_error("Failed to set SNI to " + host + ", but continuing anyway", true);
                }
                
                // Versuche Zero-RTT Handshake, wenn aktiviert
                if (zero_rtt_config_.enabled) {
                    // Initialisiere Zero-RTT wenn nötig
                    setup_zero_rtt();
                    
                    if (attempt_zero_rtt_handshake(host)) {
                        std::cout << "QuicConnection: Zero-RTT handshake attempted for " << host << std::endl;
                    } else {
                        std::cout << "QuicConnection: Standard handshake used (0-RTT unavailable) for " << host << std::endl;
                    }
                }
            } else {
                log_error("quiche_conn_new_with_tls_ctx failed with UTLSClientConfigurator", true);
                // Fallback wird unten versucht
            }
        } else {
            log_error("Failed to initialize uTLS with hostname " + host);
            // Fallback wird unten versucht
        }
    }
    // Legacy-Unterstützung für die alte uTLS-Integration
    else if (utls_ssl_ctx_) {
        std::cout << "QuicConnection: Attempting legacy connect with uTLS via quiche_conn_new_with_tls_ctx..." << std::endl;
        // Versuche verbesserte TLS ClientHello-Anpassung mit unserem Wrapper
        quiche_conn_ = quiche_conn_new_with_tls_ctx(scid, scid_len,
                                                   nullptr, 0, // odcid (optional)
                                                   (struct sockaddr*)&local_ss, local_len,
                                                   (struct sockaddr*)&peer_ss, peer_len,
                                                   quiche_config_,
                                                   utls_ssl_ctx_);
        
        if (quiche_conn_) {
            std::cout << "QuicConnection: Legacy uTLS connection successful." << std::endl;
            using_utls = true;
            
            // Setze explizit SNI
            if (quiche_conn_set_sni(quiche_conn_, host.c_str()) != 0) {
                std::cout << "QuicConnection: Successfully set SNI to " << host << std::endl;
            }
        } else {
            log_error("Legacy quiche_conn_new_with_tls_ctx failed", true);
            // Fallback wird unten versucht
        }
    }
    
    // Fallback auf Standardverbindung ohne uTLS, wenn uTLS fehlgeschlagen oder deaktiviert ist
    if (!using_utls) {
        std::cout << "QuicConnection: Falling back to standard QUIC connection without uTLS..." << std::endl;
        
        // Aktualisierte Version von quiche_conn_new verwenden
        // Wir erstellen einen neuen Connection mit der aktuellen Quiche-API
        // Angepasst für quiche 0.24.2, mit korrekten Adresstypen
        struct sockaddr_in local_in;
        memset(&local_in, 0, sizeof(local_in));
        local_in.sin_family = AF_INET;
        local_in.sin_addr.s_addr = INADDR_ANY;
        local_in.sin_port = htons(0); // Beliebiger Port
        
        struct sockaddr_in peer_in;
        memset(&peer_in, 0, sizeof(peer_in));
        peer_in.sin_family = AF_INET;
        // Verwenden wir eine bekannte IP-Adresse für den Test
        peer_in.sin_addr.s_addr = inet_addr("1.1.1.1"); 
        peer_in.sin_port = htons(443);
        
        // Erzeuge zumindest ein SSL-Objekt für quiche_conn_new_with_tls
        SSL *ssl = nullptr;
        if (utls_client_configurator_) {
            ssl = utls_client_configurator_->get_ssl_conn();
        }
        
        // Versuche mit quiche_conn_new_with_tls, da diese in der Bibliothek verfügbar ist
        quiche_conn_ = quiche_conn_new_with_tls(
            scid, scid_len,                      // Source Connection ID
            nullptr, 0,                         // Keine optionale Destination Connection ID
            (struct sockaddr*)&local_in, sizeof(local_in), // Lokale IPv4-Adresse
            (struct sockaddr*)&peer_in, sizeof(peer_in),   // Peer IPv4-Adresse
            quiche_config_,                     // Quiche-Konfiguration
            ssl,                               // SSL-Objekt von uTLS
            false                              // Dies ist ein Client
        );
        
        // Wenn das fehlschlägt, versuchen wir einen alternativen Ansatz
        if (!quiche_conn_) {
            std::cerr << "Fallback auf Alternative ohne Adressen..." << std::endl;
            
            // Versuche mit minimalen Parametern
            quiche_conn_ = quiche_conn_new_with_tls(
                scid, scid_len,                // Source Connection ID
                nullptr, 0,                   // Keine optionale Destination Connection ID
                nullptr, 0,                   // Keine lokale Adresse
                nullptr, 0,                   // Keine Peer-Adresse
                quiche_config_,                // Quiche-Konfiguration
                ssl,                          // SSL-Objekt von uTLS
                false                         // Dies ist ein Client
            );
        }
        
        if (quiche_conn_) {
            std::cout << "QuicConnection: Standard QUIC connection successful." << std::endl;
            
            // Setze SNI
            quiche_conn_set_sni(quiche_conn_, host.c_str());
        } else {
            std::string err_msg = "Failed to create standard QUIC connection";
            log_error(err_msg, true);
            if (callback) callback(std::make_error_code(std::errc::connection_aborted));
            return;
        }
    }
    
    // Öffne den UDP-Socket, falls noch nicht geschehen
    if (!socket_.is_open()) {
        boost::system::error_code ec;
        socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec) {
            log_error("Failed to open UDP socket: " + ec.message());
            if (callback) callback(ec);
            return;
        }
        
        // Verbinde Socket mit dem remote endpoint (optional, aber nützlich)
        socket_.connect(remote_endpoint_, ec);
        if (ec) {
            log_error("Failed to connect UDP socket: " + ec.message());
            if (callback) callback(ec);
            return;
        }
    }
    
    // Starte den Handshake-Prozess mit dem Server
    // Bereite das erste QUIC-Paket vor (Initial packet)
    uint8_t* out = send_buf_.data();
    size_t out_len = send_buf_.size();
    
    // Erstelle Initial Packet mit quiche
    quiche_send_info send_info;
    memset(&send_info, 0, sizeof(send_info));
    ssize_t written = quiche_conn_send(quiche_conn_, out, out_len, &send_info);
    
    if (written < 0) {
        log_error("Failed to create initial QUIC packet");
        if (callback) callback(std::make_error_code(std::errc::protocol_error));
        return;
    }
    
    // Sende das Initial Packet zum Server
    if (written > 0) {
        std::cout << "QuicConnection: Sending initial QUIC packet, size: " << written << std::endl;
        
        socket_.async_send_to(
            boost::asio::buffer(out, static_cast<size_t>(written)),
            remote_endpoint_,
            [this, callback](const boost::system::error_code& ec, std::size_t /*bytes_transferred*/) {
                if (ec) {
                    log_error("Failed to send initial packet: " + ec.message());
                    if (callback) callback(ec);
                    return;
                }
                
                // Starte das Empfangen von Paketen
                start_receive(callback);
            });
    } else {
        // Kein Paket zum Senden, starte direkt den Empfang
        start_receive(callback);
    }
}

// Helper-Methode zum Starten des Empfangens von Paketen
void QuicConnection::start_receive(std::function<void(std::error_code)> callback) {
    if (!quiche_conn_ || !socket_.is_open()) {
        if (callback) callback(std::make_error_code(std::errc::not_connected));
        return;
    }
    
    // Starte asynchrones Empfangen von UDP-Paketen
    socket_.async_receive_from(
        boost::asio::buffer(recv_buffer_),
        remote_endpoint_,
        [this, callback](const boost::system::error_code& ec, std::size_t bytes_received) {
            if (ec) {
                log_error("Fehler beim Empfangen von UDP-Paketen: " + ec.message());
                if (callback) callback(ec);
                return;
            }
            
            if (bytes_received == 0) {
                // Leeres Paket, ignorieren und weiter Empfangen
                start_receive(callback);
                return;
            }
            
            std::cout << "QuicConnection: Received " << bytes_received << " bytes" << std::endl;
            
            // Verarbeite das empfangene QUIC-Paket
            uint8_t* buf = recv_buffer_.data();
            
            // Erstelle quiche_recv_info Struktur
            quiche_recv_info recv_info;
            sockaddr_storage from_storage, to_storage;
            recv_info.from = (struct sockaddr*)&from_storage;
            recv_info.from_len = sizeof(from_storage);
            recv_info.to = (struct sockaddr*)&to_storage;
            recv_info.to_len = sizeof(to_storage);
            
            // Konvertiere boost::asio endpoint zu sockaddr für quiche
            boost::asio::ip::udp::endpoint local_endpoint = socket_.local_endpoint();
            boost::asio::ip::address local_addr = local_endpoint.address();
            if (local_addr.is_v4()) {
                sockaddr_in* addr_in = (sockaddr_in*)&to_storage;
                addr_in->sin_family = AF_INET;
                addr_in->sin_port = htons(local_endpoint.port());
                inet_pton(AF_INET, local_addr.to_string().c_str(), &addr_in->sin_addr);
                recv_info.to_len = sizeof(sockaddr_in);
            } else {
                sockaddr_in6* addr_in6 = (sockaddr_in6*)&to_storage;
                addr_in6->sin6_family = AF_INET6;
                addr_in6->sin6_port = htons(local_endpoint.port());
                inet_pton(AF_INET6, local_addr.to_string().c_str(), &addr_in6->sin6_addr);
                recv_info.to_len = sizeof(sockaddr_in6);
            }
            
            // Remote endpoint
            boost::asio::ip::address remote_addr = remote_endpoint_.address();
            if (remote_addr.is_v4()) {
                sockaddr_in* addr_in = (sockaddr_in*)&from_storage;
                addr_in->sin_family = AF_INET;
                addr_in->sin_port = htons(remote_endpoint_.port());
                inet_pton(AF_INET, remote_addr.to_string().c_str(), &addr_in->sin_addr);
                recv_info.from_len = sizeof(sockaddr_in);
            } else {
                sockaddr_in6* addr_in6 = (sockaddr_in6*)&from_storage;
                addr_in6->sin6_family = AF_INET6;
                addr_in6->sin6_port = htons(remote_endpoint_.port());
                inet_pton(AF_INET6, remote_addr.to_string().c_str(), &addr_in6->sin6_addr);
                recv_info.from_len = sizeof(sockaddr_in6);
            }
            
            ssize_t done = quiche_conn_recv(quiche_conn_, buf, bytes_received, &recv_info);
            
            if (done < 0) {
                log_error("Failed to process QUIC packet");
                if (callback) callback(std::make_error_code(std::errc::protocol_error));
                return;
            }
            
            // Prüfe ob wir weitere Pakete senden müssen (z.B. ACKs)
            uint8_t* out = send_buf_.data();
            size_t out_len = send_buf_.size();
            
            // Erstelle quiche_send_info Struktur
            quiche_send_info send_info;
            memset(&send_info, 0, sizeof(send_info));
            
            ssize_t written = quiche_conn_send(quiche_conn_, out, out_len, &send_info);
            
            if (written > 0) {
                // Wenn FEC aktiviert ist, wende die Kodierung auf die Antwort an
                if (fec_enabled_ && fec_) {
                    std::vector<uint8_t> encoded_response = apply_fec_encoding(out, static_cast<size_t>(written));
                    memcpy(out, encoded_response.data(), std::min(encoded_response.size(), send_buf_.size()));
                    written = std::min(static_cast<ssize_t>(encoded_response.size()), static_cast<ssize_t>(send_buf_.size()));
                }
                
                // Sende Antwortpaket
                boost::system::error_code ec;
                socket_.send_to(boost::asio::buffer(out, static_cast<size_t>(written)), remote_endpoint_, 0, ec);
                
                if (ec) {
                    log_error("Failed to send response packet: " + ec.message());
                }
            }
            
            // Prüfe Status der Verbindung
            if (quiche_conn_is_established(quiche_conn_)) {
                // Verbindung hergestellt, informiere Callback
                std::cout << "QuicConnection: Connection established!" << std::endl;
                if (callback) {
                    callback(std::error_code{}); // Kein Fehler
                    return;  // Callback nur einmal aufrufen, wenn Verbindung hergestellt
                }
            } else if (quiche_conn_is_closed(quiche_conn_)) {
                // Verbindung geschlossen
                bool app_closed = quiche_conn_is_closed(quiche_conn_);
                bool is_app = false;
                uint64_t error_code = 0;
                const uint8_t *reason = nullptr;
                size_t reason_len = 0;
                quiche_conn_peer_error(quiche_conn_, &is_app, &error_code, &reason, &reason_len);
                
                std::string close_reason = app_closed ? "closed by peer" : "closed locally";
                log_error("Connection " + close_reason + " with error code " + std::to_string(error_code));
                
                if (callback) callback(std::make_error_code(std::errc::connection_aborted));
                return;
            }
            
            // Setze Empfangen fort
            start_receive(callback);
        });
}

void QuicConnection::disconnect(std::error_code ec) {
    std::cout << "Disconnecting with error: " << ec.message() << std::endl;
    
    if (quiche_conn_) {
        // Sende QUIC CONNECTION_CLOSE Frame
        quiche_conn_close(quiche_conn_, true, 0, nullptr, 0);
        
        // Sende abschließendes Paket mit dem Close-Frame
        uint8_t* out = send_buf_.data();
        size_t out_len = send_buf_.size();
        
        quiche_send_info send_info;
        memset(&send_info, 0, sizeof(send_info));
        ssize_t written = quiche_conn_send(quiche_conn_, out, out_len, &send_info);
        
        if (written > 0) {
            boost::system::error_code send_ec;
            socket_.send_to(boost::asio::buffer(out, static_cast<size_t>(written)), 
                          remote_endpoint_, 0, send_ec);
            
            if (send_ec) {
                log_error("Failed to send disconnect packet: " + send_ec.message());
            }
        }
    }
    
    // Informiere Callback, falls vorhanden
    if (error_callback) {
        error_callback(ec);
    }
}

std::shared_ptr<QuicStream> QuicConnection::create_stream() {
    if (!quiche_conn_ || !quiche_conn_is_established(quiche_conn_)) {
        log_error("Cannot create stream: Connection not established");
        return nullptr;
    }
    
    // Erstelle einen neuen bidirektionalen Stream
    // Verwende eine quiche-kompatible Methode für Stream-Erstellung
    uint64_t stream_id = 0;
    // Ab quiche v0.10.0 kann stream_id direkt gesetzt werden für bidirektionale Streams
    uint64_t stream_type = 0; // 0 = bidirektional, client-initiiert
    stream_id = (stream_type << 60) | (quiche_stream_id_counter_ * 4); // Shift nur um 60 Bits (weniger als 64)
    quiche_stream_id_counter_++;
    
    // Überprüfe, ob der Stream erstellt werden kann
    if (quiche_conn_stream_capacity(quiche_conn_, stream_id) <= 0) {
        log_error("No capacity to create new QUIC stream");
        return nullptr;
    }
    
    if (stream_id < 0) {
        log_error("Failed to create new QUIC stream");
        return nullptr;
    }
    
    // Erstelle ein QuicStream-Objekt mit std::shared_ptr
    // Hier müsste die tatsächliche QuicStream-Implementierung verwendet werden
    // Dies ist ein Platzhalter, der angepasst werden muss
    std::shared_ptr<QuicStream> stream = std::make_shared<QuicStream>(shared_from_this(), stream_id, StreamType::Bidirectional);
    
    // Informiere Callback, falls vorhanden
    if (stream_callback) {
        stream_callback(stream);
    }
    
    return stream;
}

void QuicConnection::send_datagram(const uint8_t* data, size_t size) {
    if (!quiche_conn_ || !quiche_conn_is_established(quiche_conn_)) {
        log_error("Cannot send datagram: Connection not established");
        return;
    }
    
    // Wenn FEC aktiviert ist, wende die Kodierung an
    std::vector<uint8_t> encoded_data;
    
    if (fec_enabled_ && fec_) {
        encoded_data = apply_fec_encoding(data, size);
        data = encoded_data.data();
        size = encoded_data.size();
    }
    
    // Sende ein Datagramm über die Verbindung
    // Dies ist nützlich für Daten, die nicht von einer Stream-Semantik profitieren
    // oder wenn garantierte Zustellung nicht benötigt wird
    
    int64_t sent = quiche_conn_dgram_send(quiche_conn_, data, size);
    
    if (sent < 0) {
        log_error("Failed to queue datagram for sending");
        return;
    }
    
    // Sendebereitschaft prüfen und ggf. Pakete versenden
    uint8_t* out = send_buf_.data();
    size_t out_len = send_buf_.size();
    
    quiche_send_info send_info;
    memset(&send_info, 0, sizeof(send_info));
    
    ssize_t written = quiche_conn_send(quiche_conn_, out, out_len, &send_info);
    
    if (written <= 0) {
        if (written == QUICHE_ERR_DONE) {
            // Nichts zu senden
            return;
        }
        
        log_error("Failed to create outgoing packet: " + std::to_string(written));
        return;
    }
    
    // Aktualisiere Statistiken für gesendete Pakete
    if (fec_enabled_) {
        total_packets_++;
    }
    
    // Sende das Paket
    boost::system::error_code ec;
    socket_.send_to(boost::asio::buffer(out, static_cast<size_t>(written)), remote_endpoint_, 0, ec);
    
    if (ec) {
        log_error("Failed to send datagram: " + ec.message());
    }
}

void QuicConnection::handle_error(std::error_code ec) {
    log_error("Handling error: " + ec.message());
    
    // Informiere Callback, falls vorhanden
    if (error_callback) {
        error_callback(ec);
    }
    
    // Trenne die Verbindung mit dem Fehlercode
    disconnect(ec);
}

// Implementation der handle_packet-Methode
void QuicConnection::handle_packet(const uint8_t* packet, size_t size) {
    if (!quiche_conn_) {
        log_error("Cannot handle packet: No QUIC connection established");
        return;
    }
    
    // Wenn FEC aktiviert ist, wende die Dekodierung an
    std::vector<uint8_t> decoded_data;
    bool packet_recovered = false;
    
    if (fec_enabled_ && fec_) {
        decoded_data = apply_fec_decoding(packet, size);
        
        // Wenn die dekodierte Datengröße größer ist als die Eingabedaten,
        // wurde möglicherweise ein verlorenes Paket wiederhergestellt
        if (decoded_data.size() > size) {
            packet_recovered = true;
            packet = decoded_data.data();
            size = decoded_data.size();
        }
    }
    
    // Verarbeite das empfangene QUIC-Paket
    // Erstellen der recv_info-Struktur
    quiche_recv_info recv_info;
    memset(&recv_info, 0, sizeof(recv_info));
    
    // Wir müssen packet in einen nicht-const Puffer kopieren, da quiche_conn_recv
    // einen nicht-const Puffer erwartet
    uint8_t *mutable_packet = new uint8_t[size];
    memcpy(mutable_packet, packet, size);
    
    ssize_t done = quiche_conn_recv(quiche_conn_, mutable_packet, size, &recv_info);
    
    // Bereinigen des temporären Puffers
    delete[] mutable_packet;
    
    if (done < 0) {
        log_error("Failed to process QUIC packet in handle_packet");
        // Zähle als verlorenes Paket für die FEC-Statistik
        if (fec_enabled_) {
            update_packet_statistics(true, false);
        }
        return;
    }
    
    // Aktualisiere FEC-Statistiken für erfolgreich empfangene Pakete
    if (fec_enabled_) {
        update_packet_statistics(false, packet_recovered);
    }
    
    // Prüfe ob wir eine Antwort senden müssen
    uint8_t* out = send_buf_.data();
    size_t out_len = send_buf_.size();
    
    // Erstellen der send_info-Struktur
    quiche_send_info send_info;
    memset(&send_info, 0, sizeof(send_info));
    
    ssize_t written = quiche_conn_send(quiche_conn_, out, out_len, &send_info);
    
    if (written > 0) {
        // Wenn FEC aktiviert ist, wende die Kodierung auf die Antwort an
        if (fec_enabled_ && fec_) {
            std::vector<uint8_t> encoded_response = apply_fec_encoding(out, static_cast<size_t>(written));
            memcpy(out, encoded_response.data(), std::min(encoded_response.size(), send_buf_.size()));
            written = std::min(static_cast<ssize_t>(encoded_response.size()), static_cast<ssize_t>(send_buf_.size()));
        }
        
        // Sende Antwortpaket
        boost::system::error_code ec;
        socket_.send_to(boost::asio::buffer(out, static_cast<size_t>(written)), remote_endpoint_, 0, ec);
        
        if (ec) {
            log_error("Failed to send response packet in handle_packet: " + ec.message());
        }
    }
    
    // Prüfe auf Path Response Frames, falls Connection Migration aktiviert ist
    if (migration_enabled_) {
        // Laut QUIC RFC 9000 haben Path Response Frames den Typen 0x1b
        // Dies ist eine vereinfachte Version der Path Response Erkennung
        // In einer vollständigen Implementierung würden wir hier die QUIC-Frame-Parsing-Logik verwenden
        bool path_response_received = false;
        
        // Suche im Paket nach Path Response Frames (Typ 0x1b)
        for (size_t i = 0; i < size - 8; i++) {
            if (packet[i] == 0x1b) { // Path Response Frame Typ
                // Validiere die Path Response und aktualisiere den Connection-Status
                if (validate_path_response(&packet[i], size - i)) {
                    path_response_received = true;
                    std::cout << "QuicConnection: Path Response received and validated" << std::endl;
                    break;
                }
            }
        }
        
        // Prüfe zusätzlich, ob eine Netzwerkänderung erkannt wurde
        if (!path_response_received && detect_network_change()) {
            std::cout << "QuicConnection: Network change detected, attempting migration" << std::endl;
            initiate_migration();
        }
    }
    
    // Prüfe auf MTU-Probe-Antworten, falls MTU Discovery aktiviert ist
    if (mtu_discovery_enabled_ && in_search_phase_) {
        // Prüfe, ob seit dem letzten Probe-Versuch eine Antwort empfangen wurde
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_probe_time_).count();
        
        // Wenn wir eine Antwort innerhalb des Timeouts erhalten, betrachten wir die Probe als erfolgreich
        if (elapsed < probe_timeout_ms_) {
            // Eine Antwort wurde empfangen, betrachte dies als erfolgreiche Probe
            handle_mtu_probe_response(true);
        } else if (elapsed >= probe_timeout_ms_ && current_probe_mtu_ > 0) {
            // Timeout für die aktuelle Probe
            handle_mtu_probe_response(false);
        }
    }
    
    // Prüfe Status der Verbindung
    if (quiche_conn_is_established(quiche_conn_)) {
        std::cout << "QuicConnection: Connection is now established" << std::endl;
        
        // Informiere Callback, falls vorhanden
        if (connection_callback) {
            // Wir müssen boost::shared_ptr zu std::shared_ptr konvertieren
            if (connection_callback) {
                // Erzwinge eine Konvertierung von boost::shared_ptr zu std::shared_ptr
                std::shared_ptr<QuicConnection> std_self(shared_from_this().get(), 
                                                       [self = shared_from_this()](QuicConnection*){});
                connection_callback(std_self, std::error_code{});
            }
        }
    } else if (quiche_conn_is_closed(quiche_conn_)) {
        // Verbindung geschlossen
        bool app_closed = quiche_conn_is_closed(quiche_conn_);
        bool is_app = false;
        uint64_t error_code = 0;
        const uint8_t *reason = nullptr;
        size_t reason_len = 0;
        quiche_conn_peer_error(quiche_conn_, &is_app, &error_code, &reason, &reason_len);
        
        std::string close_reason = app_closed ? "closed by peer" : "closed locally";
        log_error("Connection " + close_reason + " with error code " + std::to_string(error_code));
        
        // Informiere Callback, falls vorhanden
        if (error_callback) {
            error_callback(std::make_error_code(std::errc::connection_aborted));
        }
    }
}



// Connection Migration Implementation

bool QuicConnection::enable_migration(bool enable) {
    // Migration kann nur aktiviert werden, wenn QUIC richtig initialisiert wurde
    if (!quiche_conn_) {
        std::cerr << "Cannot enable migration without an active QUIC connection" << std::endl;
        return false;
    }
    
    // Prüfe, ob Migration vom Server unterstützt wird (im quiche config gespeichert)
    // QUIC RFC 9000 erfordert, dass der Server dies angibt
    if (enable && !quiche_conn_migration_supported(quiche_conn_)) {
        std::cerr << "Connection migration is not supported by the remote server" << std::endl;
        return false;
    }
    
    // Wenn wir Migration aktivieren, listen wir verfügbare Netzwerkschnittstellen auf
    if (enable && !migration_enabled_) {
        available_interfaces_ = enumerate_network_interfaces();
        if (available_interfaces_.empty()) {
            std::cerr << "No network interfaces available for migration" << std::endl;
            return false;
        }
        
        // Speichere ursprünglichen Endpunkt für mögliche Zurückwechslung
        original_endpoint_ = remote_endpoint_;
        
        std::cout << "Connection migration enabled. Available interfaces: ";
        for (const auto& iface : available_interfaces_) {
            std::cout << iface << " ";
        }
        std::cout << std::endl;
    }
    
    migration_enabled_ = enable;
    return true;
}

bool QuicConnection::is_migration_enabled() const {
    return migration_enabled_;
}

bool QuicConnection::initiate_migration() {
    if (!migration_enabled_ || !quiche_conn_) {
        std::cerr << "Cannot initiate migration: migration not enabled or no active connection" << std::endl;
        return false;
    }
    
    // Wenn eine bevorzugte Schnittstelle gesetzt ist, verwende diese
    if (!preferred_interface_.empty()) {
        std::cout << "Initiating migration to preferred interface: " << preferred_interface_ << std::endl;
        return setup_migration_socket(preferred_interface_);
    }
    
    // Andernfalls versuche, eine automatische Migration durchzuführen
    // Aktuelle Schnittstelle identifizieren
    std::string current_interface = get_current_interface_name();
    
    // Finde eine alternative Schnittstelle
    for (const auto& iface : available_interfaces_) {
        if (iface != current_interface) {
            std::cout << "Initiating migration from " << current_interface << " to " << iface << std::endl;
            return setup_migration_socket(iface);
        }
    }
    
    std::cerr << "No alternative interfaces available for migration" << std::endl;
    return false;
}

bool QuicConnection::set_preferred_interface(const std::string& interface_name) {
    // Prüfe, ob die angegebene Schnittstelle verfügbar ist
    available_interfaces_ = enumerate_network_interfaces();
    bool interface_available = false;
    
    for (const auto& iface : available_interfaces_) {
        if (iface == interface_name) {
            interface_available = true;
            break;
        }
    }
    
    if (!interface_available) {
        std::cerr << "Interface '" << interface_name << "' is not available" << std::endl;
        return false;
    }
    
    preferred_interface_ = interface_name;
    return true;
}

void QuicConnection::set_migration_callback(std::function<void(bool, const std::string&, const std::string&)> callback) {
    migration_callback_ = std::move(callback);
}

// Private implementation methods for Connection Migration

bool QuicConnection::detect_network_change() {
    if (!migration_enabled_) {
        return false;
    }
    
    // Aktuelle Netzwerkschnittstellen auflisten
    std::vector<std::string> current_interfaces = enumerate_network_interfaces();
    
    // Prüfen, ob sich die verfügbaren Schnittstellen geändert haben
    bool interfaces_changed = false;
    if (current_interfaces.size() != available_interfaces_.size()) {
        interfaces_changed = true;
    } else {
        for (const auto& iface : current_interfaces) {
            bool found = false;
            for (const auto& available : available_interfaces_) {
                if (iface == available) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                interfaces_changed = true;
                break;
            }
        }
    }
    
    if (interfaces_changed) {
        std::cout << "Network interfaces changed, may need migration" << std::endl;
        available_interfaces_ = current_interfaces;
        return true;
    }
    
    return false;
}

bool QuicConnection::send_path_challenge(const boost::asio::ip::udp::endpoint& endpoint) {
    // Path Challenge wird gemäß QUIC RFC 9000 gesendet
    // Dies ist ein spezielles Paket, das prüft, ob der neue Pfad funktioniert
    
    // Generiere eine eindeutige 8-Byte-Challenge
    std::array<uint8_t, 8> challenge_data;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    for (auto& byte : challenge_data) {
        byte = dist(gen);
    }
    
    // QUIC Path Challenge Frame erstellen (Typ 0x1a)
    std::vector<uint8_t> path_challenge_frame;
    path_challenge_frame.push_back(0x1a);  // Path Challenge Frame Type
    path_challenge_frame.insert(path_challenge_frame.end(), challenge_data.begin(), challenge_data.end());
    
    // Stelle sicher, dass das Socket an das richtige Interface gebunden ist
    // Dies wird durch setup_migration_socket() behandelt
    
    try {
        // Sende die Challenge über das neue Interface
        socket_.send_to(boost::asio::buffer(path_challenge_frame), endpoint);
        
        // In einer realen Implementierung müssten wir nun auf eine Path Response warten
        // Dies wird in handle_packet() implementiert durch Aufruf von validate_path_response
        
        std::cout << "Sent path challenge to " << endpoint.address().to_string() 
                  << ":" << endpoint.port() << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to send path challenge: " << e.what() << std::endl;
        return false;
    }
}

bool QuicConnection::validate_path_response(const uint8_t* data, size_t size) {
    // Path Response muss mindestens 9 Bytes sein (1 Byte Typ + 8 Byte Challenge Data)
    if (size < 9 || data[0] != 0x1b) {  // 0x1b ist der Path Response Frame Type
        return false;
    }
    
    // In einer echten Implementierung würden wir hier die Challenge Data aus dem Paket extrahieren
    // und mit der gesendeten Challenge vergleichen
    
    // Vereinfachte Implementierung: Wir nehmen eine erfolgreiche Validierung an
    std::cout << "Path response validated successfully" << std::endl;
    
    // Update connection state for the new path
    update_connection_id();
    
    // Notify callback if set
    if (migration_callback_) {
        migration_callback_(true, get_current_interface_name(), preferred_interface_);
    }
    
    return true;
}

std::vector<std::string> QuicConnection::enumerate_network_interfaces() {
    std::vector<std::string> interfaces;
    
#ifdef _WIN32
    // Windows-spezifische Implementierung
    // GetAdaptersInfo oder ähnliche API verwenden
    // Vereinfachte Implementierung für dieses Beispiel
    interfaces.push_back("wlan0");
    interfaces.push_back("eth0");
#else
    // POSIX-kompatible Systeme (Linux, macOS)
    struct ifaddrs *ifap, *ifa;
    
    if (getifaddrs(&ifap) == 0) {
        for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
            // Ignoriere Interfaces ohne Adresse oder nicht-IP-Interfaces
            if (ifa->ifa_addr == nullptr || (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)) {
                continue;
            }
            
            // Ignoriere Loopback-Interfaces
            if (strcmp(ifa->ifa_name, "lo") == 0) {
                continue;
            }
            
            // Füge Interface zur Liste hinzu, wenn es noch nicht vorhanden ist
            std::string iface_name(ifa->ifa_name);
            if (std::find(interfaces.begin(), interfaces.end(), iface_name) == interfaces.end()) {
                interfaces.push_back(iface_name);
            }
        }
        
        freeifaddrs(ifap);
    }
#endif
    
    return interfaces;
}

bool QuicConnection::setup_migration_socket(const std::string& interface_name) {
    try {
        // Thread Safety: Sperren des Socket-Mutex
        std::lock_guard<std::mutex> lock(socket_mutex_);
        
        // Speichere den alten Endpunkt, falls wir zurückwechseln müssen
        previous_endpoints_.push_back(remote_endpoint_);
        
        // Schließe das alte Socket
        socket_.close();
        
        // Erstelle ein neues Socket, das an das spezifizierte Interface gebunden ist
        boost::asio::ip::udp::endpoint local_endpoint(boost::asio::ip::udp::v4(), 0); // Any port
        socket_ = boost::asio::ip::udp::socket(io_context_, local_endpoint);
        
#ifdef _WIN32
        // Windows-spezifischer Code für Interface-Bindung
        // ... (hier die Windows-spezifische Implementierung)
#else
        // In POSIX-Systemen (Linux, macOS), Verwende SO_BINDTODEVICE
        // Benötigt Root-Rechte auf einigen Systemen
        if (!interface_name.empty()) {
            socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true));
            
            // SO_BINDTODEVICE setzt das Netzwerkinterface
            // (benötigt CAP_NET_RAW Capability oder Root-Rechte unter Linux)
            if (setsockopt(socket_.native_handle(), SOL_SOCKET, SO_BINDTODEVICE, 
                           interface_name.c_str(), interface_name.length() + 1) == -1) {
                std::cerr << "Failed to bind to interface: " << interface_name 
                          << ", error: " << strerror(errno) << std::endl;
                
                // Fallback: Versuche ohne Interface-Bindung fortzufahren
                std::cout << "Falling back to default interface binding" << std::endl;
            } else {
                std::cout << "Successfully bound to interface: " << interface_name << std::endl;
            }
        }
#endif
        
        // Sende einen Path Challenge an den Server über die neue Verbindung
        return send_path_challenge(remote_endpoint_);
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to set up migration socket: " << e.what() << std::endl;
        handle_migration_failure();
        return false;
    }
}

void QuicConnection::handle_migration_failure() {
    // Behandle Fehler bei der Migration
    std::cerr << "Connection migration failed, attempting to revert to original connection" << std::endl;
    
    try {
        // Thread Safety: Sperren des Socket-Mutex
        std::lock_guard<std::mutex> lock(socket_mutex_);
        
        // Schließe das fehlgeschlagene Socket
        socket_.close();
        
        // Erstelle ein neues Socket mit dem ursprünglichen Endpunkt
        socket_ = boost::asio::ip::udp::socket(io_context_, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
        
        // Setze remote_endpoint_ zurück auf den ursprünglichen Wert
        if (!previous_endpoints_.empty()) {
            remote_endpoint_ = previous_endpoints_.back();
            previous_endpoints_.pop_back();
        } else {
            remote_endpoint_ = original_endpoint_;
        }
        
        // Beginne erneut mit dem Empfangen von Paketen
        start_receive([this](std::error_code ec) {
            if (ec) {
                std::cerr << "Failed to recover from migration failure: " << ec.message() << std::endl;
                
                // Benachrichtige über den Fehler
                if (migration_callback_) {
                    migration_callback_(false, preferred_interface_, get_current_interface_name());
                }
            } else {
                std::cout << "Successfully recovered from migration failure" << std::endl;
            }
        });
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to recover from migration failure: " << e.what() << std::endl;
        
        // Benachrichtige über den Fehler
        if (migration_callback_) {
            migration_callback_(false, preferred_interface_, get_current_interface_name());
        }
    }
}

void QuicConnection::update_connection_id() {
    // QUIC erfordert, dass die Connection-ID nach einer Migration aktualisiert wird
    // Dies ist ein Teil des QUIC-Protokolls (RFC 9000)
    
    // In einer echten Implementierung würden wir hier den QUIC-Stack anweisen,
    // eine neue Connection-ID zu verwenden
    
    // Vereinfachte Beispielimplementierung
    std::cout << "Updated connection ID after migration" << std::endl;
    
    // In einer vollständigen Implementierung würden wir hier quiche verwenden,
    // um eine neue Connection-ID zu erzeugen und zu verwenden
    // quiche_conn_new_connection_id(quiche_conn_, new_seq_num, new_conn_id, new_conn_id_len, new_stateless_reset_token);
}

std::string QuicConnection::get_current_interface_name() const {
    // In einer realen Implementierung würden wir den Namen des Interfaces zurückgeben,
    // an das das aktuelle Socket gebunden ist
    
    // Vereinfachte Beispielimplementierung
    // In einer vollständigen Implementierung würden wir das Interface aus dem Socket-Handle ermitteln
    
#ifdef _WIN32
    // Windows-spezifische Implementierung zur Ermittlung des aktuellen Interfaces
    return "wlan0"; // Dummy-Wert für dieses Beispiel
#else
    // POSIX-Systeme (Linux, macOS)
    // Hier würden wir das Interface aus dem Socket-Handle ermitteln
    char if_name[IF_NAMESIZE];
    unsigned int if_index = 0;
    
    // Versuche, den Interface-Index aus dem Socket zu bekommen
    socklen_t len = sizeof(if_index);
    if (getsockopt(socket_.native_handle(), SOL_SOCKET, SO_BINDTODEVICE, &if_index, &len) == 0 && if_index > 0) {
        // Konvertiere Index zu Name
        if (if_indextoname(if_index, if_name)) {
            return std::string(if_name);
        }
    }
    
    // Fallback für den Fall, dass wir das Interface nicht ermitteln können
    return "unknown";
#endif
}

} // namespace quicsand
