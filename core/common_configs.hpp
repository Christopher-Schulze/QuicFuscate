#pragma once

#include <cstdint>
#include <chrono>
#include <string>

namespace quicsand {

/**
 * ZeroRttConfig - Konfigurationsoptionen für Zero-RTT-Verbindungen
 */
struct ZeroRttConfig {
    bool enabled = true;                      // Zero-RTT aktiviert
    bool require_binding = true;              // Token-Binding erforderlich
    uint32_t max_early_data = 16384;          // Maximale Datenmenge für 0-RTT (16 KB)
    uint32_t max_tokens_per_host = 4;         // Maximale Anzahl Tokens pro Host
    uint32_t max_token_lifetime_s = 7200;     // Max. Lebensdauer eines Tokens (2 Stunden)
    bool reject_if_no_token = false;          // Verbindung ablehnen, wenn kein Token verfügbar
    bool update_keys_after_handshake = true;  // Schlüssel nach Handshake aktualisieren
};

} // namespace quicsand
