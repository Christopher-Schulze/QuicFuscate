/**
 * quiche_utls_wrapper.hpp
 * 
 * Ein Wrapper für quiche, der zusätzliche Funktionen für die uTLS-Integration bereitstellt.
 * Diese Datei implementiert Funktionen, die in der Standard-quiche-Bibliothek fehlen, 
 * aber für die uTLS-Integration benötigt werden.
 */

#ifndef QUICHE_UTLS_WRAPPER_HPP
#define QUICHE_UTLS_WRAPPER_HPP

#include <openssl/ssl.h>
#include <quiche.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Definition der SSL_QUIC_METHOD Struktur, die in der quiche-Bibliothek verwendet wird,
 * aber nicht in der C-API exponiert wird.
 * 
 * Hinweis: Wir verwenden int statt enum ssl_encryption_level_t für die Level-Parameter,
 * um Probleme mit vorwärts-Referenzen auf undefinierte Enums zu vermeiden.
 */
typedef struct ssl_quic_method_st {
    int (*set_read_secret)(SSL *ssl, int level,
                           const SSL_CIPHER *cipher, const uint8_t *secret,
                           size_t secret_len);
    int (*set_write_secret)(SSL *ssl, int level,
                            const SSL_CIPHER *cipher, const uint8_t *secret,
                            size_t secret_len);
    int (*add_handshake_data)(SSL *ssl, int level,
                              const uint8_t *data, size_t len);
    int (*flush_flight)(SSL *ssl);
    int (*send_alert)(SSL *ssl, int level, uint8_t alert);
} SSL_QUIC_METHOD;

/**
 * Gibt einen Zeiger auf die in quiche definierte QUICHE_STREAM_METHOD zurück.
 * Da diese Funktion in der quiche-Bibliothek nicht verfügbar ist, gibt diese
 * Implementierung einen NULL-Zeiger zurück und protokolliert einen Fehler.
 */
const SSL_QUIC_METHOD* quiche_ssl_get_quic_method();

/**
 * Erstellt eine neue QUIC-Verbindung mit einem extern erstellten SSL_CTX.
 * Da diese Funktion in der quiche-Bibliothek nicht verfügbar ist, ruft diese
 * Implementierung stattdessen quiche_connect auf und protokolliert einen Hinweis.
 */
quiche_conn* quiche_conn_new_with_tls_ctx(const uint8_t *scid, size_t scid_len,
                                         const uint8_t *odcid, size_t odcid_len,
                                         const struct sockaddr *local, socklen_t local_len,
                                         const struct sockaddr *peer, socklen_t peer_len,
                                         const quiche_config *config, void *ssl_ctx);

/**
 * Setzt den Server Name Indication (SNI) für eine QUIC-Verbindung.
 * Diese Funktion ist ein Wrapper um die in quiche nicht verfügbare Funktion.
 * Derzeit gibt diese Implementierung immer Erfolg zurück, da die eigentliche
 * SNI-Einstellung bereits in SSL_set_tlsext_host_name erfolgt.
 */
int quiche_conn_set_sni(quiche_conn *conn, const char *sni);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // QUICHE_UTLS_WRAPPER_HPP
