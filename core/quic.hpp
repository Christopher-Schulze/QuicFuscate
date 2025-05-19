#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <openssl/ssl.h>
#include "quiche.h"

namespace quicsand {

class QuicConnection;  // Forward-Declaration
struct QuicConfig {  // Stub-Definition
    std::string server_name;
    uint16_t port;
    // Weitere Konfigurationsparameter...

    // Für uTLS Integration mit quiche_conn_new_with_tls
    SSL* utls_ssl = nullptr; // Wird ggf. weniger relevant bei _ctx Ansatz
    SSL_CTX* utls_ssl_ctx = nullptr; // Für quiche_conn_new_with_tls_ctx
    quiche_config* utls_quiche_config = nullptr; // Für uTLS Integration
};

enum class StreamType { Bidirectional, Unidirectional };  // Definition für StreamType

class QuicStream;  // Forward-Declaration für QuicStream, Definition in quic_stream.hpp

} // namespace quicsand
