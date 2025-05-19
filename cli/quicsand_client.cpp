#include <iostream>
#include <boost/asio.hpp>
#include "quic.hpp"
#include "quic_connection.hpp"
#include "quic_stream.hpp"
#include "tls/utls_client_configurator.hpp" // uTLS Konfigurator

int main(int argc, char *argv[]) { // argc, argv für Host/Port hinzugefügt
    std::string host = "localhost";
    uint16_t port = 8080;

    if (argc >= 3) {
        host = argv[1];
        port = static_cast<uint16_t>(std::stoi(argv[2]));
    } else {
        std::cout << "Usage: quicsand_client <host> <port>" << std::endl;
        std::cout << "Using default: localhost 8080" << std::endl;
    }

    std::cout << "quicSand Client gestartet. Verbinde mit " << host << ":" << port << "..." << std::endl;
    boost::asio::io_context io_context;

    // uTLS Konfiguration
    UTLSClientConfigurator utls_configurator;
    // Hier den gewünschten Hostnamen für SNI und das Fingerprint-Profil angeben
    if (!utls_configurator.initialize("Chrome_Latest_Placeholder", host.c_str(), nullptr)) { // nullptr für ca_cert_path -> keine Verifizierung
        std::cerr << "Fehler bei der Initialisierung des UTLSClientConfigurators." << std::endl;
        return 1;
    }

    quicsand::QuicConfig qc;
    qc.server_name = host;
    qc.port = port;
    // Setze uTLS Parameter nur, wenn die Initialisierung erfolgreich war
    // qc.utls_ssl = utls_configurator.get_ssl_conn(); // Nicht mehr primär für den _ctx Ansatz
    qc.utls_ssl_ctx = utls_configurator.get_ssl_context();
    qc.utls_quiche_config = utls_configurator.get_quiche_config();

    // Shared_ptr für QuicConnection, da es von enable_shared_from_this erbt
    auto conn = std::make_shared<quicsand::QuicConnection>(io_context, qc);

    conn->async_connect(host, port, [conn](std::error_code ec) {
        if (!ec) {
            std::cout << "Verbunden mit Server!" << std::endl;
            // Beispiel: Einen Stream erstellen und Daten senden
            auto stream = conn->create_stream();
            if (stream) {
                std::cout << "Stream erstellt. Sende 'Hello uTLS!'..." << std::endl;
                const uint8_t data[] = "Hello uTLS!";
                stream->send_data(data, sizeof(data) - 1); // sizeof() - 1 um Nullterminator zu ignorieren
            } else {
                std::cerr << "Fehler beim Erstellen des Streams." << std::endl;
            }
        } else {
            std::cerr << "Verbindungsfehler: " << ec.message() << " (Code: " << ec.value() << ")" << std::endl;
        }
    });

    io_context.run();  // Handhabung asynchroner Operationen
    return 0;
}