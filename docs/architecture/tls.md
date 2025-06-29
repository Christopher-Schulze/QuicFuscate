sequenceDiagram
    Client->>SniHiding: process_client_hello(tls_packet)
    SniHiding->>SniHiding: modify_sni(front_domain)
    SniHiding->>SniHiding: apply_sni_padding()
    SniHiding-->>Client: Modified TLS packet
    Client->>Front-Server: TLS handshake with disguised domain
    Front-Server->>Real-Server: Forwarding to real service
```mermaid
sequenceDiagram
    Client->>UTLSImplementation: generate_client_hello("example.com")
    UTLSImplementation->>OpenSSL: Configure Cipher Suites
    UTLSImplementation->>OpenSSL: Configure TLS Extensions
    OpenSSL-->>UTLSImplementation: Raw ClientHello data
    UTLSImplementation->>Client: Modified ClientHello
    Client->>Server: TLS handshake with browser fingerprint
```
