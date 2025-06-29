```mermaid
sequenceDiagram
    Client->>QuicConnection: process_packet()
    QuicConnection->>BBRv2: update_metrics()
    BBRv2-->>QuicConnection: congestion_window
    QuicConnection->>XdpSocket: send_packet()
    XdpSocket->>Network: Zero-Copy Transmission
    Network->>QuicConnection: handle_xdp_packet()
    QuicConnection->>MemoryPool: allocate()
