
**Design Features:**
- Atomic operations for performance optimization
- Condition variable for efficient notification
- Move semantics to avoid data copies
- RAII mutex locks for exception safety

**Application Example:**
```mermaid
sequenceDiagram
    Sender->>QuicStream: write_data(payload)
    QuicStream->>Condition Variable: notify_one()
    Receiver->>QuicStream: is_readable()?
    QuicStream-->>Receiver: true
    Receiver->>QuicStream: read_data()
    QuicStream-->>Receiver: payload
```
```mermaid
sequenceDiagram
    Application->>QuicStream: write_data()
    QuicStream->>QuicConnection: send_packet()
    QuicConnection->>Network: Transmission
    Network->>QuicConnection: Reception
    QuicConnection->>QuicStream: read_data()
    QuicStream->>Application: Data delivery
```
