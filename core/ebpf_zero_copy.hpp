#ifndef EBPF_ZERO_COPY_HPP
#define EBPF_ZERO_COPY_HPP

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <array>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>

namespace quicsand {

// Callback-Funktionstypen
using PacketHandler = std::function<void(const void* data, size_t len, const struct sockaddr* addr, socklen_t addrlen)>;
using CompletionHandler = std::function<void(size_t bytes_sent, int error)>;

/**
 * EBPF_MAP_Typen
 */
enum class EbpfMapType {
    HASH,
    ARRAY,
    PROG_ARRAY,
    PERF_EVENT_ARRAY,
    PERCPU_HASH,
    PERCPU_ARRAY,
    RINGBUF
};

/**
 * XDP-Aktionen
 */
enum class XdpAction {
    ABORTED = 0,
    DROP = 1,
    PASS = 2,
    TX = 3,
    REDIRECT = 4
};

/**
 * Struktur für XDP-Metadaten, die zwischen Kernel und Userspace ausgetauscht werden
 */
struct XdpMetadata {
    uint32_t packet_size;
    uint32_t flags;
    uint32_t ip_protocol;
    uint32_t src_port;
    uint32_t dst_port;
    uint8_t src_addr[16]; // Groß genug für IPv6
    uint8_t dst_addr[16];
    uint64_t timestamp;
};

/**
 * EbpfMap verwaltet eine eBPF-Map zum Datenaustausch zwischen Kernel und Userspace
 */
class EbpfMap {
public:
    EbpfMap(const std::string& name, EbpfMapType type, uint32_t key_size, uint32_t value_size, uint32_t max_entries);
    ~EbpfMap();

    int get_fd() const { return fd_; }
    bool update(const void* key, const void* value, uint64_t flags = 0);
    bool lookup(const void* key, void* value) const;
    bool delete_key(const void* key);

    template<typename K, typename V>
    bool update_typed(const K& key, const V& value, uint64_t flags = 0) {
        return update(&key, &value, flags);
    }

    template<typename K, typename V>
    bool lookup_typed(const K& key, V& value) const {
        return lookup(&key, &value);
    }

private:
    int fd_;
    std::string name_;
    EbpfMapType type_;
    uint32_t key_size_;
    uint32_t value_size_;
    uint32_t max_entries_;
};

/**
 * Ringbuffer zum schnellen, lockfreien Datentransfer zwischen Kernel und Userspace
 */
class RingBuffer {
public:
    RingBuffer(int map_fd, size_t buffer_size = 16 * 1024 * 1024);
    ~RingBuffer();

    bool add_callback(std::function<void(const void*, size_t)> callback);
    bool start();
    void stop();

private:
    void poll_thread_fn();

    int map_fd_;
    size_t buffer_size_;
    std::atomic<bool> running_{false};
    std::thread poll_thread_;
    std::vector<std::function<void(const void*, size_t)>> callbacks_;
    void* ring_buffer_;
};

/**
 * XdpSocket bietet eine High-Level-Schnittstelle für XDP-basierte Zero-Copy-Operationen
 */
class XdpSocket {
public:
    // Konstruktor mit Netzwerk-Interface und optionalem Port
    XdpSocket(const std::string& interface, uint16_t port = 0);
    ~XdpSocket();

    // Socket aktivieren und eBPF-Programm laden
    bool attach(const std::string& ebpf_program_path = "");

    // Socket deaktivieren und eBPF-Programm entladen
    bool detach();

    // Callback für eingehende Pakete setzen
    void set_packet_handler(PacketHandler handler);

    // Senden von Daten mit Zero-Copy
    bool send_zero_copy(const void* data, size_t len, const struct sockaddr* addr, socklen_t addrlen,
                       CompletionHandler completion_handler = nullptr);

    // Bulk-Senden mit Zero-Copy für bessere Leistung
    bool send_zero_copy_batch(const std::vector<std::pair<const void*, size_t>>& buffers,
                            const struct sockaddr* addr, socklen_t addrlen,
                            CompletionHandler completion_handler = nullptr);

    // CPU-Core-Pinning für optimale Leistung
    bool pin_to_core(int cpu_id);

    // Einstellungen und Optimierungen
    bool set_tx_burst_size(uint32_t burst_size);
    bool set_rx_ringsize(uint32_t ringsize);
    bool set_tx_ringsize(uint32_t ringsize);
    bool set_sockopt(int level, int optname, const void* optval, socklen_t optlen);

private:
    // Interne Methoden
    void poll_packets();
    bool setup_maps();
    bool load_program(const std::string& path);

    std::string interface_;
    int ifindex_;
    uint16_t port_;
    int xdp_fd_;
    int umem_fd_;
    std::unique_ptr<RingBuffer> rx_ring_;
    std::unique_ptr<EbpfMap> xdp_map_;
    
    PacketHandler packet_handler_;
    std::thread poll_thread_;
    std::atomic<bool> running_{false};
    
    // Speicherpuffer für Zero-Copy-Operationen
    void* umem_area_;
    size_t umem_size_;
    
    // Steuerungsvariablen
    uint32_t tx_burst_size_{64};
    uint32_t rx_ringsize_{4096};
    uint32_t tx_ringsize_{4096};
};

/**
 * EbpfProgram verwaltet einen eBPF-Programmlebenszyklus
 */
class EbpfProgram {
public:
    EbpfProgram(const std::string& name);
    ~EbpfProgram();

    bool load_from_file(const std::string& filename);
    bool load_from_memory(const void* data, size_t size);
    int get_fd() const { return prog_fd_; }

    bool attach_to_interface(const std::string& interface, XdpAction default_action = XdpAction::PASS);
    bool detach_from_interface(const std::string& interface);

private:
    std::string name_;
    int prog_fd_;
};

/**
 * QuicSandXdpContext verwaltet den eBPF/XDP-Kontext für die QuicSand-Anwendung
 */
class QuicSandXdpContext {
public:
    static QuicSandXdpContext& instance();

    bool initialize(const std::string& interface);
    bool is_xdp_supported();
    
    std::shared_ptr<XdpSocket> create_socket(uint16_t port);
    std::shared_ptr<EbpfProgram> load_program(const std::string& name, const std::string& filename);

    // CPU-Pinning und NUMA-Optimierungen
    bool pin_udp_threads_to_cores(const std::vector<int>& core_ids);
    bool setup_memory_numa_aware();

    // Performance-Tuning
    bool set_global_tx_burst_size(uint32_t burst_size);
    bool set_global_rx_ringsize(uint32_t ringsize);
    bool set_global_tx_ringsize(uint32_t ringsize);

private:
    QuicSandXdpContext() = default;
    ~QuicSandXdpContext();

    bool initialized_{false};
    std::string interface_;
    
    std::unordered_map<uint16_t, std::shared_ptr<XdpSocket>> sockets_;
    std::unordered_map<std::string, std::shared_ptr<EbpfProgram>> programs_;
    
    uint32_t global_tx_burst_size_{64};
    uint32_t global_rx_ringsize_{4096};
    uint32_t global_tx_ringsize_{4096};
    
    std::mutex mutex_;
};

} // namespace quicsand

#endif // EBPF_ZERO_COPY_HPP
