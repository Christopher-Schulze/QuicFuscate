# QuicSand Optimierungen API-Dokumentation

Diese Dokumentation beschreibt die Performance-Optimierungen der QuicSand-Bibliothek.

## Überblick

Die QuicSand-Bibliothek enthält verschiedene Optimierungen, um die Leistung zu verbessern, Energieverbrauch zu reduzieren und Cache-Nutzung zu maximieren. Besonderer Fokus liegt auf ARM-Optimierungen für Apple M1/M2 Prozessoren mit SIMD-Vektorisierung (NEON) und Crypto-Erweiterungen.

## Performance-Optimierungen

### 1. Cache-Optimierungen

Die Cache-Optimierungskomponenten verbessern die Cache-Lokalität und reduzieren Cache-Misses.

```cpp
// Cache-Line-Größe für gängige CPUs
constexpr size_t CACHE_LINE_SIZE = 64;

// Cache-optimierter Vektor
template <typename T, size_t BlockSize = (CACHE_LINE_SIZE / sizeof(T))>
class CacheOptimizedVector {
public:
    // Konstruktoren und Standard-Container-Funktionen
    
    // Element-Zugriff
    reference operator[](size_type index);
    const_reference operator[](size_type index) const;
    
    // Kapazitätsverwaltung
    void reserve(size_type n);
    void resize(size_type new_size);
    
    // Modifikatoren
    void push_back(const T& value);
    void push_back(T&& value);
    void pop_back();
};

// Prefetcher für Cache-optimierten Zugriff
class Prefetcher {
public:
    enum class PrefetchType { READ, WRITE };
    enum class PrefetchLocality { NONE, LOW, MODERATE, HIGH };
    
    static void prefetch(const void* addr, 
                       PrefetchType type = PrefetchType::READ,
                       PrefetchLocality locality = PrefetchLocality::MODERATE);
                       
    static void prefetch_range(const void* addr, size_t size_bytes,
                             PrefetchType type = PrefetchType::READ,
                             PrefetchLocality locality = PrefetchLocality::MODERATE);
                             
    template <typename T>
    static void prefetch_array(const T* array, size_t count,
                             PrefetchType type = PrefetchType::READ,
                             PrefetchLocality locality = PrefetchLocality::MODERATE);
};

// Cache-aligned Klasse zur Vermeidung von False Sharing
template <typename T>
class alignas(CACHE_LINE_SIZE) CacheAlignedAtomic {
public:
    // Atomare Operationen mit Padding zur Vermeidung von False Sharing
};
```

#### Beispiel
```cpp
// Cache-optimierten Vektor erstellen
CacheOptimizedVector<uint8_t> packet_data;
packet_data.reserve(1500); // Typische MTU-Größe

// Daten hinzufügen
for (size_t i = 0; i < 1000; ++i) {
    packet_data.push_back(static_cast<uint8_t>(i & 0xFF));
}

// Prefetching für bessere Performance
Prefetcher::prefetch_array(packet_data.data(), packet_data.size());

// Cache-aligned Atome für multi-threaded Zähler
CacheAlignedAtomic<uint64_t> packet_counter(0);
```

### 2. Energieoptimierungen

Die Energieoptimierungsklassen verbessern die Energieeffizienz, insbesondere auf mobilen Geräten.

```cpp
// Energiemodi für verschiedene Leistungs-/Effizienz-Abwägungen
enum class ThreadEnergyMode {
    PERFORMANCE,  // Maximale Leistung, hoher Energieverbrauch
    BALANCED,     // Ausgeglichenes Verhältnis
    EFFICIENT,    // Energieeffizient, möglicherweise auf Kosten der Leistung
    ULTRA_EFFICIENT // Maximale Energieeinsparung, minimale Leistung
};

// Konfiguration für Energieoptimierung
struct EnergyConfig {
    ThreadEnergyMode thread_mode = ThreadEnergyMode::BALANCED;
    bool enable_adaptive_polling = true;
    bool enable_arm_specific_optimizations = true;
    int idle_spin_count = 1000;
    std::chrono::milliseconds min_sleep_duration{1};
    std::chrono::milliseconds max_sleep_duration{100};
};

// Manager für energieeffiziente Threads
class EnergyManager {
public:
    EnergyManager();
    explicit EnergyManager(const EnergyConfig& config);
    
    void configure(const EnergyConfig& config);
    void set_thread_mode(ThreadEnergyMode mode);
    
    template<typename Predicate>
    bool wait_efficiently(Predicate predicate, 
                         std::chrono::milliseconds timeout_ms = std::chrono::milliseconds::max());
                         
    void optimize_for_arm();
    
    ThreadEnergyMode get_thread_mode() const;
};

// Energieeffizienter Thread-Pool
class EnergyEfficientWorkerPool {
public:
    explicit EnergyEfficientWorkerPool(
        size_t num_threads = std::thread::hardware_concurrency(),
        ThreadEnergyMode mode = ThreadEnergyMode::BALANCED);
        
    void enqueue(std::function<void()> task);
    void set_energy_mode(ThreadEnergyMode mode);
};
```

#### Beispiel
```cpp
// Energiekonfiguration erstellen
EnergyConfig config;
config.thread_mode = ThreadEnergyMode::EFFICIENT;
config.enable_arm_specific_optimizations = true; // Für Apple M1/M2

// Energy Manager initialisieren
EnergyManager energy_manager(config);

// Effizientes Warten auf eine Bedingung
std::atomic<bool> condition{false};
std::thread worker([&]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    condition = true;
});

energy_manager.wait_efficiently([&]() {
    return condition.load();
});

worker.join();

// Energieeffizienten Thread-Pool verwenden
EnergyEfficientWorkerPool pool(4, ThreadEnergyMode::BALANCED);

for (int i = 0; i < 10; ++i) {
    pool.enqueue([i]() {
        // Aufgabe ausführen...
        std::cout << "Task " << i << " ausgeführt." << std::endl;
    });
}

// In den Energiesparmodus wechseln, wenn weniger Arbeit anfällt
pool.set_energy_mode(ThreadEnergyMode::EFFICIENT);
```

### 3. Zero-Copy-Optimierungen

Die Zero-Copy-Klassen ermöglichen die Datenübertragung ohne unnötige Kopieroperationen.

```cpp
// Grundlegender Zero-Copy-Buffer
class ZeroCopyBuffer {
public:
    explicit ZeroCopyBuffer(size_t max_iovecs = 16);
    
    bool add_buffer(const void* data, size_t size, bool own_data = false);
    bool add_buffer(const std::vector<uint8_t>& data);
    
    ssize_t send(int fd, int flags = 0);
    ssize_t sendto(int fd, const struct sockaddr* dest, socklen_t dest_len, int flags = 0);
    
    void clear();
    size_t total_size() const;
    size_t iovec_count() const;
    const struct iovec* iovecs() const;
};

// Cache-optimierte Zero-Copy-Erweiterung
class OptimizedZeroCopyBuffer : public ZeroCopyBuffer {
public:
    OptimizedZeroCopyBuffer(
        size_t max_iovecs = 16,
        const CacheOptimizationConfig& cache_config = CacheOptimizationConfig());
        
    bool add_buffer_optimized(
        const void* data, 
        size_t size, 
        bool own_data = false,
        bool prefetch = true);
        
    ssize_t send_optimized(int fd, int flags = 0);
    
    void set_cache_config(const CacheOptimizationConfig& config);
};

// Energieeffiziente Memory-Pool-Erweiterung
class EnergyEfficientMemoryPool : public MemoryPool {
public:
    EnergyEfficientMemoryPool(
        size_t block_size = 4096,
        size_t initial_blocks = 16,
        size_t max_blocks = 0,
        const EnergyConfig& energy_config = EnergyConfig());
        
    void* allocate_optimized();
    void free_optimized(void* block);
    
    void set_energy_mode(ThreadEnergyMode mode);
};
```

#### Beispiel
```cpp
// Optimierten Zero-Copy-Buffer erstellen
OptimizedZeroCopyBuffer buffer;

// Daten hinzufügen mit Prefetching
std::vector<uint8_t> packet_data = generate_packet();
buffer.add_buffer_optimized(packet_data.data(), packet_data.size(), false, true);

// Socket erstellen
int sock = socket(AF_INET, SOCK_DGRAM, 0);
struct sockaddr_in dest_addr = create_destination_address();

// Daten senden mit optimiertem Zero-Copy
ssize_t bytes_sent = buffer.send_optimized(sock);

// Speicherpool mit Energieoptimierung
EnergyEfficientMemoryPool pool(2048, 32);

// Speicher allokieren
void* data = pool.allocate_optimized();

// Energiemodus ändern basierend auf Batteriestatus
if (is_battery_low()) {
    pool.set_energy_mode(ThreadEnergyMode::ULTRA_EFFICIENT);
}

// Speicher freigeben
pool.free_optimized(data);
```

### 4. Optimizations Manager

Der `OptimizationsManager` bietet eine zentrale Schnittstelle für alle Performance-Optimierungen.

```cpp
// Zentrale Konfiguration für alle Optimierungen
struct OptimizationsConfig {
    CacheOptimizationConfig cache_config;
    ThreadOptimizationConfig thread_config;
    EnergyConfig energy_config;
    
    // Factory-Methoden für typische Szenarien
    static OptimizationsConfig create_default();
    static OptimizationsConfig create_for_mobile();
    static OptimizationsConfig create_for_server();
};

// Zentrale Verwaltung aller Optimierungen
class OptimizationsManager {
public:
    explicit OptimizationsManager(
        const OptimizationsConfig& config = OptimizationsConfig::create_default()
    );
    
    // Konfiguration aktualisieren
    void set_config(const OptimizationsConfig& config);
    
    // Verschiedene Komponenten optimieren
    void optimize_connection(QuicConnection& connection);
    void optimize_mtu_manager(PathMtuManager& mtu_manager);
    
    // Optimierte Ressourcen erstellen
    std::unique_ptr<EnergyEfficientWorkerPool> create_optimized_worker_pool(
        size_t num_threads = std::thread::hardware_concurrency()
    );
    
    template <typename T>
    CacheOptimizedVector<T> create_optimized_buffer(size_t initial_capacity = 1500);
    
    // Zugriff auf spezialisierte Manager
    EnergyManager& get_energy_manager();
};
```

#### Beispiel
```cpp
// Mobile-optimierte Konfiguration erstellen
auto config = OptimizationsConfig::create_for_mobile();

// OptimizationsManager initialisieren
OptimizationsManager opt_manager(config);

// QUIC-Verbindung optimieren
QuicConnection connection(true);
opt_manager.optimize_connection(connection);

// MTU-Manager optimieren
PathMtuManager mtu_manager(connection);
opt_manager.optimize_mtu_manager(mtu_manager);

// Optimierten Worker-Pool erstellen
auto worker_pool = opt_manager.create_optimized_worker_pool(4);

// Optimierten Buffer erstellen
auto packet_buffer = opt_manager.create_optimized_buffer<uint8_t>(2048);

// Energieoptimierung anpassen
if (is_battery_low()) {
    opt_manager.get_energy_manager().set_thread_mode(ThreadEnergyMode::ULTRA_EFFICIENT);
}
```

## Integrationsbeispiele

### Performance-Optimierungen in QUIC-Verbindungen

```cpp
// Optimierungskonfiguration für Apple M1/M2
auto config = OptimizationsConfig::create_for_mobile();
config.energy_config.enable_arm_specific_optimizations = true;

// OptimizationsManager initialisieren
OptimizationsManager opt_manager(config);

// QUIC-Verbindung mit Zero-Copy erstellen
QuicConnection connection(true);
opt_manager.optimize_connection(connection);

// Optimierten Worker-Pool für Paketverarbeitung erstellen
auto worker_pool = opt_manager.create_optimized_worker_pool();

// Verbindung herstellen
if (!connection.connect("example.com", 443)) {
    std::cerr << "Verbindungsfehler!" << std::endl;
    return 1;
}

// Daten mit Zero-Copy senden
std::vector<uint8_t> data = prepare_data();
connection.send_packet_zero_copy(data.data(), data.size());

// Energiesparmodus aktivieren, wenn keine aktiven Transfers
worker_pool->set_energy_mode(ThreadEnergyMode::EFFICIENT);

// Auf Antwort warten mit Energieoptimierung
std::atomic<bool> response_received{false};
worker_pool->enqueue([&]() {
    auto result = connection.receive_data(2048);
    if (result) {
        process_response(result.value());
    }
    response_received = true;
});

// Effizient warten
opt_manager.get_energy_manager().wait_efficiently([&]() {
    return response_received.load();
});

// Verbindung schließen
connection.disconnect();
```

### Benchmark und Optimierung

```cpp
// Benchmarking-Funktion
template<typename Func>
double measure_execution_time(Func&& func, int iterations = 1) {
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        func();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    return static_cast<double>(duration) / iterations;
}

// Standard-Implementierung vs. optimierte Implementierung vergleichen
void benchmark_optimizations() {
    const size_t data_size = 1500;
    std::vector<uint8_t> test_data(data_size, 0x42);
    
    // 1. Standard-Vektor
    auto standard_test = [&test_data]() {
        std::vector<uint8_t> copy = test_data;
        for (size_t i = 0; i < copy.size(); ++i) {
            copy[i] = copy[i] ^ 0xFF;
        }
        return copy;
    };
    
    // 2. Cache-optimierter Vektor
    auto optimized_test = [&test_data]() {
        CacheOptimizedVector<uint8_t> copy;
        copy.reserve(test_data.size());
        for (auto byte : test_data) {
            copy.push_back(byte);
        }
        
        Prefetcher::prefetch_array(copy.data(), copy.size());
        
        for (size_t i = 0; i < copy.size(); ++i) {
            copy[i] = copy[i] ^ 0xFF;
        }
        return copy;
    };
    
    // Benchmark ausführen
    const int iterations = 10000;
    double standard_time = measure_execution_time(standard_test, iterations);
    double optimized_time = measure_execution_time(optimized_test, iterations);
    
    std::cout << "Standard-Vektor: " << standard_time << " µs" << std::endl;
    std::cout << "Optimierter Vektor: " << optimized_time << " µs" << std::endl;
    std::cout << "Speedup: " << (standard_time / optimized_time) << "x" << std::endl;
}
```
