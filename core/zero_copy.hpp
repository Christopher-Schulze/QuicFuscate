#ifndef ZERO_COPY_HPP
#define ZERO_COPY_HPP

#include <vector>
#include <memory>
#include <functional>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cstdint>

namespace quicsand {

/**
 * ZeroCopyBuffer implementiert einen Zero-Copy-Puffer für optimierte Datenübertragungen.
 * Anstatt Daten mehrfach zu kopieren, werden sie direkt aus Quellpuffern in die Socket-Operationen übertragen.
 */
class ZeroCopyBuffer {
public:
    /**
     * Konstruktor
     * @param max_iovecs Maximale Anzahl von iovec-Strukturen (Scatter-Gather-Array-Größe)
     */
    explicit ZeroCopyBuffer(size_t max_iovecs = 16);
    
    /**
     * Destruktor
     */
    ~ZeroCopyBuffer();
    
    /**
     * Fügt einen Datenblock zum Zero-Copy-Puffer hinzu
     * @param data Zeiger auf die Daten
     * @param size Größe des Datenblocks in Bytes
     * @param own_data Falls true, wird eine Kopie der Daten erstellt und verwaltet
     * @return true wenn erfolgreich, false bei Fehler oder wenn max_iovecs erreicht ist
     */
    bool add_buffer(const void* data, size_t size, bool own_data = false);
    
    /**
     * Fügt einen Vektor zum Zero-Copy-Puffer hinzu
     * @param data Vektor mit den Daten
     * @return true wenn erfolgreich, false bei Fehler
     */
    bool add_buffer(const std::vector<uint8_t>& data);
    
    /**
     * Führt eine Zero-Copy-Sendeoperation aus
     * @param fd Socket-Deskriptor
     * @param flags Flags für sendmsg
     * @return Anzahl gesendeter Bytes oder -1 bei Fehler
     */
    ssize_t send(int fd, int flags = 0);
    
    /**
     * Führt eine Zero-Copy-Sendeoperation an eine Zieladresse aus
     * @param fd Socket-Deskriptor
     * @param dest Zieladresse
     * @param flags Flags für sendmsg
     * @return Anzahl gesendeter Bytes oder -1 bei Fehler
     */
    ssize_t sendto(int fd, const struct sockaddr* dest, socklen_t dest_len, int flags = 0);
    
    /**
     * Löscht alle Puffer und setzt den Zustand zurück
     */
    void clear();
    
    /**
     * Gibt die Gesamtgröße aller Puffer zurück
     * @return Summe der Größen aller Puffer in Bytes
     */
    size_t total_size() const;
    
    /**
     * Gibt die Anzahl der aktuell verwendeten iovec-Strukturen zurück
     * @return Anzahl der iovec-Strukturen
     */
    size_t iovec_count() const;
    
    /**
     * Gibt das iovec-Array für direkte Verwendung zurück
     * @return Zeiger auf das iovec-Array
     */
    const struct iovec* iovecs() const;
    
private:
    struct Buffer {
        void* data;
        size_t size;
        bool owned;
        
        Buffer(void* d, size_t s, bool o) : data(d), size(s), owned(o) {}
        ~Buffer() {
            if (owned && data) {
                free(data);
            }
        }
    };
    
    std::vector<struct iovec> iovecs_;
    std::vector<std::unique_ptr<Buffer>> buffers_;
    size_t max_iovecs_;
    size_t total_bytes_;
};

/**
 * ZeroCopyReceiver implementiert eine Zero-Copy-Empfangsfunktionalität.
 * Erlaubt das Lesen von Daten direkt in mehrere vorallokierte Puffer ohne zusätzliche Kopieroperationen.
 */
class ZeroCopyReceiver {
public:
    /**
     * Konstruktor
     * @param max_iovecs Maximale Anzahl von iovec-Strukturen (Scatter-Gather-Array-Größe)
     */
    explicit ZeroCopyReceiver(size_t max_iovecs = 16);
    
    /**
     * Destruktor
     */
    ~ZeroCopyReceiver();
    
    /**
     * Fügt einen Empfangspuffer hinzu
     * @param buffer Zeiger auf den Puffer
     * @param size Größe des Puffers in Bytes
     * @return true wenn erfolgreich, false bei Fehler
     */
    bool add_buffer(void* buffer, size_t size);
    
    /**
     * Führt eine Zero-Copy-Empfangsoperation aus
     * @param fd Socket-Deskriptor
     * @param flags Flags für recvmsg
     * @return Anzahl empfangener Bytes oder -1 bei Fehler
     */
    ssize_t receive(int fd, int flags = 0);
    
    /**
     * Führt eine Zero-Copy-Empfangsoperation aus und gibt die Quelladresse zurück
     * @param fd Socket-Deskriptor
     * @param source Quelladresse (Ausgabeparameter)
     * @param source_len Länge der Quelladresse (Ein- und Ausgabeparameter)
     * @param flags Flags für recvmsg
     * @return Anzahl empfangener Bytes oder -1 bei Fehler
     */
    ssize_t recvfrom(int fd, struct sockaddr* source, socklen_t* source_len, int flags = 0);
    
    /**
     * Löscht alle Puffer und setzt den Zustand zurück
     */
    void clear();
    
    /**
     * Gibt die Gesamtgröße aller Puffer zurück
     * @return Summe der Größen aller Puffer in Bytes
     */
    size_t total_size() const;
    
    /**
     * Gibt die Anzahl der aktuell verwendeten iovec-Strukturen zurück
     * @return Anzahl der iovec-Strukturen
     */
    size_t iovec_count() const;
    
    /**
     * Gibt das iovec-Array für direkte Verwendung zurück
     * @return Zeiger auf das iovec-Array
     */
    const struct iovec* iovecs() const;
    
private:
    std::vector<struct iovec> iovecs_;
    size_t max_iovecs_;
    size_t total_bytes_;
};

/**
 * MemoryPool implementiert einen Pool für effiziente Speicherverwaltung.
 * Stellt vorallokierte Puffer bereit, um wiederholte Allokationen zu vermeiden.
 */
class MemoryPool {
public:
    /**
     * Konstruktor
     * @param block_size Größe eines einzelnen Blocks in Bytes
     * @param initial_blocks Anfängliche Anzahl von Blöcken im Pool
     * @param max_blocks Maximale Anzahl von Blöcken im Pool (0 = unbegrenzt)
     */
    MemoryPool(size_t block_size = 4096, size_t initial_blocks = 16, size_t max_blocks = 0);
    
    /**
     * Destruktor
     */
    ~MemoryPool();
    
    /**
     * Allokiert einen Speicherblock aus dem Pool
     * @return Zeiger auf den Speicherblock oder nullptr bei Fehler
     */
    void* allocate();
    
    /**
     * Gibt einen Speicherblock an den Pool zurück
     * @param block Zeiger auf den Speicherblock
     */
    void deallocate(void* block);
    
    /**
     * Gibt die Größe eines Blocks zurück
     * @return Block-Größe in Bytes
     */
    size_t block_size() const;
    
    /**
     * Gibt die Anzahl der verfügbaren Blöcke zurück
     * @return Anzahl der Blöcke im Pool
     */
    size_t available_blocks() const;
    
    /**
     * Gibt die Anzahl der aktuell allokierten Blöcke zurück
     * @return Anzahl der allokierten Blöcke
     */
    size_t allocated_blocks() const;
    
    /**
     * Vergrößert den Pool um eine bestimmte Anzahl von Blöcken
     * @param additional_blocks Anzahl der hinzuzufügenden Blöcke
     * @return Anzahl der tatsächlich hinzugefügten Blöcke
     */
    size_t grow(size_t additional_blocks);
    
    /**
     * Verkleinert den Pool auf eine bestimmte Anzahl von Blöcken
     * (berücksichtigt nur verfügbare, nicht allokierte Blöcke)
     * @param target_blocks Zielanzahl von Blöcken im Pool
     * @return Anzahl der entfernten Blöcke
     */
    size_t shrink(size_t target_blocks);
    
private:
    struct PoolBlock {
        void* data;
        PoolBlock* next;
    };
    
    size_t block_size_;
    size_t available_count_;
    size_t allocated_count_;
    size_t max_blocks_;
    PoolBlock* free_list_;
    std::vector<void*> all_blocks_; // Für die Speicherverwaltung
};

} // namespace quicsand

#endif // ZERO_COPY_HPP
