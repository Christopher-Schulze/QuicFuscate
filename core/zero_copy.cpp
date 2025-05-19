#include "zero_copy.hpp"
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <iostream>

namespace quicsand {

// ------------------------- ZeroCopyBuffer Implementierung --------------------------

ZeroCopyBuffer::ZeroCopyBuffer(size_t max_iovecs)
    : max_iovecs_(max_iovecs), total_bytes_(0) {
    iovecs_.reserve(max_iovecs);
    buffers_.reserve(max_iovecs);
}

ZeroCopyBuffer::~ZeroCopyBuffer() {
    clear();
}

bool ZeroCopyBuffer::add_buffer(const void* data, size_t size, bool own_data) {
    if (!data || size == 0 || iovecs_.size() >= max_iovecs_) {
        return false;
    }
    
    void* buffer_data = const_cast<void*>(data);
    
    // Wenn wir die Daten besitzen sollen, erstellen wir eine Kopie
    if (own_data) {
        buffer_data = malloc(size);
        if (!buffer_data) {
            return false;
        }
        memcpy(buffer_data, data, size);
    }
    
    // Erstelle einen neuen Buffer und füge ihn zur Verwaltungsliste hinzu
    buffers_.push_back(std::make_unique<Buffer>(buffer_data, size, own_data));
    
    // Füge entsprechende iovec-Struktur hinzu
    struct iovec iov;
    iov.iov_base = buffer_data;
    iov.iov_len = size;
    iovecs_.push_back(iov);
    
    total_bytes_ += size;
    return true;
}

bool ZeroCopyBuffer::add_buffer(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return false;
    }
    
    // Erstelle eine Kopie des Vektors, da wir keine Garantie haben, dass der
    // Vektor während der gesamten Lebensdauer des Buffers existiert
    return add_buffer(data.data(), data.size(), true);
}

ssize_t ZeroCopyBuffer::send(int fd, int flags) {
    if (iovecs_.empty()) {
        return 0; // Keine Daten zum Senden
    }
    
    // Optimierte msghdr-Erstellung mit eingeschränkter iovec-Anzahl
    // Linux hat ein Limit von ca. 1024 iovecs pro sendmsg-Aufruf
    const size_t MAX_IOVECS_PER_CALL = 1024;
    ssize_t total_sent = 0;
    size_t remaining_iovecs = iovecs_.size();
    size_t current_index = 0;
    
    while (remaining_iovecs > 0) {
        // Bestimme die Anzahl der iovecs für diesen Aufruf
        size_t iovecs_to_send = std::min(remaining_iovecs, MAX_IOVECS_PER_CALL);
        
        struct msghdr msg;
        std::memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iovecs_[current_index];
        msg.msg_iovlen = iovecs_to_send;
        
        // Führe den sendmsg-Aufruf durch
        ssize_t sent = sendmsg(fd, &msg, flags);
        
        if (sent < 0) {
            // Fehler beim Senden
            if (total_sent > 0) {
                // Wir haben bereits einige Daten gesendet, geben diese Anzahl zurück
                return total_sent;
            }
            return sent; // Gib den Fehlercode zurück
        }
        
        total_sent += sent;
        
        // Berechne, wie viele vollständige iovecs wir verarbeitet haben
        size_t bytes_processed = 0;
        size_t iovecs_processed = 0;
        
        for (size_t i = current_index; i < current_index + iovecs_to_send && bytes_processed < static_cast<size_t>(sent); i++) {
            if (bytes_processed + iovecs_[i].iov_len <= static_cast<size_t>(sent)) {
                // Diese iovec wurde vollständig gesendet
                bytes_processed += iovecs_[i].iov_len;
                iovecs_processed++;
            } else {
                // Diese iovec wurde teilweise gesendet
                size_t bytes_sent_in_current = sent - bytes_processed;
                iovecs_[i].iov_base = static_cast<char*>(iovecs_[i].iov_base) + bytes_sent_in_current;
                iovecs_[i].iov_len -= bytes_sent_in_current;
                break;
            }
        }
        
        // Aktualisiere die verbleibenden iovecs und den Index
        current_index += iovecs_processed;
        remaining_iovecs -= iovecs_processed;
        
        // Wenn wir weniger als erwartet gesendet haben, brechen wir ab
        if (static_cast<size_t>(sent) < bytes_processed) {
            break;
        }
    }
    
    return total_sent;
}

ssize_t ZeroCopyBuffer::sendto(int fd, const struct sockaddr* dest, socklen_t dest_len, int flags) {
    if (!dest || iovecs_.empty()) {
        return 0; // Keine Daten zum Senden oder kein Ziel
    }
    
    // Optimierte msghdr-Erstellung mit eingeschränkter iovec-Anzahl
    // Linux hat ein Limit von ca. 1024 iovecs pro sendmsg-Aufruf
    const size_t MAX_IOVECS_PER_CALL = 1024;
    ssize_t total_sent = 0;
    size_t remaining_iovecs = iovecs_.size();
    size_t current_index = 0;
    
    while (remaining_iovecs > 0) {
        // Bestimme die Anzahl der iovecs für diesen Aufruf
        size_t iovecs_to_send = std::min(remaining_iovecs, MAX_IOVECS_PER_CALL);
        
        struct msghdr msg;
        std::memset(&msg, 0, sizeof(msg));
        msg.msg_name = const_cast<struct sockaddr*>(dest);
        msg.msg_namelen = dest_len;
        msg.msg_iov = &iovecs_[current_index];
        msg.msg_iovlen = iovecs_to_send;
        
        // Führe den sendmsg-Aufruf durch
        ssize_t sent = sendmsg(fd, &msg, flags);
        
        if (sent < 0) {
            // Fehler beim Senden
            if (total_sent > 0) {
                // Wir haben bereits einige Daten gesendet, geben diese Anzahl zurück
                return total_sent;
            }
            return sent; // Gib den Fehlercode zurück
        }
        
        total_sent += sent;
        
        // Berechne, wie viele vollständige iovecs wir verarbeitet haben
        size_t bytes_processed = 0;
        size_t iovecs_processed = 0;
        
        for (size_t i = current_index; i < current_index + iovecs_to_send && bytes_processed < static_cast<size_t>(sent); i++) {
            if (bytes_processed + iovecs_[i].iov_len <= static_cast<size_t>(sent)) {
                // Diese iovec wurde vollständig gesendet
                bytes_processed += iovecs_[i].iov_len;
                iovecs_processed++;
            } else {
                // Diese iovec wurde teilweise gesendet
                size_t bytes_sent_in_current = sent - bytes_processed;
                iovecs_[i].iov_base = static_cast<char*>(iovecs_[i].iov_base) + bytes_sent_in_current;
                iovecs_[i].iov_len -= bytes_sent_in_current;
                break;
            }
        }
        
        // Aktualisiere die verbleibenden iovecs und den Index
        current_index += iovecs_processed;
        remaining_iovecs -= iovecs_processed;
        
        // Wenn wir weniger als erwartet gesendet haben, brechen wir ab
        if (static_cast<size_t>(sent) < bytes_processed) {
            break;
        }
    }
    
    return total_sent;
}

void ZeroCopyBuffer::clear() {
    // Lösche alle Buffer und damit alle Daten, die wir besitzen
    buffers_.clear();
    
    // Lösche die iovec-Strukturen
    iovecs_.clear();
    
    total_bytes_ = 0;
}

size_t ZeroCopyBuffer::total_size() const {
    return total_bytes_;
}

size_t ZeroCopyBuffer::iovec_count() const {
    return iovecs_.size();
}

const struct iovec* ZeroCopyBuffer::iovecs() const {
    return iovecs_.data();
}

// ------------------------- ZeroCopyReceiver Implementierung --------------------------

ZeroCopyReceiver::ZeroCopyReceiver(size_t max_iovecs)
    : max_iovecs_(max_iovecs), total_bytes_(0) {
    iovecs_.reserve(max_iovecs);
}

ZeroCopyReceiver::~ZeroCopyReceiver() {
    clear();
}

bool ZeroCopyReceiver::add_buffer(void* buffer, size_t size) {
    if (!buffer || size == 0 || iovecs_.size() >= max_iovecs_) {
        return false;
    }
    
    // Füge iovec-Struktur hinzu
    struct iovec iov;
    iov.iov_base = buffer;
    iov.iov_len = size;
    iovecs_.push_back(iov);
    
    total_bytes_ += size;
    return true;
}

ssize_t ZeroCopyReceiver::receive(int fd, int flags) {
    if (iovecs_.empty()) {
        return 0; // Keine Puffer zum Empfangen
    }
    
    // Optimierte Version mit verbesserter Fehlerbehandlung
    // und Puffernutzung
    
    // Um Leistung zu maximieren, verwenden wir einen einzelnen recvmsg-Aufruf
    // aber analysieren das Ergebnis sorgfältig
    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    
    msg.msg_iov = iovecs_.data();
    msg.msg_iovlen = iovecs_.size();
    
    // Führe den recvmsg-Aufruf durch - hier erhalten wir maximale Leistung
    // durch Zero-Copy und Minimierung der Systemaufrufe
    ssize_t bytes_received = recvmsg(fd, &msg, flags);
    
    // Intelligente Fehlerbehandlung
    if (bytes_received < 0) {
        // Bei EAGAIN oder EWOULDBLOCK sind keine Daten verfügbar, was kein Fehler ist
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        // Bei anderen Fehlern geben wir den Fehlercode zurück
        return bytes_received;
    }
    
    // Bei 0 Bytes ist die Verbindung geschlossen
    if (bytes_received == 0) {
        return 0;
    }
    
    // Optional: Für Leistungsmetriken und Diagnostik
    // std::cout << "Received " << bytes_received << " bytes via Zero-Copy" << std::endl;
    
    return bytes_received;
}

ssize_t ZeroCopyReceiver::recvfrom(int fd, struct sockaddr* source, socklen_t* source_len, int flags) {
    if (!source || !source_len || iovecs_.empty()) {
        return 0; // Keine Puffer zum Empfangen oder keine Adressinfo
    }
    
    // Optimierte Version mit verbesserter Fehlerbehandlung
    // und Puffernutzung
    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    
    msg.msg_name = source;
    msg.msg_namelen = *source_len;
    msg.msg_iov = iovecs_.data();
    msg.msg_iovlen = iovecs_.size();
    
    // Führe den recvmsg-Aufruf durch
    ssize_t bytes_received = recvmsg(fd, &msg, flags);
    
    // Intelligente Fehlerbehandlung
    if (bytes_received < 0) {
        // Bei EAGAIN oder EWOULDBLOCK sind keine Daten verfügbar, was kein Fehler ist
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        // Bei anderen Fehlern geben wir den Fehlercode zurück
        return bytes_received;
    }
    
    // Bei 0 Bytes ist die Verbindung geschlossen
    if (bytes_received == 0) {
        return 0;
    }
    
    // Aktualisiere die Länge der Quelladresse
    *source_len = msg.msg_namelen;
    
    return bytes_received;
}

void ZeroCopyReceiver::clear() {
    iovecs_.clear();
    total_bytes_ = 0;
}

size_t ZeroCopyReceiver::total_size() const {
    return total_bytes_;
}

size_t ZeroCopyReceiver::iovec_count() const {
    return iovecs_.size();
}

const struct iovec* ZeroCopyReceiver::iovecs() const {
    return iovecs_.data();
}

// ------------------------- MemoryPool Implementierung --------------------------

MemoryPool::MemoryPool(size_t block_size, size_t initial_blocks, size_t max_blocks)
    : block_size_(block_size),
      available_count_(0),
      allocated_count_(0),
      max_blocks_(max_blocks),
      free_list_(nullptr) {
    // Initialisiere den Pool mit der angegebenen Anzahl von Blöcken
    grow(initial_blocks);
}

MemoryPool::~MemoryPool() {
    // Gebe alle Blöcke frei
    for (void* block : all_blocks_) {
        free(block);
    }
    all_blocks_.clear();
    free_list_ = nullptr;
}

void* MemoryPool::allocate() {
    if (free_list_ == nullptr) {
        // Der Pool ist leer, wir müssen ihn vergrößern
        
        // Überprüfe, ob wir unter dem Limit sind
        if (max_blocks_ > 0 && available_count_ + allocated_count_ >= max_blocks_) {
            // Maximale Blockanzahl erreicht
            return nullptr;
        }
        
        // Optimiertes Wachstum: Verdopple die Größe des Pools bis zu einem Maximum
        // für bessere Skalierung bei hoher Last
        size_t current_size = available_count_ + allocated_count_;
        size_t growth_size = std::min(
            current_size > 0 ? current_size : 4, // Beginne mit 4, dann verdopple
            max_blocks_ > 0 ? max_blocks_ - current_size : 64 // Bis zu max_blocks_ oder 64
        );
        
        // Versuche, den Pool zu vergrößern
        if (grow(growth_size) == 0) {
            // Konnte nicht vergrößern
            return nullptr;
        }
    }
    
    // Hole einen Block von der freien Liste
    PoolBlock* block = free_list_;
    free_list_ = free_list_->next;
    
    available_count_--;
    allocated_count_++;
    
    // Konvertiere den Blockzeiger zu einem Datenzeiger
    return block->data;
}

void MemoryPool::deallocate(void* block) {
    if (!block) {
        return;
    }
    
    // Erstelle einen neuen PoolBlock und füge ihn zur freien Liste hinzu
    PoolBlock* pool_block = new PoolBlock;
    pool_block->data = block;
    pool_block->next = free_list_;
    free_list_ = pool_block;
    
    available_count_++;
    allocated_count_--;
}

size_t MemoryPool::block_size() const {
    return block_size_;
}

size_t MemoryPool::available_blocks() const {
    return available_count_;
}

size_t MemoryPool::allocated_blocks() const {
    return allocated_count_;
}

size_t MemoryPool::grow(size_t additional_blocks) {
    // Überprüfe zuerst, ob wir überhaupt wachsen können
    if (additional_blocks == 0) {
        return 0;
    }
    
    // Begrenze das Wachstum auf das festgelegte Maximum
    if (max_blocks_ > 0) {
        size_t max_additional = max_blocks_ > (available_count_ + allocated_count_) ?
                               max_blocks_ - (available_count_ + allocated_count_) : 0;
        additional_blocks = std::min(additional_blocks, max_additional);
        
        if (additional_blocks == 0) {
            return 0; // Nichts zu tun
        }
    }
    
    // Optimiere die Block-Allokation indem wir alle Blöcke auf einmal reservieren
    // Dies kann effizienter sein als viele einzelne allocs
    std::vector<PoolBlock*> new_blocks;
    new_blocks.reserve(additional_blocks);
    std::vector<void*> new_data;
    new_data.reserve(additional_blocks);
    
    // Allociere alle Datenblöcke
    bool allocation_failed = false;
    for (size_t i = 0; i < additional_blocks; i++) {
        void* data = nullptr;
        
        // Verwende posix_memalign für Seiten-ausgerichteten Speicher, wenn der Block groß genug ist
        // Dies kann die Cache-Effizienz und DMA-Operationen verbessern
        if (block_size_ >= 4096) { // Seitengröße
            if (posix_memalign(&data, 4096, block_size_) != 0) {
                allocation_failed = true;
                break;
            }
        } else {
            data = malloc(block_size_);
            if (!data) {
                allocation_failed = true;
                break;
            }
        }
        
        new_data.push_back(data);
    }
    
    // Allokiere alle Block-Strukturen
    if (!allocation_failed) {
        for (size_t i = 0; i < additional_blocks; i++) {
            PoolBlock* block = new PoolBlock;
            if (!block) {
                allocation_failed = true;
                break;
            }
            new_blocks.push_back(block);
        }
    }
    
    // Wenn irgendeine Allokation fehlgeschlagen ist, bereinigen und Fehler zurückgeben
    if (allocation_failed) {
        // Freigabe aller bereits allozierten Ressourcen
        for (auto& block : new_blocks) {
            delete block;
        }
        for (auto& data : new_data) {
            free(data);
        }
        return 0;
    }
    
    // Verknüpfe die Blöcke miteinander in die Free-Liste
    for (size_t i = 0; i < additional_blocks; i++) {
        PoolBlock* block = new_blocks[i];
        block->data = new_data[i];
        block->next = free_list_;
        free_list_ = block;
        
        // Speichere den Blockzeiger für späteres Freigeben
        all_blocks_.push_back(new_data[i]);
    }
    
    available_count_ += additional_blocks;
    return additional_blocks;
}

size_t MemoryPool::shrink(size_t target_blocks) {
    if (target_blocks >= (available_count_ + allocated_count_)) {
        return 0;
    }
    
    // Berechne, wie viele Blöcke entfernt werden müssen
    size_t blocks_to_remove = (available_count_ + allocated_count_) - target_blocks;
    
    // Begrenze die Entfernung auf verfügbare (nicht allokierte) Blöcke
    blocks_to_remove = std::min(blocks_to_remove, available_count_);
    
    size_t removed_blocks = 0;
    
    while (removed_blocks < blocks_to_remove && free_list_) {
        // Entferne einen Block aus der freien Liste
        PoolBlock* block = free_list_;
        free_list_ = block->next;
        
        // Finde den Block in all_blocks_ und entferne ihn
        auto it = std::find(all_blocks_.begin(), all_blocks_.end(), block->data);
        if (it != all_blocks_.end()) {
            free(*it);
            all_blocks_.erase(it);
        }
        
        delete block;
        removed_blocks++;
    }
    
    available_count_ -= removed_blocks;
    return removed_blocks;
}

} // namespace quicsand
