#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include "fec/tetrys_fec.hpp"

void print_buffer(const std::vector<uint8_t>& buffer, const std::string& label) {
    std::cout << label << " (size: " << buffer.size() << "): ";
    for (size_t i = 0; i < std::min(size_t(16), buffer.size()); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << (buffer.size() > 16 ? "..." : "") << std::endl;
}

int main() {
    std::cout << "=== Tetrys FEC Test gestartet ===" << std::endl;
    try {
        using namespace quicsand;
        
        std::cout << "Initialisierung..." << std::endl;
        int data_shards = 4;
        int parity_shards = 2;
        std::vector<uint8_t> data(100);
        for (int i = 0; i < 100; i++) data[i] = i;
        
        print_buffer(data, "Original data");
        
        std::cout << "Erstelle FEC mit " << data_shards << " Datenshards und " 
                  << parity_shards << " Paritätsshards..." << std::endl;
        TetrysFEC fec(data_shards, parity_shards);
        
        std::cout << "Encodierung..." << std::endl;
        auto coded = fec.encode(data);
        if (coded.empty()) {
            std::cout << "FEHLER: Encodierung fehlgeschlagen (leeres Ergebnis)" << std::endl;
            return 1;
        }
        print_buffer(coded, "Encoded data");
        
        // Shards aufteilen
        std::cout << "Aufteilung in Shards..." << std::endl;
        int total = data_shards + parity_shards;
        int shard_size = coded.size() / total;
        std::cout << "Shard size: " << shard_size << " bytes" << std::endl;
        
        std::vector<std::vector<uint8_t>> shards(total);
        for (int i = 0; i < total; i++) {
            shards[i].assign(coded.begin() + i*shard_size, coded.begin() + (i+1)*shard_size);
            print_buffer(shards[i], "Shard " + std::to_string(i));
        }
        
        // Simuliere Paketverlust (lösche einen Shard)
        int lost_shard = 1; // Entferne den zweiten Shard (Index 1)
        std::cout << "Simuliere Paketverlust: Entferne Shard " << lost_shard << std::endl;
        shards[lost_shard].clear();
        
        std::cout << "Decodierung..." << std::endl;
        auto decoded = fec.decode(shards);
        print_buffer(decoded, "Decoded data");
        
        if (decoded.size() != (size_t)data_shards * shard_size) {
            std::cout << "FEHLER: Decodierte Größe stimmt nicht überein. Erwartet: " 
                      << (size_t)data_shards * shard_size << ", Erhalten: " << decoded.size() << std::endl;
            return 1;
        }
        
        // Überprüfe, ob die ersten 100 Bytes korrekt wiederhergestellt wurden
        bool match = true;
        for (int i = 0; i < 100 && i < static_cast<int>(decoded.size()); i++) {
            if (decoded[i] != data[i]) {
                std::cout << "FEHLER: Daten an Position " << i << " stimmen nicht überein. "
                          << "Erwartet: " << (int)data[i] << ", Erhalten: " << (int)decoded[i] << std::endl;
                match = false;
                break;
            }
        }
        
        if (match) {
            std::cout << "\n✅ FEC encode/decode Test BESTANDEN! Die Daten wurden erfolgreich wiederhergestellt." << std::endl;
        } else {
            std::cout << "\n❌ FEC Test FEHLGESCHLAGEN!" << std::endl;
            return 1;
        }
        
        // Zusätzlicher Test mit mehreren verlorenen Paketen
        std::cout << "\n=== Erweiterte Tests mit mehreren verlorenen Paketen ===" << std::endl;
        
        // Neuinitialisierung für den zweiten Test
        std::vector<std::vector<uint8_t>> shards2(total);
        for (int i = 0; i < total; i++) {
            shards2[i].assign(coded.begin() + i*shard_size, coded.begin() + (i+1)*shard_size);
        }
        
        // Simuliere Verlust von mehreren Paketen (max. parity_shards)
        std::cout << "Simuliere Verlust von " << parity_shards << " Paketen..." << std::endl;
        for (int i = 0; i < parity_shards; i++) {
            shards2[i].clear();
            std::cout << "Shard " << i << " entfernt." << std::endl;
        }
        
        auto decoded2 = fec.decode(shards2);
        print_buffer(decoded2, "Decoded data (multiple losses)");
        
        bool match2 = true;
        for (int i = 0; i < 100 && i < static_cast<int>(decoded2.size()); i++) {
            if (decoded2[i] != data[i]) {
                std::cout << "FEHLER im erweiterten Test: Daten an Position " << i << " stimmen nicht überein." << std::endl;
                match2 = false;
                break;
            }
        }
        
        if (match2) {
            std::cout << "\n✅ Erweiterter FEC Test BESTANDEN! Daten wurden nach Verlust von " 
                      << parity_shards << " Paketen wiederhergestellt." << std::endl;
        } else {
            std::cout << "\n❌ Erweiterter FEC Test FEHLGESCHLAGEN!" << std::endl;
            return 1;
        }
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "AUSNAHME: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "UNBEKANNTE AUSNAHME aufgetreten!" << std::endl;
        return 1;
    }
}
