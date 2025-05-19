#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include <algorithm>

/**
 * Ein vereinfachter FEC-Test, der die grundlegende XOR-basierte Paketwiederherstellung testet
 * ohne die Komplexität der vollständigen Tetrys-Implementierung.
 */

// Einfaches XOR zweier Byte-Vektoren
std::vector<uint8_t> xor_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    size_t size = std::max(a.size(), b.size());
    std::vector<uint8_t> result(size, 0);
    
    // Kopiere erst den Vektor A
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i];
    }
    
    // XOR mit Vektor B
    for (size_t i = 0; i < b.size(); ++i) {
        result[i] ^= b[i];
    }
    
    return result;
}

// Hilfsfunktion zur Ausgabe eines Byte-Vektors
void print_buffer(const std::vector<uint8_t>& buffer, const std::string& label) {
    std::cout << label << " (size: " << buffer.size() << "): ";
    for (size_t i = 0; i < std::min(size_t(16), buffer.size()); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << (buffer.size() > 16 ? "..." : "") << std::endl;
}

// Simple Sharding-Funktion
std::vector<std::vector<uint8_t>> create_shards(const std::vector<uint8_t>& data, 
                                               int data_shards, int parity_shards) {
    int total_shards = data_shards + parity_shards;
    std::vector<std::vector<uint8_t>> shards(total_shards);
    
    // Berechne die Shard-Größe (abgerundet)
    size_t shard_size = data.size() / data_shards;
    if (data.size() % data_shards != 0) {
        shard_size++; // Runde auf, um alle Daten zu erfassen
    }
    
    // Erstelle Datenshards
    for (int i = 0; i < data_shards; ++i) {
        size_t start = i * shard_size;
        size_t end = std::min(start + shard_size, data.size());
        
        if (start < data.size()) {
            shards[i].assign(data.begin() + start, data.begin() + end);
            // Fülle mit Nullen auf, wenn nötig
            if (shards[i].size() < shard_size) {
                shards[i].resize(shard_size, 0);
            }
        } else {
            shards[i].resize(shard_size, 0); // Leerer Shard, falls nötig
        }
    }
    
    // Erstelle Paritätsshards
    for (int i = 0; i < parity_shards; ++i) {
        shards[data_shards + i].resize(shard_size, 0);
        
        // XOR aller Daten-Shards für jeden Paritäts-Shard
        // Für Einfachheit: Jeder Paritäts-Shard enthält alle Daten-Shards
        for (int j = 0; j < data_shards; ++j) {
            shards[data_shards + i] = xor_vectors(shards[data_shards + i], shards[j]);
        }
    }
    
    return shards;
}

// Einfache Wiederherstellungsfunktion
std::vector<uint8_t> recover_data(std::vector<std::vector<uint8_t>> shards, int data_shards) {
    int total_shards = shards.size();
    int parity_shards = total_shards - data_shards;
    
    // Bestimme fehlende und vorhandene Shards
    std::vector<int> present_indices;
    std::vector<int> missing_indices;
    
    for (int i = 0; i < total_shards; ++i) {
        if (!shards[i].empty()) {
            present_indices.push_back(i);
        } else if (i < data_shards) {
            missing_indices.push_back(i);
        }
    }
    
    if (present_indices.size() < static_cast<size_t>(data_shards)) {
        std::cout << "Zu wenige Shards vorhanden für Wiederherstellung" << std::endl;
        return {};
    }
    
    // Stelle jeden fehlenden Datenshard wieder her
    for (int missing_idx : missing_indices) {
        // Finde einen verfügbaren Paritätsshard
        for (int parity_idx = data_shards; parity_idx < total_shards; ++parity_idx) {
            if (std::find(present_indices.begin(), present_indices.end(), parity_idx) != present_indices.end()) {
                // Kopiere den Paritätsshard als Basis für die Wiederherstellung
                shards[missing_idx] = shards[parity_idx];
                
                // XOR mit allen vorhandenen Datenshards
                for (int data_idx = 0; data_idx < data_shards; ++data_idx) {
                    if (data_idx != missing_idx && 
                        std::find(present_indices.begin(), present_indices.end(), data_idx) != present_indices.end()) {
                        shards[missing_idx] = xor_vectors(shards[missing_idx], shards[data_idx]);
                    }
                }
                
                // Aktualisiere die Listen
                present_indices.push_back(missing_idx);
                present_indices.erase(std::remove(present_indices.begin(), present_indices.end(), parity_idx), 
                                     present_indices.end());
                break;
            }
        }
    }
    
    // Kombiniere die Datenshards
    std::vector<uint8_t> result;
    size_t shard_size = shards[0].size();
    result.reserve(data_shards * shard_size);
    
    for (int i = 0; i < data_shards; ++i) {
        result.insert(result.end(), shards[i].begin(), shards[i].end());
    }
    
    return result;
}

int main() {
    std::cout << "=== Einfacher FEC-Test gestartet ===" << std::endl;
    
    try {
        // Test-Parameter
        int data_shards = 4;
        int parity_shards = 2;
        std::vector<uint8_t> original_data(100);
        for (int i = 0; i < 100; i++) {
            original_data[i] = i;
        }
        
        print_buffer(original_data, "Original-Daten");
        
        // Erstelle Shards
        std::cout << "Erstelle " << data_shards << " Datenshards und " 
                  << parity_shards << " Paritätsshards" << std::endl;
        
        auto shards = create_shards(original_data, data_shards, parity_shards);
        
        // Ausgabe aller Shards
        for (size_t i = 0; i < shards.size(); ++i) {
            print_buffer(shards[i], "Shard " + std::to_string(i));
        }
        
        // Simuliere Paketverlust
        int lost_shard = 1; // Entferne den zweiten Shard (Index 1)
        std::cout << "Simuliere Paketverlust: Entferne Shard " << lost_shard << std::endl;
        shards[lost_shard].clear();
        
        // Wiederherstellung
        std::cout << "Wiederherstellung..." << std::endl;
        auto recovered_data = recover_data(shards, data_shards);
        
        print_buffer(recovered_data, "Wiederhergestellte Daten");
        
        // Überprüfe die Ergebnisse
        bool success = true;
        if (recovered_data.size() < original_data.size()) {
            std::cout << "FEHLER: Wiederhergestellte Daten zu kurz. Erwartet: " 
                      << original_data.size() << ", Erhalten: " << recovered_data.size() << std::endl;
            success = false;
        } else {
            for (size_t i = 0; i < original_data.size(); ++i) {
                if (recovered_data[i] != original_data[i]) {
                    std::cout << "FEHLER bei Position " << i << ": Erwartet: " 
                              << static_cast<int>(original_data[i]) << ", Erhalten: " 
                              << static_cast<int>(recovered_data[i]) << std::endl;
                    success = false;
                }
            }
        }
        
        if (success) {
            std::cout << "\n✅ Einfacher FEC-Test BESTANDEN!" << std::endl;
            return 0;
        } else {
            std::cout << "\n❌ Einfacher FEC-Test FEHLGESCHLAGEN!" << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "AUSNAHME: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "UNBEKANNTE AUSNAHME aufgetreten!" << std::endl;
        return 1;
    }
}
