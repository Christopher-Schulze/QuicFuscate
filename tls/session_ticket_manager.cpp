#include "session_ticket_manager.hpp"
#include <algorithm>
#include <iostream>

namespace quicsand {

// Singleton-Zugriff
SessionTicketManager& SessionTicketManager::getInstance() {
    static SessionTicketManager instance;
    return instance;
}

// Konstruktor
SessionTicketManager::SessionTicketManager()
    : max_tickets_per_domain_(2),  // Standard: 2 Tickets pro Domain (typisch für Browser)
      max_total_tickets_(100)      // Standard: 100 Tickets insgesamt
{
    // Zufallsgenerator initialisieren (für die Simulation von Browser-Verhalten)
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
}

// Destruktor - alle Sessions freigeben
SessionTicketManager::~SessionTicketManager() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& entry : sessions_) {
        if (entry.second.first != nullptr) {
            SSL_SESSION_free(entry.second.first);
        }
    }
    
    sessions_.clear();
}

// Vormals ausgestelltes Ticket für eine Domain abrufen
SSL_SESSION* SessionTicketManager::getSession(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Überprüfen auf abgelaufene Sessions
    cleanupExpiredSessions();
    
    // Range von Einträgen für diesen Hostnamen finden
    auto range = sessions_.equal_range(hostname);
    
    // Wenn keine Sessions gefunden wurden, null zurückgeben
    if (range.first == range.second) {
        return nullptr;
    }
    
    // In einem echten Browser würde meist das neueste Ticket verwendet
    // Wir simulieren dies, indem wir das letzte Element im Range nehmen
    auto it = range.first;
    std::advance(it, std::distance(range.first, range.second) - 1);
    
    // Manchmal verwenden Browser auch ältere Tickets (z.B. wenn mehrere Tabs geöffnet sind)
    // Wir simulieren dies durch gelegentliche zufällige Auswahl eines anderen Tickets
    if (std::distance(range.first, range.second) > 1 && (std::rand() % 5 == 0)) {
        size_t random_index = std::rand() % std::distance(range.first, range.second);
        it = range.first;
        std::advance(it, random_index);
    }
    
    return it->second.first;
}

// Ein neues Ticket speichern
void SessionTicketManager::storeSession(const std::string& hostname, SSL_SESSION* session) {
    if (session == nullptr) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Referenzzähler erhöhen, da wir eine Kopie halten
    SSL_SESSION_up_ref(session);
    
    // Speichere Session mit aktuellem Zeitstempel
    sessions_.insert(std::make_pair(
        hostname, 
        std::make_pair(session, std::chrono::steady_clock::now())
    ));
    
    // Überprüfe Limits und bereinige falls nötig
    enforceTicketLimits();
}

// Ticket für eine Domain löschen
void SessionTicketManager::removeSession(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto range = sessions_.equal_range(hostname);
    
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second.first != nullptr) {
            SSL_SESSION_free(it->second.first);
        }
    }
    
    sessions_.erase(range.first, range.second);
}

// Alle abgelaufenen Tickets löschen
void SessionTicketManager::cleanupExpiredSessions() {
    // Diese Methode sollte bereits unter einem Mutex-Lock aufgerufen werden
    
    auto now = std::chrono::steady_clock::now();
    
    // Echte TLS-Session-Tickets haben typischerweise eine Lebensdauer von 24 Stunden
    auto expiry_duration = std::chrono::hours(24);
    
    // Einige Server verwenden kürzere Zeiträume, wir könnten das auch simulieren
    if (std::rand() % 10 == 0) {
        expiry_duration = std::chrono::hours(4); // Kürzere Lebensdauer, wie bei einigen CDNs
    }
    
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        // Prüfe, ob das Ticket abgelaufen ist
        if (now - it->second.second > expiry_duration) {
            // Freigeben des SSL_SESSION-Objekts
            if (it->second.first != nullptr) {
                SSL_SESSION_free(it->second.first);
            }
            
            // Eintrag entfernen
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

// Anzahl der aktuell gespeicherten Tickets
size_t SessionTicketManager::getSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

// Maximale Anzahl von Tickets pro Domain setzen
void SessionTicketManager::setMaxTicketsPerDomain(size_t max) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_tickets_per_domain_ = max;
    enforceTicketLimits();
}

// Maximale Gesamtzahl der gespeicherten Tickets setzen
void SessionTicketManager::setMaxTotalTickets(size_t max) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_total_tickets_ = max;
    enforceTicketLimits();
}

// Private Hilfsmethode: Stellt sicher, dass die Ticket-Limits eingehalten werden
void SessionTicketManager::enforceTicketLimits() {
    // Erst die globalen Limits überprüfen
    while (sessions_.size() > max_total_tickets_) {
        // Das älteste Ticket finden und entfernen (ältester Zeitstempel)
        auto oldest_it = sessions_.begin();
        auto oldest_time = oldest_it->second.second;
        
        for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
            if (it->second.second < oldest_time) {
                oldest_it = it;
                oldest_time = it->second.second;
            }
        }
        
        // Ticket freigeben
        if (oldest_it->second.first != nullptr) {
            SSL_SESSION_free(oldest_it->second.first);
        }
        
        // Aus der Map entfernen
        sessions_.erase(oldest_it);
    }
    
    // Jetzt die Limits pro Domain überprüfen
    std::map<std::string, size_t> domain_counts;
    
    // Zähle Tickets pro Domain
    for (const auto& entry : sessions_) {
        domain_counts[entry.first]++;
    }
    
    // Überprüfe jede Domain und entferne überzählige Tickets
    for (const auto& count_entry : domain_counts) {
        if (count_entry.second > max_tickets_per_domain_) {
            const std::string& domain = count_entry.first;
            size_t tickets_to_remove = count_entry.second - max_tickets_per_domain_;
            
            // Finde alle Tickets für diese Domain
            auto range = sessions_.equal_range(domain);
            
            // Sammle die Einträge, sortiere sie nach Zeitstempel
            std::vector<std::multimap<std::string, 
                std::pair<SSL_SESSION*, std::chrono::steady_clock::time_point>>::iterator> domain_entries;
                
            for (auto it = range.first; it != range.second; ++it) {
                domain_entries.push_back(it);
            }
            
            // Sortiere nach Zeitstempel (älteste zuerst)
            std::sort(domain_entries.begin(), domain_entries.end(),
                [](const auto& a, const auto& b) {
                    return a->second.second < b->second.second;
                });
            
            // Entferne die ältesten Tickets
            for (size_t i = 0; i < tickets_to_remove && i < domain_entries.size(); ++i) {
                if (domain_entries[i]->second.first != nullptr) {
                    SSL_SESSION_free(domain_entries[i]->second.first);
                }
                sessions_.erase(domain_entries[i]);
            }
        }
    }
}

} // namespace quicsand
