#ifndef SESSION_TICKET_MANAGER_HPP
#define SESSION_TICKET_MANAGER_HPP

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <chrono>
#include <openssl/ssl.h>

namespace quicsand {

/**
 * SessionTicketManager - Verwaltet TLS-SessionTickets für die Wiederaufnahme von Verbindungen
 * 
 * Diese Klasse speichert und verwaltet TLS-SessionTickets, die von Servern ausgestellt werden.
 * Diese Tickets werden für die schnelle Wiederaufnahme von TLS-Verbindungen verwendet, ohne
 * einen vollständigen Handshake durchführen zu müssen. Die Implementierung ahmt das Verhalten
 * echter Browser nach, um die Stealth-Fähigkeiten zu verbessern.
 */
class SessionTicketManager {
public:
    // Singleton-Zugriff
    static SessionTicketManager& getInstance();
    
    // Vormals ausgestelltes Ticket für eine Domain abrufen
    SSL_SESSION* getSession(const std::string& hostname);
    
    // Ein neues Ticket speichern
    void storeSession(const std::string& hostname, SSL_SESSION* session);
    
    // Ticket für eine Domain löschen
    void removeSession(const std::string& hostname);
    
    // Alle abgelaufenen Tickets löschen
    void cleanupExpiredSessions();
    
    // Anzahl der aktuell gespeicherten Tickets
    size_t getSessionCount() const;
    
    // Maximale Anzahl von Tickets pro Domain setzen
    void setMaxTicketsPerDomain(size_t max);
    
    // Maximale Gesamtzahl der gespeicherten Tickets setzen
    void setMaxTotalTickets(size_t max);
    
private:
    // Private Konstruktoren für Singleton-Pattern
    SessionTicketManager();
    ~SessionTicketManager();
    
    // Multi-Map, die Hostnamen auf Session-Tickets abbildet
    // Ein Hostname kann mehrere Session-Tickets haben (mehrere Fenster/Tabs)
    std::multimap<std::string, std::pair<SSL_SESSION*, std::chrono::steady_clock::time_point>> sessions_;
    
    // Mutex für Thread-Sicherheit
    mutable std::mutex mutex_;
    
    // Konfigurationsparameter
    size_t max_tickets_per_domain_;
    size_t max_total_tickets_;
    
    // Private Methoden
    void enforceTicketLimits();
};

} // namespace quicsand

#endif // SESSION_TICKET_MANAGER_HPP
