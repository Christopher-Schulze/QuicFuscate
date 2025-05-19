#ifndef SESSION_TICKET_UTILS_HPP
#define SESSION_TICKET_UTILS_HPP

#include "session_ticket_manager.hpp"

/**
 * Hilfsfunktionen für die Verwendung des SessionTicketManager
 * ohne explizite Namespace-Qualifizierung
 */
namespace SessionTicketUtils {

// Helferfunktion für den Zugriff auf die SessionTicketManager-Singleton-Instanz
inline quicsand::SessionTicketManager& getManager() {
    return quicsand::SessionTicketManager::getInstance();
}

// Speichert ein Session-Ticket für eine bestimmte Domain
inline void storeSessionTicket(const std::string& hostname, SSL_SESSION* session) {
    getManager().storeSession(hostname, session);
}

// Holt ein bereits gespeichertes Session-Ticket für eine Domain
inline SSL_SESSION* getSessionTicket(const std::string& hostname) {
    return getManager().getSession(hostname);
}

// Entfernt ein Session-Ticket für eine Domain
inline void removeSessionTicket(const std::string& hostname) {
    getManager().removeSession(hostname);
}

// Bereinigt abgelaufene Session-Tickets
inline void cleanupExpiredTickets() {
    getManager().cleanupExpiredSessions();
}

// Gibt die Anzahl der aktuell gespeicherten Tickets zurück
inline size_t getTicketCount() {
    return getManager().getSessionCount();
}

// Setzt das maximale Limit für Tickets pro Domain
inline void setMaxTicketsPerDomain(size_t max) {
    getManager().setMaxTicketsPerDomain(max);
}

// Setzt das maximale Limit für die Gesamtzahl der Tickets
inline void setMaxTotalTickets(size_t max) {
    getManager().setMaxTotalTickets(max);
}

} // namespace SessionTicketUtils

#endif // SESSION_TICKET_UTILS_HPP
