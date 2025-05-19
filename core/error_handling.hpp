#ifndef ERROR_HANDLING_HPP
#define ERROR_HANDLING_HPP

#include <string>
#include <optional>
#include <variant>
#include <functional>
#include <iostream>
#include <memory>
#include <map>
#include <chrono>
#include <mutex>
#include <vector>

namespace quicsand {

/**
 * @brief Kategorie für Fehler in QuicSand
 */
enum class ErrorCategory {
    NONE,               // Kein Fehler
    NETWORK,            // Netzwerkbezogene Fehler
    CRYPTO,             // Kryptographiebezogene Fehler
    PROTOCOL,           // Protokollverletzungen (QUIC, HTTP)
    SYSTEM,             // Systemfehler (Speicher, Dateien, etc.)
    CONFIGURATION,      // Konfigurationsfehler
    RUNTIME,            // Laufzeitfehler
    EXTERNAL,           // Fehler von externen Bibliotheken/APIs
    INTERNAL            // Interne Fehler
};

/**
 * @brief Fehlercode für spezifische Fehlertypen
 */
enum class ErrorCode {
    // Allgemeine Fehlercodes (0-99)
    SUCCESS = 0,                    // Erfolg (kein Fehler)
    UNKNOWN_ERROR = 1,              // Unbekannter Fehler
    NOT_IMPLEMENTED = 2,            // Funktion nicht implementiert
    INVALID_ARGUMENT = 3,           // Ungültiges Argument
    OPERATION_FAILED = 4,           // Operation fehlgeschlagen
    TIMED_OUT = 5,                  // Timeout
    
    // Netzwerkfehlercodes (100-199)
    NETWORK_BASE = 100,
    CONNECTION_FAILED = 101,        // Verbindung fehlgeschlagen
    CONNECTION_CLOSED = 102,        // Verbindung geschlossen
    CONNECTION_TIMEOUT = 103,       // Verbindungs-Timeout
    INVALID_PACKET = 104,           // Ungültiges Paket
    PACKET_TOO_LARGE = 105,         // Paket zu groß
    MTU_BLACKHOLE = 106,            // MTU Blackhole erkannt
    SOCKET_ERROR = 107,             // Socket-Fehler
    DNS_FAILURE = 108,              // DNS-Auflösungsfehler
    
    // Kryptographiefehlercodes (200-299)
    CRYPTO_BASE = 200,
    HANDSHAKE_FAILED = 201,         // TLS-Handshake fehlgeschlagen
    CERTIFICATE_ERROR = 202,        // Zertifikatsfehler
    KEY_GENERATION_FAILED = 203,    // Schlüsselgenerierung fehlgeschlagen
    ENCRYPTION_FAILED = 204,        // Verschlüsselung fehlgeschlagen
    DECRYPTION_FAILED = 205,        // Entschlüsselung fehlgeschlagen
    INTEGRITY_CHECK_FAILED = 206,   // Integritätsprüfung fehlgeschlagen
    
    // Protokollfehlercodes (300-399)
    PROTOCOL_BASE = 300,
    INVALID_STATE = 301,            // Ungültiger Zustand
    PROTOCOL_VIOLATION = 302,       // Protokollverletzung
    STREAM_ERROR = 303,             // Stream-Fehler
    FLOW_CONTROL_ERROR = 304,       // Flow-Control-Fehler
    FRAME_ERROR = 305,              // Frame-Fehler
    TRANSPORT_ERROR = 306,          // Transport-Fehler
    
    // Systemfehlercodes (400-499)
    SYSTEM_BASE = 400,
    MEMORY_ALLOCATION_FAILED = 401, // Speicherallokation fehlgeschlagen
    FILE_IO_ERROR = 402,            // Datei-I/O-Fehler
    RESOURCE_LIMIT_REACHED = 403,   // Ressourcenlimit erreicht
    PERMISSION_DENIED = 404,        // Berechtigung verweigert
    
    // Konfigurationsfehlercodes (500-599)
    CONFIG_BASE = 500,
    INVALID_CONFIGURATION = 501,    // Ungültige Konfiguration
    MISSING_CONFIGURATION = 502,    // Fehlende Konfiguration
    
    // Laufzeitfehlercodes (600-699)
    RUNTIME_BASE = 600,
    INVALID_OPERATION = 601,        // Ungültige Operation
    INVALID_HANDLE = 602,           // Ungültiger Handle
    
    // Externe Fehler (700-799)
    EXTERNAL_BASE = 700,
    EXTERNAL_LIBRARY_ERROR = 701,   // Fehler in externer Bibliothek
    API_ERROR = 702,                // API-Fehler
    
    // Interne Fehler (800-899)
    INTERNAL_BASE = 800,
    ASSERTION_FAILED = 801,         // Assertion fehlgeschlagen
    INVARIANT_VIOLATED = 802,       // Invariante verletzt
    LOGIC_ERROR = 803               // Logikfehler
};

/**
 * @brief Struktur zur Beschreibung eines Fehlers
 */
struct ErrorInfo {
    ErrorCategory category;            // Fehlerkategorie
    ErrorCode code;                    // Fehlercode
    std::string message;               // Fehlermeldung
    std::string file;                  // Dateiname, wo der Fehler auftrat
    int line;                          // Zeilennummer, wo der Fehler auftrat
    std::optional<uint64_t> connection_id; // Optional: Verbindungs-ID
    std::optional<uint64_t> stream_id;     // Optional: Stream-ID
    std::chrono::system_clock::time_point timestamp; // Zeitstempel
    
    // Konstruktor für einfache Verwendung
    ErrorInfo(
        ErrorCategory cat = ErrorCategory::NONE,
        ErrorCode err_code = ErrorCode::SUCCESS,
        const std::string& msg = "",
        const std::string& src_file = "",
        int src_line = 0,
        std::optional<uint64_t> conn_id = std::nullopt,
        std::optional<uint64_t> str_id = std::nullopt
    ) : category(cat),
        code(err_code),
        message(msg),
        file(src_file),
        line(src_line),
        connection_id(conn_id),
        stream_id(str_id),
        timestamp(std::chrono::system_clock::now()) {}
        
    // Helfer für formatierte Ausgabe
    std::string to_string() const {
        std::string result = "[" + category_to_string(category) + "] ";
        result += code_to_string(code) + ": " + message;
        
        if (connection_id.has_value()) {
            result += " (Connection ID: " + std::to_string(connection_id.value()) + ")";
        }
        
        if (stream_id.has_value()) {
            result += " (Stream ID: " + std::to_string(stream_id.value()) + ")";
        }
        
        if (!file.empty()) {
            result += " at " + file + ":" + std::to_string(line);
        }
        
        return result;
    }
    
    // Helfer zur Konvertierung von Kategorie zu String
    static std::string category_to_string(ErrorCategory cat) {
        switch (cat) {
            case ErrorCategory::NONE: return "NONE";
            case ErrorCategory::NETWORK: return "NETWORK";
            case ErrorCategory::CRYPTO: return "CRYPTO";
            case ErrorCategory::PROTOCOL: return "PROTOCOL";
            case ErrorCategory::SYSTEM: return "SYSTEM";
            case ErrorCategory::CONFIGURATION: return "CONFIG";
            case ErrorCategory::RUNTIME: return "RUNTIME";
            case ErrorCategory::EXTERNAL: return "EXTERNAL";
            case ErrorCategory::INTERNAL: return "INTERNAL";
            default: return "UNKNOWN";
        }
    }
    
    // Helfer zur Konvertierung von ErrorCode zu String
    static std::string code_to_string(ErrorCode code) {
        switch (code) {
            case ErrorCode::SUCCESS: return "SUCCESS";
            case ErrorCode::UNKNOWN_ERROR: return "UNKNOWN_ERROR";
            case ErrorCode::NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
            case ErrorCode::INVALID_ARGUMENT: return "INVALID_ARGUMENT";
            case ErrorCode::OPERATION_FAILED: return "OPERATION_FAILED";
            case ErrorCode::TIMED_OUT: return "TIMED_OUT";
            
            // Netzwerkfehlercodes
            case ErrorCode::CONNECTION_FAILED: return "CONNECTION_FAILED";
            case ErrorCode::CONNECTION_CLOSED: return "CONNECTION_CLOSED";
            case ErrorCode::CONNECTION_TIMEOUT: return "CONNECTION_TIMEOUT";
            case ErrorCode::INVALID_PACKET: return "INVALID_PACKET";
            case ErrorCode::PACKET_TOO_LARGE: return "PACKET_TOO_LARGE";
            case ErrorCode::MTU_BLACKHOLE: return "MTU_BLACKHOLE";
            case ErrorCode::SOCKET_ERROR: return "SOCKET_ERROR";
            case ErrorCode::DNS_FAILURE: return "DNS_FAILURE";
            
            // Kryptographiefehlercodes
            case ErrorCode::HANDSHAKE_FAILED: return "HANDSHAKE_FAILED";
            case ErrorCode::CERTIFICATE_ERROR: return "CERTIFICATE_ERROR";
            case ErrorCode::KEY_GENERATION_FAILED: return "KEY_GENERATION_FAILED";
            case ErrorCode::ENCRYPTION_FAILED: return "ENCRYPTION_FAILED";
            case ErrorCode::DECRYPTION_FAILED: return "DECRYPTION_FAILED";
            case ErrorCode::INTEGRITY_CHECK_FAILED: return "INTEGRITY_CHECK_FAILED";
            
            // Protokollfehlercodes
            case ErrorCode::INVALID_STATE: return "INVALID_STATE";
            case ErrorCode::PROTOCOL_VIOLATION: return "PROTOCOL_VIOLATION";
            case ErrorCode::STREAM_ERROR: return "STREAM_ERROR";
            case ErrorCode::FLOW_CONTROL_ERROR: return "FLOW_CONTROL_ERROR";
            case ErrorCode::FRAME_ERROR: return "FRAME_ERROR";
            case ErrorCode::TRANSPORT_ERROR: return "TRANSPORT_ERROR";
            
            // Systemfehlercodes
            case ErrorCode::MEMORY_ALLOCATION_FAILED: return "MEMORY_ALLOCATION_FAILED";
            case ErrorCode::FILE_IO_ERROR: return "FILE_IO_ERROR";
            case ErrorCode::RESOURCE_LIMIT_REACHED: return "RESOURCE_LIMIT_REACHED";
            case ErrorCode::PERMISSION_DENIED: return "PERMISSION_DENIED";
            
            // Konfigurationsfehlercodes
            case ErrorCode::INVALID_CONFIGURATION: return "INVALID_CONFIGURATION";
            case ErrorCode::MISSING_CONFIGURATION: return "MISSING_CONFIGURATION";
            
            // Laufzeitfehlercodes
            case ErrorCode::INVALID_OPERATION: return "INVALID_OPERATION";
            case ErrorCode::INVALID_HANDLE: return "INVALID_HANDLE";
            
            // Externe Fehler
            case ErrorCode::EXTERNAL_LIBRARY_ERROR: return "EXTERNAL_LIBRARY_ERROR";
            case ErrorCode::API_ERROR: return "API_ERROR";
            
            // Interne Fehler
            case ErrorCode::ASSERTION_FAILED: return "ASSERTION_FAILED";
            case ErrorCode::INVARIANT_VIOLATED: return "INVARIANT_VIOLATED";
            case ErrorCode::LOGIC_ERROR: return "LOGIC_ERROR";
            
            default: return "ERROR_" + std::to_string(static_cast<int>(code));
        }
    }
};

/**
 * @brief Result-Klasse für Operationen, die fehlschlagen können
 * 
 * Diese Klasse implementiert ein ähnliches Konzept wie std::expected (C++23)
 * oder rust::Result und erlaubt die Rückgabe von entweder einem Wert oder
 * einem Fehlerobjekt.
 * 
 * Beispielverwendung:
 * ```
 * Result<int> divide(int a, int b) {
 *     if (b == 0) {
 *         return Error(ErrorCategory::RUNTIME, ErrorCode::INVALID_ARGUMENT, "Division by zero");
 *     }
 *     return a / b;
 * }
 * 
 * // Verwendung:
 * auto result = divide(10, 2);
 * if (result) {
 *     int value = result.value();
 *     // ...
 * } else {
 *     auto error = result.error();
 *     std::cerr << error.to_string() << std::endl;
 * }
 * ```
 */
template <typename T>
class Result {
public:
    // Konstruktoren
    
    // Erfolgsfall: Wert speichern
    Result(T value) : variant_(std::move(value)) {}
    
    // Fehlerfall: ErrorInfo speichern
    Result(ErrorInfo error) : variant_(std::move(error)) {}
    
    // Prüfen, ob Erfolg
    bool success() const {
        return std::holds_alternative<T>(variant_);
    }
    
    // Operatorversion von success()
    explicit operator bool() const {
        return success();
    }
    
    // Zugriff auf den Wert (wirft bei Fehler)
    T& value() & {
        if (!success()) {
            throw std::runtime_error("Attempted to access value of failed Result");
        }
        return std::get<T>(variant_);
    }
    
    const T& value() const & {
        if (!success()) {
            throw std::runtime_error("Attempted to access value of failed Result");
        }
        return std::get<T>(variant_);
    }
    
    T&& value() && {
        if (!success()) {
            throw std::runtime_error("Attempted to access value of failed Result");
        }
        return std::move(std::get<T>(variant_));
    }
    
    // Zugriff auf den Fehler (wirft bei Erfolg)
    ErrorInfo& error() & {
        if (success()) {
            throw std::runtime_error("Attempted to access error of successful Result");
        }
        return std::get<ErrorInfo>(variant_);
    }
    
    const ErrorInfo& error() const & {
        if (success()) {
            throw std::runtime_error("Attempted to access error of successful Result");
        }
        return std::get<ErrorInfo>(variant_);
    }
    
    // Zugriff auf den Wert mit Fallback bei Fehler
    T value_or(T default_value) const {
        if (success()) {
            return std::get<T>(variant_);
        }
        return default_value;
    }
    
    // Transformiere den Wert bei Erfolg
    template <typename U, typename Func>
    Result<U> map(Func&& func) const {
        if (success()) {
            try {
                return Result<U>(func(std::get<T>(variant_)));
            } catch (const std::exception& e) {
                return Result<U>(ErrorInfo(
                    ErrorCategory::RUNTIME, 
                    ErrorCode::OPERATION_FAILED,
                    std::string("Exception in map function: ") + e.what()
                ));
            }
        }
        return Result<U>(std::get<ErrorInfo>(variant_));
    }
    
    // Flache Transformation (wenn Func ein Result zurückgibt)
    template <typename U, typename Func>
    Result<U> and_then(Func&& func) const {
        if (success()) {
            try {
                return func(std::get<T>(variant_));
            } catch (const std::exception& e) {
                return Result<U>(ErrorInfo(
                    ErrorCategory::RUNTIME, 
                    ErrorCode::OPERATION_FAILED,
                    std::string("Exception in and_then function: ") + e.what()
                ));
            }
        }
        return Result<U>(std::get<ErrorInfo>(variant_));
    }
    
private:
    std::variant<T, ErrorInfo> variant_;
};

// Spezialfall für void-Rückgabewerte
template <>
class Result<void> {
public:
    // Konstruktoren
    
    // Erfolgsfall
    Result() : success_(true), error_() {}
    
    // Fehlerfall
    Result(ErrorInfo error) : success_(false), error_(std::move(error)) {}
    
    // Prüfen, ob Erfolg
    bool success() const {
        return success_;
    }
    
    // Operatorversion von success()
    explicit operator bool() const {
        return success_;
    }
    
    // Wert "zugreifen" (tut nichts, aber konsistent mit dem generischen Fall)
    void value() const {
        if (!success_) {
            throw std::runtime_error("Attempted to access value of failed Result<void>");
        }
    }
    
    // Zugriff auf den Fehler
    ErrorInfo& error() & {
        if (success_) {
            throw std::runtime_error("Attempted to access error of successful Result<void>");
        }
        return error_;
    }
    
    const ErrorInfo& error() const & {
        if (success_) {
            throw std::runtime_error("Attempted to access error of successful Result<void>");
        }
        return error_;
    }
    
    // Transformiere das Ergebnis, falls erfolgreich
    template <typename U, typename Func>
    Result<U> map(Func&& func) const {
        if (success_) {
            try {
                return Result<U>(func());
            } catch (const std::exception& e) {
                return Result<U>(ErrorInfo(
                    ErrorCategory::RUNTIME, 
                    ErrorCode::OPERATION_FAILED,
                    std::string("Exception in map function: ") + e.what()
                ));
            }
        }
        return Result<U>(error_);
    }
    
    // Flache Transformation
    template <typename U, typename Func>
    Result<U> and_then(Func&& func) const {
        if (success_) {
            try {
                return func();
            } catch (const std::exception& e) {
                return Result<U>(ErrorInfo(
                    ErrorCategory::RUNTIME, 
                    ErrorCode::OPERATION_FAILED,
                    std::string("Exception in and_then function: ") + e.what()
                ));
            }
        }
        return Result<U>(error_);
    }
    
private:
    bool success_;
    ErrorInfo error_;
};

// Hilfsfunktion zur Erstellung eines Errors
inline ErrorInfo make_error(
    ErrorCategory category,
    ErrorCode code,
    const std::string& message,
    const std::string& file = "",
    int line = 0,
    std::optional<uint64_t> connection_id = std::nullopt,
    std::optional<uint64_t> stream_id = std::nullopt
) {
    return ErrorInfo(category, code, message, file, line, connection_id, stream_id);
}

// Erfolgs-Helfer für void-Rückgabewerte
inline Result<void> success() {
    return Result<void>();
}

// Makros für Quelldatei-Informationen
#define MAKE_ERROR(category, code, message, ...) \
    make_error(category, code, message, __FILE__, __LINE__, ##__VA_ARGS__)

/**
 * @brief Manager für Fehlerverarbeitung und -statistik
 * 
 * Diese Klasse sammelt Fehler, führt Statistiken und kann Callbacks für
 * bestimmte Fehlertypen auslösen.
 */
class ErrorManager {
public:
    // Singelton-Zugriff
    static ErrorManager& instance() {
        static ErrorManager instance;
        return instance;
    }
    
    // Melde einen Fehler
    void report_error(const ErrorInfo& error) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Fehler speichern
        recent_errors_.push_back(error);
        if (recent_errors_.size() > max_recent_errors_) {
            recent_errors_.erase(recent_errors_.begin());
        }
        
        // Statistiken aktualisieren
        error_counts_[error.category]++;
        error_code_counts_[error.code]++;
        
        // Fehler loggen
        if (log_errors_) {
            std::cerr << "ERROR: " << error.to_string() << std::endl;
        }
        
        // Callbacks für diese Fehlerkategorie auslösen
        auto it = callbacks_.find(error.category);
        if (it != callbacks_.end()) {
            for (const auto& callback : it->second) {
                callback(error);
            }
        }
        
        // Callbacks für diesen spezifischen Fehlercode auslösen
        auto code_it = code_callbacks_.find(error.code);
        if (code_it != code_callbacks_.end()) {
            for (const auto& callback : code_it->second) {
                callback(error);
            }
        }
    }
    
    // Füge einen Callback für eine Fehlerkategorie hinzu
    void add_callback(ErrorCategory category, std::function<void(const ErrorInfo&)> callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_[category].push_back(callback);
    }
    
    // Füge einen Callback für einen spezifischen Fehlercode hinzu
    void add_callback(ErrorCode code, std::function<void(const ErrorInfo&)> callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        code_callbacks_[code].push_back(callback);
    }
    
    // Aktiviere/Deaktiviere Fehlerlogging
    void set_logging(bool enable) {
        std::lock_guard<std::mutex> lock(mutex_);
        log_errors_ = enable;
    }
    
    // Hole Fehlerstatistiken
    std::map<ErrorCategory, uint64_t> get_category_counts() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return error_counts_;
    }
    
    std::map<ErrorCode, uint64_t> get_code_counts() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return error_code_counts_;
    }
    
    // Hole kürzliche Fehler
    std::vector<ErrorInfo> get_recent_errors() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return recent_errors_;
    }
    
    // Lösche alle Fehlerstatistiken
    void clear_stats() {
        std::lock_guard<std::mutex> lock(mutex_);
        error_counts_.clear();
        error_code_counts_.clear();
        recent_errors_.clear();
    }
    
private:
    // Privater Konstruktor für Singleton
    ErrorManager() : log_errors_(true), max_recent_errors_(100) {}
    
    // Standardmäßig bis zu 100 kürzliche Fehler speichern
    size_t max_recent_errors_;
    
    // Fehlerstatistiken
    mutable std::mutex mutex_;
    std::map<ErrorCategory, uint64_t> error_counts_;
    std::map<ErrorCode, uint64_t> error_code_counts_;
    std::vector<ErrorInfo> recent_errors_;
    
    // Callbacks für Fehlerkategorien
    std::map<ErrorCategory, std::vector<std::function<void(const ErrorInfo&)>>> callbacks_;
    
    // Callbacks für spezifische Fehlercodes
    std::map<ErrorCode, std::vector<std::function<void(const ErrorInfo&)>>> code_callbacks_;
    
    // Flag für Fehlerlogging
    bool log_errors_;
};

// Hilfsfunktion zum Melden eines Fehlers
inline void report_error(const ErrorInfo& error) {
    ErrorManager::instance().report_error(error);
}

// Makro zum Melden eines Fehlers mit Quelldatei-Informationen
#define REPORT_ERROR(category, code, message, ...) \
    report_error(MAKE_ERROR(category, code, message, ##__VA_ARGS__))

} // namespace quicsand

#endif // ERROR_HANDLING_HPP
