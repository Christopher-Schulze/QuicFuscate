/**
 * @file browser_fingerprint.hpp
 * @brief Browser-Fingerprint-Funktionalitu00e4t fu00fcr Stealth-Features
 */

#pragma once

#include <string>
#include <map>
#include <vector>

namespace quicfuscate {
namespace stealth {

/**
 * @brief Repru00e4sentiert einen Browser-Fingerprint fu00fcr Stealth-Funktionalitu00e4t
 * 
 * Diese Klasse enthu00e4lt die Parameter, die einen bestimmten Browser-Fingerprint
 * charakterisieren, wie User-Agent, TLS-Funktionen, HTTP-Header-Reihenfolge usw.
 */
class BrowserFingerprint {
public:
    /**
     * @brief Browser-Typen
     */
    enum class BrowserType {
        CHROME,         // Google Chrome
        FIREFOX,        // Mozilla Firefox
        SAFARI,         // Apple Safari
        EDGE,           // Microsoft Edge
        OPERA,          // Opera
        BRAVE,          // Brave
        UNKNOWN         // Unbekannter Browser
    };

    /**
     * @brief Betriebssystem-Typen
     */
    enum class OSType {
        WINDOWS,        // Microsoft Windows
        MACOS,          // Apple macOS
        LINUX,          // Linux
        IOS,            // Apple iOS
        ANDROID,        // Android
        UNKNOWN         // Unbekanntes Betriebssystem
    };

    /**
     * @brief Standardkonstruktor
     */
    BrowserFingerprint() : browser_type_(BrowserType::CHROME), os_type_(OSType::MACOS) {}

    /**
     * @brief Konstruktor mit spezifischen Parametern
     * 
     * @param browser_type Der Browser-Typ
     * @param os_type Das Betriebssystem
     * @param user_agent Der User-Agent-String
     */
    BrowserFingerprint(
        BrowserType browser_type,
        OSType os_type,
        const std::string& user_agent)
        : browser_type_(browser_type),
          os_type_(os_type),
          user_agent_(user_agent) {}

    /**
     * @brief Getter fu00fcr den Browser-Typ
     * 
     * @return Der Browser-Typ
     */
    BrowserType get_browser_type() const { return browser_type_; }

    /**
     * @brief Setter fu00fcr den Browser-Typ
     * 
     * @param browser_type Der neue Browser-Typ
     */
    void set_browser_type(BrowserType browser_type) { browser_type_ = browser_type; }

    /**
     * @brief Getter fu00fcr den Betriebssystem-Typ
     * 
     * @return Der Betriebssystem-Typ
     */
    OSType get_os_type() const { return os_type_; }

    /**
     * @brief Setter fu00fcr den Betriebssystem-Typ
     * 
     * @param os_type Der neue Betriebssystem-Typ
     */
    void set_os_type(OSType os_type) { os_type_ = os_type; }

    /**
     * @brief Getter fu00fcr den User-Agent
     * 
     * @return Der User-Agent-String
     */
    const std::string& get_user_agent() const { return user_agent_; }

    /**
     * @brief Setter fu00fcr den User-Agent
     * 
     * @param user_agent Der neue User-Agent-String
     */
    void set_user_agent(const std::string& user_agent) { user_agent_ = user_agent; }

    /**
     * @brief Generiert typische HTTP-Header fu00fcr den Browser-Fingerprint
     * 
     * @return Eine Map von Header-Namen zu Header-Werten
     */
    std::map<std::string, std::string> generate_http_headers() const {
        std::map<std::string, std::string> headers;
        
        // Fu00fcge Standard-Header hinzu
        headers["User-Agent"] = user_agent_;
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
        headers["Accept-Language"] = "en-US,en;q=0.5";
        headers["Accept-Encoding"] = "gzip, deflate, br";
        headers["Connection"] = "keep-alive";
        headers["Upgrade-Insecure-Requests"] = "1";
        
        return headers;
    }

    /**
     * @brief Generiert TLS-Parameter fu00fcr den Browser-Fingerprint
     * 
     * @return Eine Map von TLS-Parameter-Namen zu Werten
     */
    std::map<std::string, std::string> generate_tls_parameters() const {
        std::map<std::string, std::string> params;
        
        // Füge Standard-TLS-Parameter hinzu - Ersetzt durch AEGIS/MORUS für echte Verschlüsselung
        params["TLS-Version"] = "TLS 1.3";
        params["Cipher-Suites"] = "TLS_AEGIS_128X_SHA256,TLS_AEGIS_128L_SHA384,TLS_MORUS_1280_128_SHA256";
        
        return params;
    }

private:
    BrowserType browser_type_;
    OSType os_type_;
    std::string user_agent_;
    std::vector<std::string> supported_cipher_suites_;
    std::vector<std::string> supported_extensions_;
    std::vector<std::string> http_header_order_;
};

} // namespace stealth
} // namespace quicfuscate