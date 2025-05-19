#include "http3_masquerading.hpp"
#include <random>
#include <chrono>

namespace quicsand {

// Browser-Profile-Konfigurationen
const std::unordered_map<std::string, std::string> Http3Masquerading::browser_user_agents_ = {
    {"Chrome_Latest", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},
    {"Firefox_Latest", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0"},
    {"Safari_Latest", "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15"},
    {"Edge_Latest", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62"},
    {"Mobile_Chrome", "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36"},
    {"Mobile_Safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"},
    {"Random", ""}  // Wird dynamisch generiert
};

// Typische HTTP-Header für verschiedene Browser
const std::unordered_map<std::string, std::vector<std::string>> Http3Masquerading::browser_typical_headers_ = {
    {"Chrome_Latest", {
        "accept", "accept-encoding", "accept-language", "cache-control", "sec-ch-ua", 
        "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", 
        "sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests"
    }},
    {"Firefox_Latest", {
        "accept", "accept-encoding", "accept-language", "cache-control", "dnt", 
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", 
        "te", "upgrade-insecure-requests"
    }},
    {"Safari_Latest", {
        "accept", "accept-encoding", "accept-language", "cache-control", 
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "upgrade-insecure-requests"
    }},
    {"Edge_Latest", {
        "accept", "accept-encoding", "accept-language", "cache-control", "sec-ch-ua", 
        "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", 
        "sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests"
    }},
    {"Mobile_Chrome", {
        "accept", "accept-encoding", "accept-language", "cache-control", "sec-ch-ua", 
        "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", 
        "sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests"
    }},
    {"Mobile_Safari", {
        "accept", "accept-encoding", "accept-language", "cache-control", 
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "upgrade-insecure-requests"
    }},
    {"Random", {}} // Wird dynamisch generiert
};

// Getter/Setter für Browser-Profil
void Http3Masquerading::set_browser_profile(const std::string& profile) {
    if (browser_user_agents_.find(profile) != browser_user_agents_.end()) {
        browser_profile_ = profile;
    } else {
        // Fallback auf Chrome, wenn unbekanntes Profil
        browser_profile_ = "Chrome_Latest";
    }
}

std::string Http3Masquerading::get_browser_profile() const {
    return browser_profile_;
}

// Generiert realistische HTTP-Header basierend auf dem Browser-Profil
std::vector<Http3HeaderField> Http3Masquerading::generate_realistic_headers(
    const std::string& host, 
    const std::string& path,
    const std::string& method) {
    
    std::vector<Http3HeaderField> headers;
    
    // Grundlegende Pseudo-Header gemäß HTTP/3-Spezifikation
    headers.push_back({":method", method});
    headers.push_back({":scheme", "https"});
    headers.push_back({":authority", host});
    headers.push_back({":path", path});
    
    // User-Agent basierend auf Browser-Profil
    if (browser_profile_ == "Random") {
        // Generiere zufälligen User-Agent
        std::vector<std::string> profiles = {"Chrome_Latest", "Firefox_Latest", "Safari_Latest", 
                                            "Edge_Latest", "Mobile_Chrome", "Mobile_Safari"};
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0, profiles.size() - 1);
        
        std::string random_profile = profiles[dist(gen)];
        headers.push_back({"user-agent", browser_user_agents_.at(random_profile)});
    } else {
        headers.push_back({"user-agent", browser_user_agents_.at(browser_profile_)});
    }
    
    // Gemeinsame Header für alle Browser
    headers.push_back({"accept-language", "en-US,en;q=0.9"});
    headers.push_back({"accept-encoding", "gzip, deflate, br"});
    
    // Browser-spezifische Header
    if (browser_profile_ == "Chrome_Latest" || browser_profile_ == "Edge_Latest") {
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"});
        headers.push_back({"sec-ch-ua", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\""});
        headers.push_back({"sec-ch-ua-mobile", "?0"});
        headers.push_back({"sec-ch-ua-platform", "\"Windows\""});
    } else if (browser_profile_ == "Firefox_Latest") {
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"});
        headers.push_back({"dnt", "1"});
        headers.push_back({"te", "trailers"});
    } else if (browser_profile_ == "Safari_Latest") {
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"});
    } else if (browser_profile_ == "Mobile_Chrome") {
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"});
        headers.push_back({"sec-ch-ua", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\""});
        headers.push_back({"sec-ch-ua-mobile", "?1"});
        headers.push_back({"sec-ch-ua-platform", "\"Android\""});
    } else if (browser_profile_ == "Mobile_Safari") {
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"});
    }
    
    // Gemeinsame Fetch-Metadaten-Header für moderne Browser
    headers.push_back({"sec-fetch-site", "none"});
    headers.push_back({"sec-fetch-mode", "navigate"});
    headers.push_back({"sec-fetch-dest", "document"});
    
    if (method == "GET") {
        headers.push_back({"sec-fetch-user", "?1"});
    }
    
    // Cache-Control und Upgrade-Insecure-Requests sind üblich
    headers.push_back({"cache-control", "max-age=0"});
    headers.push_back({"upgrade-insecure-requests", "1"});
    
    return headers;
}

// Simulate realistische Browser-Timing
void Http3Masquerading::simulate_realistic_timing(uint64_t& delay_ms) {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Verteilung für realistische Verzögerungen (10ms - 100ms)
    std::uniform_int_distribution<> dist(10, 100);
    
    delay_ms = dist(gen);
}

} // namespace quicsand
