#include "http3_priority.hpp"
#include <algorithm>
#include <sstream>
#include <regex>
#include <iostream>

namespace quicsand {

// PriorityFieldValue Implementation

PriorityFieldValue::PriorityFieldValue(const std::string& header_value) {
    // Format: "u=<urgency>,i=<incremental>" oder Teilmengen davon
    std::regex urgency_regex("u=([0-7])");
    std::regex incremental_regex("i=(0|1|true|false)");
    
    std::smatch urgency_match;
    if (std::regex_search(header_value, urgency_match, urgency_regex)) {
        int u = std::stoi(urgency_match[1]);
        urgency = static_cast<UrgencyLevel>(u);
    }
    
    std::smatch incremental_match;
    if (std::regex_search(header_value, incremental_match, incremental_regex)) {
        std::string inc_str = incremental_match[1];
        incremental = (inc_str == "1" || inc_str == "true");
    }
}

std::string PriorityFieldValue::to_string() const {
    std::stringstream ss;
    bool has_value = false;
    
    if (urgency.has_value()) {
        ss << "u=" << static_cast<int>(urgency.value());
        has_value = true;
    }
    
    if (incremental.has_value()) {
        if (has_value) {
            ss << ",";
        }
        ss << "i=" << (incremental.value() ? "1" : "0");
    }
    
    return ss.str();
}

void PriorityFieldValue::apply_to(PriorityParameters& params) const {
    if (urgency.has_value()) {
        params.urgency = urgency.value();
    }
    
    if (incremental.has_value()) {
        params.incremental = incremental.value();
    }
}

// PriorityScheduler Implementation

PriorityScheduler::PriorityScheduler() {
    // Initialisiere alle Dringlichkeitsstufen
    for (int i = 0; i <= static_cast<int>(UrgencyLevel::LOWEST); i++) {
        urgency_buckets_[static_cast<UrgencyLevel>(i)] = std::set<uint64_t>();
        last_processed_streams_[static_cast<UrgencyLevel>(i)] = 0;
    }
}

void PriorityScheduler::add_stream(uint64_t stream_id, const PriorityParameters& params) {
    if (stream_id == 0 || stream_priorities_.find(stream_id) != stream_priorities_.end()) {
        return;  // Stream-ID 0 ist ungültig oder Stream bereits vorhanden
    }
    
    // Speichere Prioritätsparameter
    stream_priorities_[stream_id] = params;
    
    // Füge Stream zur entsprechenden Dringlichkeitsstufe hinzu
    urgency_buckets_[params.urgency].insert(stream_id);
}

void PriorityScheduler::update_stream_priority(uint64_t stream_id, const PriorityParameters& params) {
    auto it = stream_priorities_.find(stream_id);
    if (it == stream_priorities_.end()) {
        // Stream nicht gefunden, füge ihn hinzu
        add_stream(stream_id, params);
        return;
    }
    
    UrgencyLevel old_urgency = it->second.urgency;
    
    // Entferne Stream aus alter Dringlichkeitsstufe
    urgency_buckets_[old_urgency].erase(stream_id);
    
    // Aktualisiere Prioritätsparameter
    it->second = params;
    
    // Füge Stream zur neuen Dringlichkeitsstufe hinzu
    urgency_buckets_[params.urgency].insert(stream_id);
}

void PriorityScheduler::remove_stream(uint64_t stream_id) {
    auto it = stream_priorities_.find(stream_id);
    if (it == stream_priorities_.end()) {
        return;  // Stream nicht gefunden
    }
    
    // Entferne Stream aus Dringlichkeitsstufe
    urgency_buckets_[it->second.urgency].erase(stream_id);
    
    // Entferne Stream aus bereitliste
    ready_streams_.erase(stream_id);
    
    // Entferne Stream aus Prioritätszuordnung
    stream_priorities_.erase(it);
    
    // Wenn dies der zuletzt verarbeitete Stream für diese Dringlichkeitsstufe war, setze zurück
    if (last_processed_streams_[it->second.urgency] == stream_id) {
        last_processed_streams_[it->second.urgency] = 0;
    }
}

uint64_t PriorityScheduler::select_next_stream() {
    // Durchlaufe alle Dringlichkeitsstufen von höchster (0) bis niedrigster (7)
    for (int i = 0; i <= static_cast<int>(UrgencyLevel::LOWEST); i++) {
        UrgencyLevel urgency = static_cast<UrgencyLevel>(i);
        
        // Überprüfe, ob es Streams mit dieser Dringlichkeitsstufe gibt
        if (urgency_buckets_[urgency].empty()) {
            continue;
        }
        
        // Überprüfe, ob es bereite Streams in dieser Dringlichkeitsstufe gibt
        std::set<uint64_t> ready_in_urgency;
        std::set_intersection(
            urgency_buckets_[urgency].begin(), urgency_buckets_[urgency].end(),
            ready_streams_.begin(), ready_streams_.end(),
            std::inserter(ready_in_urgency, ready_in_urgency.begin())
        );
        
        if (ready_in_urgency.empty()) {
            continue;
        }
        
        // Wenn Stream mit diesem Urgency Level gefunden wurde
        
        // Überprüfe, ob inkrementelles Scheduling verwendet werden soll
        bool has_incremental = false;
        for (uint64_t stream_id : ready_in_urgency) {
            if (stream_priorities_[stream_id].incremental) {
                has_incremental = true;
                break;
            }
        }
        
        if (!has_incremental) {
            // Nicht-inkrementell: Wähle einen beliebigen Stream
            return *ready_in_urgency.begin();
        }
        
        // Inkrementell: Round-Robin-Scheduling
        uint64_t last_processed = last_processed_streams_[urgency];
        
        // Finde den nächsten Stream nach dem zuletzt verarbeiteten
        auto it = ready_in_urgency.upper_bound(last_processed);
        if (it != ready_in_urgency.end()) {
            last_processed_streams_[urgency] = *it;
            return *it;
        }
        
        // Wenn kein nächster Stream gefunden wurde, starte von vorne
        last_processed_streams_[urgency] = *ready_in_urgency.begin();
        return *ready_in_urgency.begin();
    }
    
    // Kein bereiter Stream gefunden
    return 0;
}

void PriorityScheduler::mark_stream_ready(uint64_t stream_id) {
    if (stream_priorities_.find(stream_id) != stream_priorities_.end()) {
        ready_streams_.insert(stream_id);
    }
}

void PriorityScheduler::mark_stream_not_ready(uint64_t stream_id) {
    ready_streams_.erase(stream_id);
}

std::optional<PriorityParameters> PriorityScheduler::get_stream_priority(uint64_t stream_id) const {
    auto it = stream_priorities_.find(stream_id);
    if (it != stream_priorities_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::map<uint64_t, PriorityParameters> PriorityScheduler::get_all_streams() const {
    return stream_priorities_;
}

// PriorityManager Implementation

void PriorityManager::create_scheduler(uint64_t connection_id) {
    if (schedulers_.find(connection_id) != schedulers_.end()) {
        return;  // Scheduler bereits vorhanden
    }
    
    schedulers_[connection_id] = std::make_unique<PriorityScheduler>();
}

void PriorityManager::remove_scheduler(uint64_t connection_id) {
    schedulers_.erase(connection_id);
}

PriorityParameters PriorityManager::extract_priority_from_headers(
    const std::map<std::string, std::string>& headers) {
    
    // Standardpriorität
    PriorityParameters params;
    
    // Suche nach Priority-Header
    auto it = headers.find("priority");
    if (it != headers.end()) {
        PriorityFieldValue field_value(it->second);
        field_value.apply_to(params);
    }
    
    return params;
}

std::string PriorityManager::generate_priority_header(const PriorityParameters& params) {
    PriorityFieldValue field_value(params.urgency, params.incremental);
    return field_value.to_string();
}

PriorityScheduler* PriorityManager::get_scheduler(uint64_t connection_id) {
    auto it = schedulers_.find(connection_id);
    if (it != schedulers_.end()) {
        return it->second.get();
    }
    return nullptr;
}

} // namespace quicsand
