#ifndef SIMD_FEATURE_DETECTION_HPP
#define SIMD_FEATURE_DETECTION_HPP

#include <cstdint>
#include <string>
#include <array>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>

namespace quicsand {
namespace simd {

// Erweiterte CPU-Feature-Flags für detailliertere Erkennung
enum class CpuFeature : uint64_t {
    // Basis-Features
    NONE = 0ULL,
    
    // x86/x64 Features
    SSE                = 1ULL << 0,
    SSE2               = 1ULL << 1,
    SSE3               = 1ULL << 2,
    SSSE3              = 1ULL << 3,
    SSE41              = 1ULL << 4,
    SSE42              = 1ULL << 5,
    AVX                = 1ULL << 6,
    AVX2               = 1ULL << 7,
    AVX512F            = 1ULL << 8,
    AVX512BW           = 1ULL << 9,
    AVX512DQ           = 1ULL << 10,
    AVX512VL           = 1ULL << 11,
    AVX512VBMI         = 1ULL << 12,
    FMA                = 1ULL << 13,
    AES_NI             = 1ULL << 14,
    PCLMULQDQ          = 1ULL << 15,
    RDRAND             = 1ULL << 16,
    RDSEED             = 1ULL << 17,
    
    // ARM Features
    NEON               = 1ULL << 20,
    ASIMD              = 1ULL << 21,  // Advanced SIMD (ARMv8)
    SVE                = 1ULL << 22,  // Scalable Vector Extension
    SVE2               = 1ULL << 23,
    DOTPROD            = 1ULL << 24,  // Dot Product
    CRYPTO             = 1ULL << 25,  // Crypto Extensions (AES, SHA)
    CRC                = 1ULL << 26,  // CRC32

    // Gemeinsame/Abstrakte Features
    HW_AES             = 1ULL << 40,  // Hardware-AES (AES-NI oder ARM Crypto)
    HW_CRC32           = 1ULL << 41,  // Hardware-CRC32
    WIDE_VECTORS       = 1ULL << 42,  // 256+ bit Vektoren (AVX2, SVE)
    FP16_SUPPORT       = 1ULL << 43,  // Half-precision floating point
};

// Operator für Bitweise Operationen auf CpuFeature
inline CpuFeature operator|(CpuFeature a, CpuFeature b) {
    return static_cast<CpuFeature>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

inline CpuFeature operator&(CpuFeature a, CpuFeature b) {
    return static_cast<CpuFeature>(static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}

// Klasse für fortgeschrittene Feature-Detection und Fallback-Strategien
class FeatureDetector {
public:
    // Singleton-Instance
    static FeatureDetector& instance() {
        static FeatureDetector instance;
        return instance;
    }

    // Erkennt alle verfügbaren CPU-Features
    uint64_t detect_all_features();
    
    // Prüft, ob ein bestimmtes Feature unterstützt wird
    bool has_feature(CpuFeature feature) const;
    
    // Gibt eine string-Repräsentation der unterstützten Features zurück
    std::string features_to_string() const;
    
    // Findet das beste verfügbare Feature für eine bestimmte Funktion
    // z.B. "AES-Verschlüsselung" könnte entweder AES-NI, ARM Crypto oder Softwareimplementierung sein
    CpuFeature get_best_feature_for(const std::string& function_name) const;
    
    // Registriert Implementierungen für verschiedene Features mit Fallback-Optionen
    template<typename Func>
    void register_implementation(const std::string& function_name, CpuFeature required_feature, Func implementation);
    
    // Ruft die beste verfügbare Implementierung für eine Funktion auf
    template<typename RetType, typename... Args>
    RetType call_best_implementation(const std::string& function_name, Args&&... args);

private:
    FeatureDetector();
    ~FeatureDetector() = default;
    
    // Erkennt x86/x64 spezifische Features
    uint64_t detect_x86_features();
    
    // Erkennt ARM spezifische Features
    uint64_t detect_arm_features();
    
    // Definiert Abhängigkeiten zwischen Features
    void setup_feature_dependencies();
    
    // Mappt niedrigere Features auf konzeptuelle Features höheren Niveaus
    void map_architecture_features();
    
    uint64_t detected_features_ = 0;
    
    // Speichert Abhängigkeiten zwischen Features
    std::unordered_map<CpuFeature, std::vector<CpuFeature>> feature_dependencies_;
    
    // Speichert Implementierungen für verschiedene Funktionen und Features
    struct FunctionImplementation {
        CpuFeature required_feature;
        std::function<void*()> get_implementation;
        
        template<typename Func>
        Func get() {
            return reinterpret_cast<Func>(get_implementation());
        }
    };
    
    std::unordered_map<std::string, std::vector<FunctionImplementation>> implementations_;
};

// Template-Implementierung zum Registrieren einer Funktion
template<typename Func>
void FeatureDetector::register_implementation(
    const std::string& function_name,
    CpuFeature required_feature,
    Func implementation
) {
    // Speichere die Implementierung als void* mit Lambda zur späteren Typkonvertierung
    void* impl_ptr = reinterpret_cast<void*>(implementation);
    auto get_impl = [impl_ptr]() -> void* { return impl_ptr; };
    
    FunctionImplementation func_impl{required_feature, get_impl};
    implementations_[function_name].push_back(func_impl);
}

// Template-Implementierung zum Aufrufen der besten verfügbaren Implementierung
template<typename RetType, typename... Args>
RetType FeatureDetector::call_best_implementation(
    const std::string& function_name,
    Args&&... args
) {
    // Finde die beste verfügbare Implementierung
    auto it = implementations_.find(function_name);
    if (it == implementations_.end()) {
        throw std::runtime_error("No implementation found for function: " + function_name);
    }
    
    // Sortiere Implementierungen nach Priorität (höchste Features zuerst)
    auto& impls = it->second;
    CpuFeature best_feature = CpuFeature::NONE;
    FunctionImplementation* best_impl = nullptr;
    
    for (auto& impl : impls) {
        if (has_feature(impl.required_feature) && 
            static_cast<uint64_t>(impl.required_feature) > static_cast<uint64_t>(best_feature)) {
            best_feature = impl.required_feature;
            best_impl = &impl;
        }
    }
    
    if (!best_impl) {
        throw std::runtime_error("No compatible implementation found for function: " + function_name);
    }
    
    // Rufe die beste Implementierung auf
    using FuncType = RetType(*)(Args...);
    FuncType func = best_impl->template get<FuncType>();
    return func(std::forward<Args>(args)...);
}

// Convenience-Funktionen und Makros für einfache Nutzung

// CPU-Feature-Flag-Makro für bedingte Kompilierung
#ifdef __AVX2__
#define QUICSAND_SIMD_HAS_AVX2 1
#else
#define QUICSAND_SIMD_HAS_AVX2 0
#endif

#ifdef __ARM_NEON
#define QUICSAND_SIMD_HAS_NEON 1
#else
#define QUICSAND_SIMD_HAS_NEON 0
#endif

// Hilfsfunktion zum Registrieren von Implementierungen mit Fallbacks
template<typename RetType, typename... Args>
class ImplRegistrar {
public:
    ImplRegistrar(const std::string& function_name) 
        : function_name_(function_name) {}
    
    ImplRegistrar& add_impl(CpuFeature feature, RetType(*func)(Args...)) {
        FeatureDetector::instance().register_implementation(function_name_, feature, func);
        return *this;
    }
    
    RetType call(Args&&... args) {
        return FeatureDetector::instance().call_best_implementation<RetType, Args...>(
            function_name_, std::forward<Args>(args)...);
    }
    
private:
    std::string function_name_;
};

// Makro zur einfachen Registrierung von Implementierungen
#define REGISTER_SIMD_FUNCTION(name, return_type, ...) \
    ImplRegistrar<return_type, __VA_ARGS__> name##_registrar(#name)

} // namespace simd
} // namespace quicsand

#endif // SIMD_FEATURE_DETECTION_HPP
