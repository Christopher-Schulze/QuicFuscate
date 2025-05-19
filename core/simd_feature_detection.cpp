#include "simd_feature_detection.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>

#if defined(__APPLE__) && defined(__aarch64__)
// Apple Silicon (ARM) spezifisch
#include <sys/sysctl.h>
#include <unistd.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

namespace quicsand {
namespace simd {

#if defined(__x86_64__) || defined(__i386__)
// Helper function to execute cpuid instruction (nur für x86/x64)
static void cpuid(int info[4], int func_id, int sub_func_id) {
#ifdef _MSC_VER
    __cpuidex(info, func_id, sub_func_id);
#else
    __cpuid_count(func_id, sub_func_id, info[0], info[1], info[2], info[3]);
#endif
}

// Helper function to execute xgetbv instruction (für AVX-Support)
static uint64_t xgetbv(uint32_t xcr) {
#ifdef _MSC_VER
    return _xgetbv(xcr);
#else
    uint32_t eax, edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(xcr));
    return (static_cast<uint64_t>(edx) << 32) | eax;
#endif
}
#endif

FeatureDetector::FeatureDetector() {
    detected_features_ = detect_all_features();
    setup_feature_dependencies();
    map_architecture_features();
}

uint64_t FeatureDetector::detect_all_features() {
    uint64_t features = 0;

#if defined(__x86_64__) || defined(__i386__)
    features |= detect_x86_features();
#elif defined(__ARM_NEON) || defined(__aarch64__)
    features |= detect_arm_features();
#endif

    return features;
}

uint64_t FeatureDetector::detect_x86_features() {
    uint64_t features = 0;

#if defined(__x86_64__) || defined(__i386__)
    int info[4];
    
    // Basis-CPUID-Info
    cpuid(info, 0, 0);
    int max_id = info[0];
    
    if (max_id >= 1) {
        cpuid(info, 1, 0);
        
        // Überprüfe SSE-Features
        if (info[3] & (1 << 25)) features |= static_cast<uint64_t>(CpuFeature::SSE);
        if (info[3] & (1 << 26)) features |= static_cast<uint64_t>(CpuFeature::SSE2);
        if (info[2] & (1 << 0))  features |= static_cast<uint64_t>(CpuFeature::SSE3);
        if (info[2] & (1 << 9))  features |= static_cast<uint64_t>(CpuFeature::SSSE3);
        if (info[2] & (1 << 19)) features |= static_cast<uint64_t>(CpuFeature::SSE41);
        if (info[2] & (1 << 20)) features |= static_cast<uint64_t>(CpuFeature::SSE42);
        
        // Überprüfe AES-NI und CLMUL
        if (info[2] & (1 << 25)) features |= static_cast<uint64_t>(CpuFeature::AES_NI);
        if (info[2] & (1 << 1))  features |= static_cast<uint64_t>(CpuFeature::PCLMULQDQ);
        
        // Überprüfe RDRAND
        if (info[2] & (1 << 30)) features |= static_cast<uint64_t>(CpuFeature::RDRAND);
        
        // AVX erfordert OS-Support via XSAVE
        bool os_uses_xsave_xrstor = (info[2] & (1 << 27)) != 0;
        bool cpu_avx_support = (info[2] & (1 << 28)) != 0;
        
        if (os_uses_xsave_xrstor && cpu_avx_support) {
            // Überprüfe, ob der OS die AVX-Register speichert
            uint64_t xcr0 = xgetbv(0);
            bool os_avx_support = (xcr0 & 6) == 6; // XCR0[2:1] = '11b' (XMM und YMM-Status gespeichert)
            
            if (os_avx_support) {
                features |= static_cast<uint64_t>(CpuFeature::AVX);
                
                // Überprüfe FMA, benötigt AVX
                if (info[2] & (1 << 12)) features |= static_cast<uint64_t>(CpuFeature::FMA);
            }
        }
    }
    
    // Erweiterte Features prüfen
    if (max_id >= 7) {
        cpuid(info, 7, 0);
        
        // Überprüfe AVX2
        if ((features & static_cast<uint64_t>(CpuFeature::AVX)) && (info[1] & (1 << 5))) {
            features |= static_cast<uint64_t>(CpuFeature::AVX2);
        }
        
        // Überprüfe AVX-512
        bool os_avx512_support = false;
        if ((features & static_cast<uint64_t>(CpuFeature::AVX))) {
            uint64_t xcr0 = xgetbv(0);
            os_avx512_support = (xcr0 & 0xE6) == 0xE6; // XCR0[7:5] = '111b' (OPMASK, ZMM_Hi256, ZMM_Hi16 gespeichert)
        }
        
        if (os_avx512_support) {
            if (info[1] & (1 << 16)) features |= static_cast<uint64_t>(CpuFeature::AVX512F);
            if (info[1] & (1 << 17)) features |= static_cast<uint64_t>(CpuFeature::AVX512DQ);
            if (info[1] & (1 << 30)) features |= static_cast<uint64_t>(CpuFeature::AVX512BW);
            if (info[1] & (1 << 31)) features |= static_cast<uint64_t>(CpuFeature::AVX512VL);
            if (info[2] & (1 << 1))  features |= static_cast<uint64_t>(CpuFeature::AVX512VBMI);
        }
        
        // Überprüfe RDSEED
        if (info[1] & (1 << 18)) features |= static_cast<uint64_t>(CpuFeature::RDSEED);
    }
#endif

    return features;
}

uint64_t FeatureDetector::detect_arm_features() {
    uint64_t features = 0;

#if defined(__ARM_NEON) || defined(__aarch64__)
    // NEON ist auf allen ARM64-Systemen verfügbar
    features |= static_cast<uint64_t>(CpuFeature::NEON);
    features |= static_cast<uint64_t>(CpuFeature::ASIMD); // Advanced SIMD (ARMv8)

#if defined(__APPLE__) && defined(__aarch64__)
    // Apple Silicon spezifische Erkennung
    int value = 0;
    size_t size = sizeof(value);

    // Überprüfe Crypto-Features
    // Apple M-Serie Chips haben alle Crypto-Funktionen
    features |= static_cast<uint64_t>(CpuFeature::CRYPTO);

    // Überprüfe Dot Product Support
    features |= static_cast<uint64_t>(CpuFeature::DOTPROD);

    // Überprüfe CRC-Support
    features |= static_cast<uint64_t>(CpuFeature::CRC);

#else
    // Generische ARM-Feature-Erkennung
    
    // Lese CPU-Info aus /proc/cpuinfo, wo verfügbar
#if defined(__linux__)
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[1024];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strstr(line, "Features")) {
                if (strstr(line, "aes"))    features |= static_cast<uint64_t>(CpuFeature::CRYPTO);
                if (strstr(line, "sha1"))   features |= static_cast<uint64_t>(CpuFeature::CRYPTO);
                if (strstr(line, "sha2"))   features |= static_cast<uint64_t>(CpuFeature::CRYPTO);
                if (strstr(line, "pmull"))  features |= static_cast<uint64_t>(CpuFeature::CRYPTO);
                if (strstr(line, "crc32"))  features |= static_cast<uint64_t>(CpuFeature::CRC);
                if (strstr(line, "dotprod")) features |= static_cast<uint64_t>(CpuFeature::DOTPROD);
                if (strstr(line, "sve"))    features |= static_cast<uint64_t>(CpuFeature::SVE);
                break;
            }
        }
        fclose(cpuinfo);
    }
#endif

    // Compiler-basierte Feature-Erkennung
#ifdef __ARM_FEATURE_CRC32
    features |= static_cast<uint64_t>(CpuFeature::CRC);
#endif

#ifdef __ARM_FEATURE_CRYPTO
    features |= static_cast<uint64_t>(CpuFeature::CRYPTO);
#endif

#ifdef __ARM_FEATURE_DOTPROD
    features |= static_cast<uint64_t>(CpuFeature::DOTPROD);
#endif

#ifdef __ARM_FEATURE_SVE
    features |= static_cast<uint64_t>(CpuFeature::SVE);
#endif

#ifdef __ARM_FEATURE_SVE2
    features |= static_cast<uint64_t>(CpuFeature::SVE2);
#endif

#endif // __APPLE__
#endif // __ARM_NEON

    return features;
}

void FeatureDetector::setup_feature_dependencies() {
    // x86/x64 Feature-Abhängigkeiten
    feature_dependencies_[CpuFeature::SSE2] = {CpuFeature::SSE};
    feature_dependencies_[CpuFeature::SSE3] = {CpuFeature::SSE2};
    feature_dependencies_[CpuFeature::SSSE3] = {CpuFeature::SSE3};
    feature_dependencies_[CpuFeature::SSE41] = {CpuFeature::SSSE3};
    feature_dependencies_[CpuFeature::SSE42] = {CpuFeature::SSE41};
    feature_dependencies_[CpuFeature::AVX] = {CpuFeature::SSE42};
    feature_dependencies_[CpuFeature::AVX2] = {CpuFeature::AVX};
    feature_dependencies_[CpuFeature::FMA] = {CpuFeature::AVX};
    feature_dependencies_[CpuFeature::AVX512F] = {CpuFeature::AVX2};
    feature_dependencies_[CpuFeature::AVX512BW] = {CpuFeature::AVX512F};
    feature_dependencies_[CpuFeature::AVX512DQ] = {CpuFeature::AVX512F};
    feature_dependencies_[CpuFeature::AVX512VL] = {CpuFeature::AVX512F};
    feature_dependencies_[CpuFeature::AVX512VBMI] = {CpuFeature::AVX512F};
    
    // ARM Feature-Abhängigkeiten
    feature_dependencies_[CpuFeature::ASIMD] = {CpuFeature::NEON};
    feature_dependencies_[CpuFeature::SVE2] = {CpuFeature::SVE};
}

void FeatureDetector::map_architecture_features() {
    // Mappe spezifische Architektur-Features auf konzeptuelle Features höheren Niveaus
    
    // Hardware-AES-Unterstützung
    if (has_feature(CpuFeature::AES_NI) || has_feature(CpuFeature::CRYPTO)) {
        detected_features_ |= static_cast<uint64_t>(CpuFeature::HW_AES);
    }
    
    // Hardware-CRC32-Unterstützung
    if (has_feature(CpuFeature::SSE42) || has_feature(CpuFeature::CRC)) {
        detected_features_ |= static_cast<uint64_t>(CpuFeature::HW_CRC32);
    }
    
    // Breite Vektoren (256+ Bit)
    if (has_feature(CpuFeature::AVX2) || has_feature(CpuFeature::SVE)) {
        detected_features_ |= static_cast<uint64_t>(CpuFeature::WIDE_VECTORS);
    }
    
    // Half-Precision (FP16) Support
    if (has_feature(CpuFeature::AVX512F) || 
        (has_feature(CpuFeature::ASIMD) && (
#ifdef __ARM_FEATURE_FP16_VECTOR_ARITHMETIC
        true
#else
        false
#endif
        ))) {
        detected_features_ |= static_cast<uint64_t>(CpuFeature::FP16_SUPPORT);
    }
}

bool FeatureDetector::has_feature(CpuFeature feature) const {
    bool direct_support = (detected_features_ & static_cast<uint64_t>(feature)) != 0;
    if (direct_support) return true;
    
    // Überprüfe, ob alle Abhängigkeiten erfüllt sind
    auto it = feature_dependencies_.find(feature);
    if (it != feature_dependencies_.end()) {
        // Wenn es Abhängigkeiten gibt, müssen alle erfüllt sein
        bool all_dependencies_met = true;
        for (const auto& dependency : it->second) {
            if (!has_feature(dependency)) {
                all_dependencies_met = false;
                break;
            }
        }
        return all_dependencies_met;
    }
    
    return false;
}

std::string FeatureDetector::features_to_string() const {
    std::stringstream ss;
    
    // x86/x64 Features
    if (has_feature(CpuFeature::SSE))       ss << "SSE ";
    if (has_feature(CpuFeature::SSE2))      ss << "SSE2 ";
    if (has_feature(CpuFeature::SSE3))      ss << "SSE3 ";
    if (has_feature(CpuFeature::SSSE3))     ss << "SSSE3 ";
    if (has_feature(CpuFeature::SSE41))     ss << "SSE4.1 ";
    if (has_feature(CpuFeature::SSE42))     ss << "SSE4.2 ";
    if (has_feature(CpuFeature::AVX))       ss << "AVX ";
    if (has_feature(CpuFeature::AVX2))      ss << "AVX2 ";
    if (has_feature(CpuFeature::FMA))       ss << "FMA ";
    if (has_feature(CpuFeature::AES_NI))    ss << "AES-NI ";
    if (has_feature(CpuFeature::PCLMULQDQ)) ss << "PCLMULQDQ ";
    if (has_feature(CpuFeature::RDRAND))    ss << "RDRAND ";
    if (has_feature(CpuFeature::RDSEED))    ss << "RDSEED ";
    
    if (has_feature(CpuFeature::AVX512F))   ss << "AVX-512F ";
    if (has_feature(CpuFeature::AVX512BW))  ss << "AVX-512BW ";
    if (has_feature(CpuFeature::AVX512DQ))  ss << "AVX-512DQ ";
    if (has_feature(CpuFeature::AVX512VL))  ss << "AVX-512VL ";
    if (has_feature(CpuFeature::AVX512VBMI))ss << "AVX-512VBMI ";
    
    // ARM Features
    if (has_feature(CpuFeature::NEON))      ss << "NEON ";
    if (has_feature(CpuFeature::ASIMD))     ss << "Advanced SIMD ";
    if (has_feature(CpuFeature::SVE))       ss << "SVE ";
    if (has_feature(CpuFeature::SVE2))      ss << "SVE2 ";
    if (has_feature(CpuFeature::DOTPROD))   ss << "Dot Product ";
    if (has_feature(CpuFeature::CRYPTO))    ss << "Crypto ";
    if (has_feature(CpuFeature::CRC))       ss << "CRC ";
    
    // Konzeptuelle Features
    if (has_feature(CpuFeature::HW_AES))    ss << "[Hardware AES] ";
    if (has_feature(CpuFeature::HW_CRC32))  ss << "[Hardware CRC32] ";
    if (has_feature(CpuFeature::WIDE_VECTORS)) ss << "[Wide Vectors] ";
    if (has_feature(CpuFeature::FP16_SUPPORT)) ss << "[FP16 Support] ";
    
    std::string result = ss.str();
    if (!result.empty()) {
        result.pop_back();  // Entferne letztes Leerzeichen
    }
    
    return result;
}

CpuFeature FeatureDetector::get_best_feature_for(const std::string& function_name) const {
    auto it = implementations_.find(function_name);
    if (it == implementations_.end()) {
        return CpuFeature::NONE;
    }
    
    CpuFeature best_feature = CpuFeature::NONE;
    for (const auto& impl : it->second) {
        if (has_feature(impl.required_feature) && 
            static_cast<uint64_t>(impl.required_feature) > static_cast<uint64_t>(best_feature)) {
            best_feature = impl.required_feature;
        }
    }
    
    return best_feature;
}

} // namespace simd
} // namespace quicsand
