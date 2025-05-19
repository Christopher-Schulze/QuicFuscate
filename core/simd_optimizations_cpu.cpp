#include "simd_optimizations.hpp"
#include <iostream>
#include <string>
#include <sstream>

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
#endif

uint32_t detect_cpu_features() {
    uint32_t features = 0;
    
#if defined(__APPLE__) && defined(__aarch64__)
    // Apple Silicon (ARM) Feature-Erkennung
    
    // NEON ist auf allen Apple Silicon Chips verfügbar
    features |= static_cast<uint32_t>(SIMDSupport::NEON);
    features |= static_cast<uint32_t>(SIMDSupport::ASIMD); // Advanced SIMD (ARMv8)
    
    // Überprüfe auf Crypto-Erweiterungen mit sysctl
    int value = 0;
    size_t size = sizeof(value);
    
    // Überprüfe auf Crypto-Erweiterungen (AES/SHA)
    // Apple M-Serie Chips haben alle diese Funktionen
    features |= static_cast<uint32_t>(SIMDSupport::CRYPTO);
    
    // Überprüfe auf SVE und Dot Product Support
    // Alle Apple M1/M2 Chips unterstützen Dot Product
    features |= static_cast<uint32_t>(SIMDSupport::DOTPROD);
    
    // Überprüfe auf CRC Unterstützung
    features |= static_cast<uint32_t>(SIMDSupport::CRC);
    
#elif defined(__x86_64__) || defined(__i386__)
    // x86/x64 Feature-Erkennung
    int cpu_info[4];
    
    // Get basic CPU info - Check for CPUID support first
    cpuid(cpu_info, 0, 0);
    int max_func_id = cpu_info[0];
    
    if (max_func_id < 1) {
        // CPUID not fully supported
        return features;
    }
    
    // Get feature flags
    cpuid(cpu_info, 1, 0);
    
    // Check for SSE features
    if (cpu_info[3] & (1 << 25)) features |= static_cast<uint32_t>(SIMDSupport::SSE);
    if (cpu_info[3] & (1 << 26)) features |= static_cast<uint32_t>(SIMDSupport::SSE2);
    if (cpu_info[2] & (1 << 0))  features |= static_cast<uint32_t>(SIMDSupport::SSE3);
    if (cpu_info[2] & (1 << 9))  features |= static_cast<uint32_t>(SIMDSupport::SSSE3);
    if (cpu_info[2] & (1 << 19)) features |= static_cast<uint32_t>(SIMDSupport::SSE41);
    if (cpu_info[2] & (1 << 20)) features |= static_cast<uint32_t>(SIMDSupport::SSE42);
    
    // Check for AES-NI and CLMUL
    if (cpu_info[2] & (1 << 25)) features |= static_cast<uint32_t>(SIMDSupport::AESNI);
    if (cpu_info[2] & (1 << 1))  features |= static_cast<uint32_t>(SIMDSupport::PCLMULQDQ);
    
    // Check for AVX
    if (cpu_info[2] & (1 << 28)) features |= static_cast<uint32_t>(SIMDSupport::AVX);
    
    // Check for AVX2
    if (max_func_id >= 7) {
        cpuid(cpu_info, 7, 0);
        if (cpu_info[1] & (1 << 5)) features |= static_cast<uint32_t>(SIMDSupport::AVX2);
        
        // Check for AVX-512
        if ((cpu_info[1] & (1 << 16))) {
            features |= static_cast<uint32_t>(SIMDSupport::AVX512F);
        }
    }
#endif
    
    return features;
}

bool is_feature_supported(SIMDSupport feature) {
    static uint32_t supported_features = detect_cpu_features();
    return (supported_features & static_cast<uint32_t>(feature)) != 0;
}

std::string features_to_string(uint32_t features) {
    std::stringstream ss;
    
    ss << "Supported SIMD features: ";
    
#ifdef __ARM_NEON
    // ARM-spezifische Features
    if (features & static_cast<uint32_t>(SIMDSupport::NEON))    ss << "NEON ";
    if (features & static_cast<uint32_t>(SIMDSupport::ASIMD))   ss << "Advanced SIMD ";
    if (features & static_cast<uint32_t>(SIMDSupport::SVE))     ss << "SVE ";
    if (features & static_cast<uint32_t>(SIMDSupport::DOTPROD)) ss << "Dot Product ";
    if (features & static_cast<uint32_t>(SIMDSupport::CRYPTO))  ss << "AES/SHA ";
    if (features & static_cast<uint32_t>(SIMDSupport::CRC))     ss << "CRC32 ";
#else
    // x86/x64-spezifische Features
    if (features & static_cast<uint32_t>(SIMDSupport::SSE))       ss << "SSE ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE2))      ss << "SSE2 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE3))      ss << "SSE3 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSSE3))     ss << "SSSE3 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE41))     ss << "SSE4.1 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE42))     ss << "SSE4.2 ";
    if (features & static_cast<uint32_t>(SIMDSupport::AVX))       ss << "AVX ";
    if (features & static_cast<uint32_t>(SIMDSupport::AVX2))      ss << "AVX2 ";
    if (features & static_cast<uint32_t>(SIMDSupport::AVX512F))   ss << "AVX-512F ";
    if (features & static_cast<uint32_t>(SIMDSupport::AESNI))     ss << "AES-NI ";
    if (features & static_cast<uint32_t>(SIMDSupport::PCLMULQDQ)) ss << "PCLMULQDQ ";
#endif
    
    return ss.str();
}

// SIMDDispatcher implementation
SIMDDispatcher::SIMDDispatcher() 
    : supported_features_(detect_cpu_features()) {
    std::cout << features_to_string(supported_features_) << std::endl;
}

} // namespace simd
} // namespace quicsand
