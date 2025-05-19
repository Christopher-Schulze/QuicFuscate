#include "simd_optimizations.hpp"
#include <sstream>

namespace quicsand {
namespace simd {

uint32_t detect_cpu_features() {
    uint32_t features = 0;
    
#ifdef __ARM_NEON
    // ARM NEON ist immer aktiviert, wenn __ARM_NEON definiert ist
    features |= static_cast<uint32_t>(SIMDSupport::NEON);
    
    // Für Apple M1/M2 (ARM v8.2+) können wir Advanced SIMD annehmen
    features |= static_cast<uint32_t>(SIMDSupport::ASIMD);
    
    // Für Apple M1/M2 kann Crypto angenommen werden
    features |= static_cast<uint32_t>(SIMDSupport::CRYPTO);
    
    // CRC32 ist auch auf Apple M1/M2 verfügbar
    features |= static_cast<uint32_t>(SIMDSupport::CRC);
    
    // DOT-Product ist auf Apple M1/M2 verfügbar (ARMv8.2+)
    features |= static_cast<uint32_t>(SIMDSupport::DOTPROD);
    
    // SVE ist nicht auf Apple M1/M2 verfügbar
#else
    // x86/x64 Feature-Erkennung via CPUID
    #ifdef _MSC_VER
        // Windows/MSVC Implementation
        int cpu_info[4] = {-1};
        
        // Basic CPUID - SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2
        __cpuid(cpu_info, 1);
        
        // SSE-Familie erkennen
        if (cpu_info[3] & (1 << 25)) features |= static_cast<uint32_t>(SIMDSupport::SSE);
        if (cpu_info[3] & (1 << 26)) features |= static_cast<uint32_t>(SIMDSupport::SSE2);
        if (cpu_info[2] & (1 << 0))  features |= static_cast<uint32_t>(SIMDSupport::SSE3);
        if (cpu_info[2] & (1 << 9))  features |= static_cast<uint32_t>(SIMDSupport::SSSE3);
        if (cpu_info[2] & (1 << 19)) features |= static_cast<uint32_t>(SIMDSupport::SSE41);
        if (cpu_info[2] & (1 << 20)) features |= static_cast<uint32_t>(SIMDSupport::SSE42);
        
        // AES-NI und PCLMULQDQ erkennen
        if (cpu_info[2] & (1 << 25)) features |= static_cast<uint32_t>(SIMDSupport::AESNI);
        if (cpu_info[2] & (1 << 1))  features |= static_cast<uint32_t>(SIMDSupport::PCLMULQDQ);
        
        // AVX und AVX2 erkennen
        if (cpu_info[2] & (1 << 28)) features |= static_cast<uint32_t>(SIMDSupport::AVX);
        
        // AVX2 und AVX-512 erfordern zusätzliche CPUID-Abfragen
        __cpuid(cpu_info, 7);
        if (cpu_info[1] & (1 << 5))  features |= static_cast<uint32_t>(SIMDSupport::AVX2);
        if (cpu_info[1] & (1 << 16)) features |= static_cast<uint32_t>(SIMDSupport::AVX512F);
    #else
        // GCC/Clang Implementation
        // Standardmäßig sind SSE und SSE2 auf x86_64 immer verfügbar
        features |= static_cast<uint32_t>(SIMDSupport::SSE);
        features |= static_cast<uint32_t>(SIMDSupport::SSE2);
        
        // CPUID für erweiterte Features
        unsigned int eax, ebx, ecx, edx;
        
        // EAX=1 für SSE-Familie und AES-NI
        __asm__ __volatile__ (
            "cpuid"
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            : "a"(1)
        );
        
        // SSE-Familie erkennen (außer SSE/SSE2 die schon gesetzt sind)
        if (ecx & (1 << 0))  features |= static_cast<uint32_t>(SIMDSupport::SSE3);
        if (ecx & (1 << 9))  features |= static_cast<uint32_t>(SIMDSupport::SSSE3);
        if (ecx & (1 << 19)) features |= static_cast<uint32_t>(SIMDSupport::SSE41);
        if (ecx & (1 << 20)) features |= static_cast<uint32_t>(SIMDSupport::SSE42);
        
        // AES-NI und PCLMULQDQ erkennen
        if (ecx & (1 << 25)) features |= static_cast<uint32_t>(SIMDSupport::AESNI);
        if (ecx & (1 << 1))  features |= static_cast<uint32_t>(SIMDSupport::PCLMULQDQ);
        
        // AVX erkennen
        if (ecx & (1 << 28)) features |= static_cast<uint32_t>(SIMDSupport::AVX);
        
        // EAX=7 für AVX2 und AVX-512
        __asm__ __volatile__ (
            "cpuid"
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            : "a"(7), "c"(0)
        );
        
        // AVX2 und AVX-512 erkennen
        if (ebx & (1 << 5))  features |= static_cast<uint32_t>(SIMDSupport::AVX2);
        if (ebx & (1 << 16)) features |= static_cast<uint32_t>(SIMDSupport::AVX512F);
    #endif
#endif
    
    return features;
}

bool is_feature_supported(SIMDSupport feature) {
    uint32_t features = detect_cpu_features();
    return (features & static_cast<uint32_t>(feature)) != 0;
}

std::string features_to_string(uint32_t features) {
    std::stringstream ss;
    ss << "Unterstützte SIMD-Features: ";
    
#ifdef __ARM_NEON
    // ARM-spezifische Features
    if (features & static_cast<uint32_t>(SIMDSupport::NEON))
        ss << "NEON ";
    if (features & static_cast<uint32_t>(SIMDSupport::ASIMD))
        ss << "Advanced-SIMD ";
    if (features & static_cast<uint32_t>(SIMDSupport::SVE))
        ss << "SVE ";
    if (features & static_cast<uint32_t>(SIMDSupport::DOTPROD))
        ss << "Dot-Product ";
    if (features & static_cast<uint32_t>(SIMDSupport::CRYPTO))
        ss << "Crypto ";
    if (features & static_cast<uint32_t>(SIMDSupport::CRC))
        ss << "CRC ";
#else
    // x86/x64-spezifische Features
    if (features & static_cast<uint32_t>(SIMDSupport::SSE))
        ss << "SSE ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE2))
        ss << "SSE2 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE3))
        ss << "SSE3 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSSE3))
        ss << "SSSE3 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE41))
        ss << "SSE4.1 ";
    if (features & static_cast<uint32_t>(SIMDSupport::SSE42))
        ss << "SSE4.2 ";
    if (features & static_cast<uint32_t>(SIMDSupport::AVX))
        ss << "AVX ";
    if (features & static_cast<uint32_t>(SIMDSupport::AVX2))
        ss << "AVX2 ";
    if (features & static_cast<uint32_t>(SIMDSupport::AVX512F))
        ss << "AVX-512F ";
    if (features & static_cast<uint32_t>(SIMDSupport::AESNI))
        ss << "AES-NI ";
    if (features & static_cast<uint32_t>(SIMDSupport::PCLMULQDQ))
        ss << "PCLMULQDQ ";
#endif
    
    return ss.str();
}

} // namespace simd
} // namespace quicsand
