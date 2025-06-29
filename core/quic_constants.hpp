#ifndef QUIC_CONSTANTS_HPP
#define QUIC_CONSTANTS_HPP

#include <cstdint>
#include <cstddef>

namespace quicfuscate {

// RFC 8899 recommends a minimum datagram payload of 1200 bytes to
// avoid IPv6 fragmentation and ensure interoperability across paths.
inline constexpr uint16_t DEFAULT_MIN_MTU = 1200;

// Typical Ethernet MTU used as an upper bound for probing.
inline constexpr uint16_t DEFAULT_MAX_MTU = 1500;

// Common starting MTU for QUIC before the path has been validated.
inline constexpr uint16_t DEFAULT_INITIAL_MTU = 1350;

// Increment used when probing for a larger MTU.
inline constexpr uint16_t DEFAULT_MTU_STEP_SIZE = 10;

// Maximum datagram size to bundle without exceeding DEFAULT_MIN_MTU.
inline constexpr size_t DEFAULT_MAX_BUNDLE_SIZE = DEFAULT_MIN_MTU;

// Maximum fragment size for DPI evasion kept at the minimum MTU.
inline constexpr size_t DEFAULT_MAX_FRAGMENT_SIZE = DEFAULT_MIN_MTU;

// Timeout waiting for a PATH_CHALLENGE response during migration (ms).
inline constexpr uint64_t DEFAULT_PATH_CHALLENGE_TIMEOUT_MS = 500;

// Maximum allowed migration attempts before giving up.
inline constexpr uint64_t DEFAULT_MAX_MIGRATION_ATTEMPTS = 5;

// Cooldown period between migration attempts (ms).
inline constexpr uint64_t DEFAULT_MIGRATION_COOLDOWN_MS = 1000;

// Timeout waiting for MTU probe acknowledgements (ms).
inline constexpr uint32_t DEFAULT_MTU_PROBE_TIMEOUT_MS = 1000;

// Number of consecutive probe failures before assuming a black hole.
inline constexpr uint16_t DEFAULT_BLACKHOLE_DETECTION_THRESHOLD = 2;
// Alternative threshold used by the path MTU manager.
inline constexpr uint8_t DEFAULT_PATH_BLACKHOLE_THRESHOLD = 3;

// Interval for adaptive MTU checks based on network feedback (ms).
inline constexpr uint32_t DEFAULT_ADAPTIVE_CHECK_INTERVAL_MS = 10000;

// Periodic probe interval after MTU was validated (ms).
inline constexpr uint32_t DEFAULT_PERIODIC_PROBE_INTERVAL_MS = 60000;

// Expiry for outstanding probes when no response is seen (ms).
inline constexpr uint32_t DEFAULT_PROBE_TIMEOUT_MS = 2000;

// Minimum bandwidth considered acceptable for a migration path (kbps).
inline constexpr uint32_t DEFAULT_MIN_BANDWIDTH_THRESHOLD_KBPS = 1000;

// Maximum RTT considered acceptable when evaluating paths (ms).
inline constexpr uint32_t DEFAULT_MAX_RTT_THRESHOLD_MS = 200;

// Maximum delay inserted for timing randomization (microseconds).
inline constexpr uint32_t DEFAULT_DPI_MAX_DELAY_US = 5000;

// Minimum delay inserted for timing randomization (microseconds).
inline constexpr uint32_t DEFAULT_DPI_MIN_DELAY_US = 100;

// Maximum time a migration event may be delayed to appear natural (ms).
inline constexpr uint32_t DEFAULT_MAX_MIGRATION_DELAY_MS = 2000;
// Minimum delay used when randomizing migration timing (ms).
inline constexpr uint32_t DEFAULT_MIN_MIGRATION_DELAY_MS = 100;

// Default cap on cached sessions used for 0-RTT handshakes.
inline constexpr size_t DEFAULT_MAX_CACHED_SESSIONS = 1000;

// Default maximum number of concurrent streams allowed.
inline constexpr size_t DEFAULT_MAX_CONCURRENT_STREAMS = 1000;

// Default number of iterations for PBKDF2 operations.
inline constexpr size_t DEFAULT_PBKDF2_ITERATIONS = 10000;

} // namespace quicfuscate

#endif // QUIC_CONSTANTS_HPP
