#include "../../../core/error_handling.hpp"
extern "C" int quic_error_success_code() {
    return static_cast<int>(quicfuscate::ErrorCode::SUCCESS);
}
