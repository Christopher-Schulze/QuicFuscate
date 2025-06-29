#include "core/quic_core_types.hpp"
#include <cassert>

using namespace quicfuscate;

int main() {
    QuicUnifiedManager::instance().shutdown();
    auto result = QuicUnifiedManager::instance().get_integration();
    assert(!result.success());
    assert(result.error().code == ErrorCode::INVALID_STATE);
    return 0;
}
