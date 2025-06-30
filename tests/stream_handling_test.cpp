#include "../optimize/unified_optimizations.hpp"
#include <gtest/gtest.h>

using namespace quicfuscate;

TEST(StreamOptimizerTest, PriorityAndWindow) {
    optimize::QuicStreamOptimizer opt;
    optimize::StreamOptimizationConfig cfg{};
    opt.initialize(cfg);
    ASSERT_TRUE(opt.set_stream_priority(1, 10));
    EXPECT_TRUE(opt.update_flow_control_window(1, 5000));
    EXPECT_TRUE(opt.can_send_data(1, 1000));
    EXPECT_GT(opt.get_optimal_chunk_size(1), 0u);
}
