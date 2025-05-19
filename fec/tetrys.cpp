#include <vector>

namespace quicsand::fec {

class Tetrys {
public:
    Tetrys();
    std::vector<uint8_t> encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode(const std::vector<uint8_t>& encoded_data);
    // Implement FEC-Logik hier
};

} // namespace quicsand::fec
