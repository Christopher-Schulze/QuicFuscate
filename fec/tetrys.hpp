#ifndef TETRYS_HPP
#define TETRYS_HPP

#include <vector>

namespace quicsand::fec {

class Tetrys {
public:
    Tetrys();
    std::vector<uint8_t> encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode(const std::vector<uint8_t>& encoded_data);
};

} // namespace quicsand::fec

#endif // TETRYS_HPP
