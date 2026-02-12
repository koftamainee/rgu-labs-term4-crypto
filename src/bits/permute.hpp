#ifndef BITS_PERMUTATIONS_HPP
#define BITS_PERMUTATIONS_HPP

#include <cstdint>
#include <vector>

namespace crypto::bits {
enum class BitOrder {
  LittleEndian,
  BigEndian,
};

enum class BitIndexBase {
  Zero,
  One,
};

std::vector<uint8_t> permute(const std::vector<uint8_t> &bits,
                             const std::vector<size_t> &p_block, BitOrder order,
                             BitIndexBase index_base);

} // namespace crypto::bits

#endif
