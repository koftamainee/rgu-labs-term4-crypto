#ifndef CRYPTO_BITS_UTILS_HPP
#define CRYPTO_BITS_UTILS_HPP

#include <cstdint>
#include <vector>

namespace crypto::bits {

enum class MaskType {
  Or,
  And,
  Xor,
};

std::vector<uint8_t> rotate_left(const std::vector<uint8_t> &bits,
                                 size_t n_bits, size_t shift);

std::vector<uint8_t> rotate_right(const std::vector<uint8_t> &bits,
                                  size_t n_bits, size_t shift);

std::vector<uint8_t> apply_mask(const std::vector<uint8_t> &bits,
                                const std::vector<uint8_t> &mask,
                                size_t mask_bits, MaskType mask_type);

std::vector<uint8_t> get_bits(const std::vector<uint8_t> &bits, size_t i,
                              size_t j);

std::vector<uint8_t> swap_bits(const std::vector<uint8_t> &bits, size_t i,
                               size_t j);

std::vector<uint8_t> set_bit(const std::vector<uint8_t> &bits, size_t i,
                             bool value);

} // namespace crypto::bits

#endif // !CRYPTO_BITS_UTILS_HPP
