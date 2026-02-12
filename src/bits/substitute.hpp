#ifdef CRYPTO_BITS_SUBSTITUTE_HPP
#define CRYPTO_BITS_SUBSTITUTE_HPP

#include <functional>
#include <unordered_map>
#include <vector>

namespace crypcrypto::bits {

std::vector<uint8_t> substitute(const std::vector<uint8_t> &bits,
                                const std::unordered_map &s_block);

std::vector<uint8_t> substitute(const std::vector<uint8_t> &bits,
                                const std::function s_block);

} // namespace crypcrypto::bits

#endif // CRYPTO_BITS_SUBSTITUTE_HPP
