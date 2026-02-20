#ifndef CRYPTO_CORE_KEY_EXPANSION_HPP
#define CRYPTO_CORE_KEY_EXPANSION_HPP

#include "crypto.hpp"

namespace crypto::core {
class KeyExpansion {
public:
  virtual ~KeyExpansion() = default;
  virtual RoundKeys expand(const Bytes &key) const = 0;
};
} // namespace crypto::core
#endif // !CRYPTO_CORE_KEY_EXPANSION_HPP
