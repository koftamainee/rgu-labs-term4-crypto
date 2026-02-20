#ifndef CRYPTO_CORE_FEISTEL_ROUND_FUNCTION_HPP
#define CRYPTO_CORE_FEISTEL_ROUND_FUNCTION_HPP

#include "crypto.hpp"

namespace crypto::core {

class FeistelRoundFunction {
public:
  virtual ~FeistelRoundFunction() = default;
  virtual Bytes apply(const Bytes &half, const Bytes &roundKey) const = 0;
};
} // namespace crypto::core

#endif // !CRYPTO_CORE_FEISTEL_ROUND_FUNCTION_HPP
