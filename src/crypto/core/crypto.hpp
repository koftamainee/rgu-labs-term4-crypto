#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <cstdint>
#include <vector>

namespace crypto::core {
using Byte = uint8_t;
using Bytes = std::vector<Byte>;
using RoundKeys = std::vector<Bytes>;
} // namespace crypto::core

#endif // !CRYPTO_HPP
