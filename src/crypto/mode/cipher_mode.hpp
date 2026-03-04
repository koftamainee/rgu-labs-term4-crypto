#ifndef CRYPTO_MODE_CIPHER_MODE_HPP
#define CRYPTO_MODE_CIPHER_MODE_HPP

#include "core/symmetric_cipher.hpp"
#include "core/crypto.hpp"
#include <cstddef>

namespace crypto::mode {

  class CipherMode {
  public:
    virtual ~CipherMode() = default;

    virtual void encrypt(
        core::SymmetricCipher &cipher,
        const core::Bytes &input,
        core::Bytes &output,
        size_t threads) = 0;

    virtual void decrypt(
        core::SymmetricCipher &cipher,
        const core::Bytes &input,
        core::Bytes &output,
        size_t threads) = 0;
  };

} // namespace crypto::mode

#endif