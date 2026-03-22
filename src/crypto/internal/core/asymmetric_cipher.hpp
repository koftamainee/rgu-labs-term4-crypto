#ifndef CRYPTO_CORE_ASYMMETRIC_CIPHER_HPP
#define CRYPTO_CORE_ASYMMETRIC_CIPHER_HPP

#include "../bytes.hpp"

namespace crypto::core {

  class AsymmetricCipher {
  public:
    virtual ~AsymmetricCipher() = default;

    virtual Bytes encrypt(const Bytes& plaintext) const = 0;
    virtual Bytes decrypt(const Bytes& ciphertext) const = 0;
  };

} // namespace crypto::core

#endif // CRYPTO_CORE_ASYMMETRIC_CIPHER_HPP