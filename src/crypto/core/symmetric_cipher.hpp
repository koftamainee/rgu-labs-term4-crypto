#ifndef CRYPTO_CORE_SYMMETRIC_CIPHER_HPP
#define CRYPTO_CORE_SYMMETRIC_CIPHER_HPP

#include "crypto.hpp"

namespace crypto::core {

class SymmetricCipher {
public:
  virtual ~SymmetricCipher() = default;

  virtual void set_encryption_key(const Bytes &) = 0;
  virtual void set_decryption_key(const Bytes &) = 0;

  virtual Bytes encrypt_block(const Bytes &) const = 0;
  virtual Bytes decrypt_block(const Bytes &) const = 0;

  virtual size_t block_size() const = 0;
};
} // namespace crypto::core

#endif // !CRYPTO_CORE_SYMMETRIC_CIPHER_HPP
