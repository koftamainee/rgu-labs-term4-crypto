#ifndef CRYPTO_CORE_FEISTEL_NETWORK_WRAPPER_HPP
#define CRYPTO_CORE_FEISTEL_NETWORK_WRAPPER_HPP

#include "feistel_network.hpp"
#include "symmetric_cipher.hpp"

namespace crypto::core {

class FeistelNetworkWrapper : public SymmetricCipher {
public:
  explicit FeistelNetworkWrapper(FeistelNetwork &network);

  void set_encryption_key(const Bytes &key) override;
  void set_decryption_key(const Bytes &key) override;

  Bytes encrypt_block(const Bytes &plain) const override;
  Bytes decrypt_block(const Bytes &cipher) const override;

protected:
  virtual void before_rounds(Bytes &block, bool encrypting) const;
  virtual void after_rounds(Bytes &block, bool encrypting) const;
  virtual void on_key_set(const Bytes &key, bool encrypting);

private:
  FeistelNetwork &m_network;
};

} // namespace crypto::core

#endif // !CRYPTO_CORE_FEISTEL_NETWORK_WRAPPER_HPP
