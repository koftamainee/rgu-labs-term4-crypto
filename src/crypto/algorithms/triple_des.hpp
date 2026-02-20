#ifndef CRYPTO_ALGHORITMS_TRIPLE_DES_HPP
#define CRYPTO_ALGHORITMS_TRIPLE_DES_HPP

#include "des.hpp"

namespace crypto::des {

enum class TripleDESMode {
  EEE3,
  EDE3,
  EEE2,
  EDE2,
};

class TripleDES final : public core::SymmetricCipher {
public:
  explicit TripleDES(TripleDESMode mode);

  void set_encryption_key(const core::Bytes &key) override;
  void set_decryption_key(const core::Bytes &key) override;

  core::Bytes encrypt_block(const core::Bytes &block) const override;
  core::Bytes decrypt_block(const core::Bytes &block) const override;

  size_t block_size() const override;

private:
  DES m_des1;
  DES m_des2;
  DES m_des3;

  core::Bytes m_key1;
  core::Bytes m_key2;
  core::Bytes m_key3;

  TripleDESMode m_mode;

  core::Bytes process_block(const core::Bytes &block, bool encrypting) const;
};

} // namespace crypto::des

#endif // !CRYPTO_ALGHORITMS_TRIPLE_DES_HPP
