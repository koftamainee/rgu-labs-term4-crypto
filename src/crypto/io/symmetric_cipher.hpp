#ifndef CRYPTO_IO_SYMMETRIC_CIPHER_HPP
#define CRYPTO_IO_SYMMETRIC_CIPHER_HPP

#include "core/symmetric_cipher.hpp"
#include <memory>
#include <string>
#include <vector>

namespace crypto::io {

class SymmetricCipherIO {
public:
  explicit SymmetricCipherIO(std::unique_ptr<core::SymmetricCipher> cipher);

  std::vector<uint8_t> encrypt_bytes(const std::vector<uint8_t> &data);
  std::vector<uint8_t> decrypt_bytes(const std::vector<uint8_t> &data);

  void encrypt_file(const std::string &input_path,
                    const std::string &output_path);
  void decrypt_file(const std::string &input_path,
                    const std::string &output_path);

  void set_encryption_key(const std::vector<uint8_t> &key);
  void set_decryption_key(const std::vector<uint8_t> &key);

private:
  std::unique_ptr<core::SymmetricCipher> m_cipher;
  size_t m_block_size;
};

} // namespace crypto::io

#endif // CRYPTO_IO_SYMMETRIC_CIPHER_HPP
