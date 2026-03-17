#ifndef CRYPTO_CIPHER_CONTEXT_HPP
#define CRYPTO_CIPHER_CONTEXT_HPP

#include "core/symmetric_cipher.hpp"
#include "mode/cipher_mode.hpp"
#include "padding/padding.hpp"

#include <future>
#include <memory>
#include <string>

namespace crypto {

  enum class EncryptionMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RD,
  };

  enum class PaddingScheme {
    Zeros,
    AnsiX923,
    PKCS7,
    ISO10126,
  };

  class CipherContext {
  public:
    CipherContext(std::unique_ptr<core::SymmetricCipher> cipher,
                  const EncryptionMode enc_mode, const PaddingScheme pad_scheme,
                  core::Bytes iv = {})
        : m_cipher(std::move(cipher)),
          m_enc_mode(enc_mode),
          m_pad_scheme(pad_scheme),
          m_iv(std::move(iv)) {
      if (!m_cipher) {
        throw std::invalid_argument("CipherContext: cipher must not be null");
      }
      build_mode();
      build_padding();
    }

    void set_encryption_key(const core::Bytes &key) const;
    void set_decryption_key(const core::Bytes &key) const;

    void encrypt(const core::Bytes &input, core::Bytes &output, size_t threads = 1) const;
    void decrypt(const core::Bytes &input, core::Bytes &output, size_t threads = 1) const;

    std::future<void> encrypt_file(const std::string &input_path,
                                   const std::string &output_path,
                                   size_t threads = 1) const;
    std::future<void> decrypt_file(const std::string &input_path,
                                   const std::string &output_path,
                                   size_t threads = 1) const;

  private:
    static core::Bytes read_file(const std::string &path);
    static void write_file(const std::string &path, const core::Bytes &data);

    void build_mode();
    void build_padding();

    std::unique_ptr<core::SymmetricCipher> m_cipher;
    std::unique_ptr<mode::CipherMode>      m_mode;
    std::unique_ptr<padding::PaddingMode>  m_padding;
    EncryptionMode m_enc_mode;
    PaddingScheme  m_pad_scheme;
    core::Bytes    m_iv;
  };

} // namespace crypto

#endif