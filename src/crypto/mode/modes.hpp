#ifndef CRYPTO_MODE_MODES_HPP
#define CRYPTO_MODE_MODES_HPP

#include "mode/cipher_mode.hpp"
#include "core/crypto.hpp"

namespace crypto::mode {

  class ECB final : public CipherMode {
  public:
    void encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                 core::Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                 core::Bytes &output, size_t threads) override;

  private:
    static void process(core::SymmetricCipher &cipher, const core::Bytes &input,
                 core::Bytes &output, size_t threads, bool encrypting);
  };

  class CBC final : public CipherMode {
  public:
    explicit CBC(core::Bytes iv = {});

    void encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                 core::Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                 core::Bytes &output, size_t threads) override;

  private:
    core::Bytes get_iv(size_t bs) const;
    core::Bytes m_iv;
  };

  class PCBC final : public CipherMode {
  public:
    explicit PCBC(core::Bytes iv = {});

    void encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                 core::Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                 core::Bytes &output, size_t threads) override;

  private:
    core::Bytes get_iv(size_t bs) const;
    core::Bytes m_iv;
  };

} // namespace crypto::mode

#endif