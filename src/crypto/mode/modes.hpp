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

class CFB final : public CipherMode {
public:
  explicit CFB(core::Bytes iv = {});
  void encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;
  void decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;

private:
  core::Bytes get_iv(size_t bs) const;
  core::Bytes m_iv;
};

class OFB final : public CipherMode {
public:
  explicit OFB(core::Bytes iv = {});
  void encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;
  void decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;

private:
  core::Bytes get_iv(size_t bs) const;
  static void process(core::SymmetricCipher &cipher, const core::Bytes &iv,
                      const core::Bytes &input, core::Bytes &output);
  core::Bytes m_iv;
};

class CTR final : public CipherMode {
public:
  explicit CTR(core::Bytes nonce = {});
  void encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;
  void decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;

private:
  void process(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) const;
  static core::Bytes make_counter_block(const core::Bytes &nonce, uint64_t counter,
                                        size_t bs);
  core::Bytes m_nonce;
};


class RD final : public CipherMode {
public:
  explicit RD(uint64_t seed = 0);
  void encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;
  void decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
               core::Bytes &output, size_t threads) override;

private:
  uint64_t m_seed;
};

} // namespace crypto::mode

#endif // CRYPTO_MODE_MODES_HPP