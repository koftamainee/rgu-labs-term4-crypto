#ifndef CRYPTO_PADDING_PADDING_HPP
#define CRYPTO_PADDING_PADDING_HPP

#include "core/crypto.hpp"

namespace crypto::padding {

  class PaddingMode {
  public:
    virtual ~PaddingMode() = default;
    virtual core::Bytes apply(const core::Bytes &data, size_t block_size) const = 0;
    virtual core::Bytes remove(const core::Bytes &data, size_t block_size) const = 0;
  };

  class ZerosPadding final : public PaddingMode {
  public:
    core::Bytes apply(const core::Bytes &data, size_t block_size) const override;
    core::Bytes remove(const core::Bytes &data, size_t block_size) const override;
  };

  class AnsiX923Padding final : public PaddingMode {
  public:
    core::Bytes apply(const core::Bytes &data, size_t block_size) const override;
    core::Bytes remove(const core::Bytes &data, size_t block_size) const override;
  };

  class PKCS7Padding final : public PaddingMode {
  public:
    core::Bytes apply(const core::Bytes &data, size_t block_size) const override;
    core::Bytes remove(const core::Bytes &data, size_t block_size) const override;
  };

  class ISO10126Padding final : public PaddingMode {
  public:
    explicit ISO10126Padding(uint64_t seed = 0);
    core::Bytes apply(const core::Bytes &data, size_t block_size) const override;
    core::Bytes remove(const core::Bytes &data, size_t block_size) const override;

  private:
    uint64_t m_seed;
  };

} // namespace crypto::padding

#endif