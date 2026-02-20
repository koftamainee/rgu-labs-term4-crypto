#ifndef CRYPTO_ALGORITHMS_DES_HPP
#define CRYPTO_ALGORITHMS_DES_HPP

#include "core/feistel_network_wrapper.hpp"
#include "core/feistel_round_function.hpp"
#include "core/key_expansion.hpp"

namespace crypto::des {

class DES final : public core::FeistelNetworkWrapper {
public:
  explicit DES();

  size_t block_size() const override;

protected:
  void before_rounds(core::Bytes &block, bool encrypting) const override;
  void after_rounds(core::Bytes &block, bool encrypting) const override;

public:
  class KeyExpansionDES : public core::KeyExpansion {
  public:
    core::RoundKeys expand(const core::Bytes &key) const override;
  };

  class FeistelRoundFunctionDES : public core::FeistelRoundFunction {
  public:
    core::Bytes apply(const core::Bytes &half_block,
                      const core::Bytes &round_key) const override;
  };

private:
  core::FeistelNetwork m_network;
  KeyExpansionDES m_key_expansion;
  FeistelRoundFunctionDES m_round_function;
};

} // namespace crypto::des

#endif // CRYPTO_ALGORITHMS_DES_HPP
