#include "mode/modes.hpp"
#include "core/symmetric_cipher.hpp"

#include <random>
#include <stdexcept>
#include <thread>
#include <vector>

namespace crypto::mode {
  namespace {
    void add_to_block(core::Bytes& block, uint64_t delta) {
      uint64_t carry = delta;
      for (size_t i = 0; i < block.size() && carry != 0; ++i) {
        uint16_t sum = static_cast<uint16_t>(block[i]) + static_cast<uint16_t>(carry & 0xFF);
        block[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = (carry >> 8) + (sum >> 8);
      }
    }

    core::Bytes xor_blocks(const core::Bytes& a, const core::Bytes& b) {
      if (a.size() != b.size()) {
        throw std::invalid_argument("xor_blocks: size mismatch");
      }
      core::Bytes result(a.size());
      for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
      }
      return result;
    }

    std::vector<std::pair<size_t, size_t>> split_work(size_t n_blocks,
                                                      size_t num_threads) {
      if (num_threads == 0) num_threads = 1;
      if (num_threads > n_blocks) num_threads = n_blocks;

      std::vector<std::pair<size_t, size_t>> ranges;
      ranges.reserve(num_threads);
      size_t base = n_blocks / num_threads;
      size_t extra = n_blocks % num_threads;
      size_t start = 0;
      for (size_t t = 0; t < num_threads; ++t) {
        size_t count = base + (t < extra ? 1 : 0);
        ranges.emplace_back(start, start + count);
        start += count;
      }
      return ranges;
    }

    core::Bytes validated_iv(const core::Bytes& iv, size_t bs,
                             const char* mode_name) {
      if (iv.empty()) return core::Bytes(bs, 0x00);
      if (iv.size() != bs)
        throw std::invalid_argument(std::string(mode_name) +
          ": IV size does not match block size");
      return iv;
    }
  } // namespace

  void ECB::encrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t threads) {
    process(cipher, input, output, threads, true);
  }

  void ECB::decrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t threads) {
    process(cipher, input, output, threads, false);
  }

  void ECB::process(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t threads, bool encrypting) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0) {
      throw std::invalid_argument("ECB: input not block-aligned");
    }
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    auto ranges = split_work(n_blocks, threads);
    std::vector<std::thread> workers;
    workers.reserve(ranges.size());

    for (auto [start, end] : ranges) {
      workers.emplace_back([&, start, end]() {
        for (size_t b = start; b < end; ++b) {
          core::Bytes block(input.begin() + b * bs,
                            input.begin() + (b + 1) * bs);
          core::Bytes result = encrypting
                                 ? cipher.encrypt_block(block)
                                 : cipher.decrypt_block(block);
          std::copy(result.begin(), result.end(), output.begin() + b * bs);
        }
      });
    }
    for (auto& w : workers) { w.join(); }
  }

  CBC::CBC(core::Bytes iv) : m_iv(std::move(iv)) {}

  core::Bytes CBC::get_iv(size_t bs) const {
    return validated_iv(m_iv, bs, "CBC");
  }

  void CBC::encrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CBC: input not block-aligned");

    core::Bytes iv = get_iv(bs);
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) {
      core::Bytes block(input.begin() + b * bs, input.begin() + (b + 1) * bs);
      block = xor_blocks(block, iv);
      core::Bytes enc = cipher.encrypt_block(block);
      std::copy(enc.begin(), enc.end(), output.begin() + b * bs);
      iv = enc;
    }
  }

  void CBC::decrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t threads) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CBC: input not block-aligned");

    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    std::vector<core::Bytes> ivs(n_blocks);
    ivs[0] = get_iv(bs);
    for (size_t b = 1; b < n_blocks; ++b)
      ivs[b] = core::Bytes(input.begin() + (b - 1) * bs,
                           input.begin() + b * bs);

    auto ranges = split_work(n_blocks, threads);
    std::vector<std::thread> workers;
    workers.reserve(ranges.size());

    for (auto [start, end] : ranges) {
      workers.emplace_back([&, start, end]() {
        for (size_t b = start; b < end; ++b) {
          core::Bytes block(input.begin() + b * bs,
                            input.begin() + (b + 1) * bs);
          core::Bytes dec = cipher.decrypt_block(block);
          dec = xor_blocks(dec, ivs[b]);
          std::copy(dec.begin(), dec.end(), output.begin() + b * bs);
        }
      });
    }
    for (auto& w : workers) w.join();
  }

  PCBC::PCBC(core::Bytes iv) : m_iv(std::move(iv)) {}

  core::Bytes PCBC::get_iv(size_t bs) const {
    return validated_iv(m_iv, bs, "PCBC");
  }

  void PCBC::encrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                     core::Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0) {
      throw std::invalid_argument("PCBC: input not block-aligned");
    }
    core::Bytes iv = get_iv(bs);
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) {
      core::Bytes plain(input.begin() + b * bs, input.begin() + (b + 1) * bs);
      core::Bytes enc = cipher.encrypt_block(xor_blocks(plain, iv));
      std::copy(enc.begin(), enc.end(), output.begin() + b * bs);
      iv = xor_blocks(plain, enc);
    }
  }

  void PCBC::decrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                     core::Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("PCBC: input not block-aligned");

    core::Bytes iv = get_iv(bs);
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) {
      core::Bytes cipher_block(input.begin() + b * bs,
                               input.begin() + (b + 1) * bs);
      core::Bytes plain = xor_blocks(cipher.decrypt_block(cipher_block), iv);
      std::copy(plain.begin(), plain.end(), output.begin() + b * bs);
      iv = xor_blocks(plain, cipher_block);
    }
  }

  CFB::CFB(core::Bytes iv) : m_iv(std::move(iv)) {}

  core::Bytes CFB::get_iv(size_t bs) const {
    return validated_iv(m_iv, bs, "CFB");
  }

  void CFB::encrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CFB: input not block-aligned");

    core::Bytes iv = get_iv(bs);
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) {
      core::Bytes plain(input.begin() + b * bs, input.begin() + (b + 1) * bs);
      core::Bytes enc = xor_blocks(cipher.encrypt_block(iv), plain);
      std::copy(enc.begin(), enc.end(), output.begin() + b * bs);
      iv = enc;
    }
  }

  void CFB::decrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CFB: input not block-aligned");

    core::Bytes iv = get_iv(bs);
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) {
      core::Bytes cipher_block(input.begin() + b * bs,
                               input.begin() + (b + 1) * bs);
      core::Bytes plain = xor_blocks(cipher.encrypt_block(iv), cipher_block);
      std::copy(plain.begin(), plain.end(), output.begin() + b * bs);
      iv = cipher_block;
    }
  }

  OFB::OFB(core::Bytes iv) : m_iv(std::move(iv)) {}

  core::Bytes OFB::get_iv(size_t bs) const {
    return validated_iv(m_iv, bs, "OFB");
  }

  void OFB::process(core::SymmetricCipher& cipher, const core::Bytes& iv,
                    const core::Bytes& input, core::Bytes& output) {
    const size_t bs = cipher.block_size();
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    core::Bytes keystream = iv;
    for (size_t b = 0; b < n_blocks; ++b) {
      keystream = cipher.encrypt_block(keystream);
      core::Bytes plain(input.begin() + b * bs, input.begin() + (b + 1) * bs);
      core::Bytes out_block = xor_blocks(plain, keystream);
      std::copy(out_block.begin(), out_block.end(), output.begin() + b * bs);
    }
  }

  void OFB::encrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("OFB: input not block-aligned");
    process(cipher, get_iv(bs), input, output);
  }

  void OFB::decrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("OFB: input not block-aligned");
    process(cipher, get_iv(bs), input, output);
  }

  CTR::CTR(core::Bytes nonce) : m_nonce(std::move(nonce)) {}

  core::Bytes CTR::make_counter_block(const core::Bytes& nonce,
                                      uint64_t counter, size_t bs) {
    if (nonce.size() != 0 && nonce.size() != bs - 8)
      throw std::invalid_argument(
        "CTR: nonce size must be 0 or (block_size - 8)");

    core::Bytes block(bs, 0x00);

    if (!nonce.empty())
      std::copy(nonce.begin(), nonce.end(), block.begin());

    for (int i = 7; i >= 0; --i) {
      block[bs - 8 + i] = static_cast<uint8_t>(counter & 0xFF);
      counter >>= 8;
    }
    return block;
  }

  void CTR::process(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t threads) const {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CTR: input not block-aligned");

    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    auto ranges = split_work(n_blocks, threads);
    std::vector<std::thread> workers;
    workers.reserve(ranges.size());

    for (auto [start, end] : ranges) {
      workers.emplace_back([&, start, end]() {
        for (size_t b = start; b < end; ++b) {
          core::Bytes counter_block = make_counter_block(m_nonce, b, bs);
          core::Bytes keystream = cipher.encrypt_block(counter_block);
          core::Bytes plain(input.begin() + b * bs,
                            input.begin() + (b + 1) * bs);
          core::Bytes out_block = xor_blocks(plain, keystream);
          std::copy(out_block.begin(), out_block.end(),
                    output.begin() + b * bs);
        }
      });
    }
    for (auto& w : workers) w.join();
  }

  void CTR::encrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t threads) {
    process(cipher, input, output, threads);
  }

  void CTR::decrypt(core::SymmetricCipher& cipher, const core::Bytes& input,
                    core::Bytes& output, size_t threads) {
    process(cipher, input, output, threads);
  }


  RD::RD(uint64_t seed) : m_seed(seed) {}

  void RD::encrypt(core::SymmetricCipher& cipher,
                   const core::Bytes& input,
                   core::Bytes& output,
                   size_t) {
    const size_t bs = cipher.block_size();

    if (input.size() % bs != 0)
      throw std::invalid_argument("RandomDelta: input not block-aligned");

    const size_t n_blocks = input.size() / bs;

    std::mt19937_64 rng(m_seed != 0
                          ? m_seed
                          : static_cast<uint64_t>(std::random_device{}()));

    core::Bytes initial(bs);
    for (auto& byte : initial)
      byte = static_cast<uint8_t>(rng() & 0xFF);

    const uint64_t delta = rng();

    core::Bytes delta_block(bs, 0);
    for (size_t i = 0; i < 8 && i < bs; ++i)
      delta_block[i] = static_cast<uint8_t>((delta >> (i * 8)) & 0xFF);

    output.resize((n_blocks + 2) * bs);

    core::Bytes enc_initial = cipher.encrypt_block(initial);
    std::copy(enc_initial.begin(), enc_initial.end(), output.begin());

    core::Bytes enc_delta = cipher.encrypt_block(delta_block);
    std::copy(enc_delta.begin(), enc_delta.end(), output.begin() + bs);

    core::Bytes counter = initial;
    for (size_t b = 0; b < n_blocks; ++b) {
      add_to_block(counter, delta);

      core::Bytes plain(input.begin() + b * bs, input.begin() + (b + 1) * bs);
      core::Bytes masked = xor_blocks(plain, counter);
      core::Bytes enc = cipher.encrypt_block(masked);

      std::copy(enc.begin(), enc.end(), output.begin() + (b + 2) * bs);
    }
  }

  void RD::decrypt(core::SymmetricCipher& cipher,
                   const core::Bytes& input,
                   core::Bytes& output,
                   size_t) {
    const size_t bs = cipher.block_size();

    if (input.size() < 3 * bs || input.size() % bs != 0)
      throw std::invalid_argument("RandomDelta: invalid ciphertext size");

    const size_t n_blocks = input.size() / bs - 2;
    output.resize(n_blocks * bs);

    core::Bytes enc_initial(input.begin(), input.begin() + bs);
    core::Bytes initial = cipher.decrypt_block(enc_initial);

    core::Bytes enc_delta(input.begin() + bs, input.begin() + 2 * bs);
    core::Bytes delta_block = cipher.decrypt_block(enc_delta);

    uint64_t delta = 0;
    for (size_t i = 0; i < 8 && i < bs; ++i)
      delta |= static_cast<uint64_t>(delta_block[i]) << (i * 8);

    core::Bytes counter = initial;
    for (size_t b = 0; b < n_blocks; ++b) {
      add_to_block(counter, delta);

      core::Bytes enc_block(input.begin() + (b + 2) * bs,
                            input.begin() + (b + 3) * bs);
      core::Bytes masked = cipher.decrypt_block(enc_block);
      core::Bytes plain = xor_blocks(masked, counter);

      std::copy(plain.begin(), plain.end(), output.begin() + b * bs);
    }
  }
} // namespace crypto::mode
