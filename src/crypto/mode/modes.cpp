#include "mode/modes.hpp"
#include "core/symmetric_cipher.hpp"

#include <stdexcept>
#include <thread>
#include <vector>

namespace crypto::mode {

namespace {

core::Bytes xor_blocks(const core::Bytes &a, const core::Bytes &b) {
  if (a.size() != b.size()) {
    throw std::invalid_argument("xor_blocks: size mismatch");
  }
  core::Bytes result(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

std::vector<std::pair<size_t, size_t>> split_work(size_t n_blocks, size_t num_threads) {
  if (num_threads == 0) {
    num_threads = 1;
  }
  if (num_threads > n_blocks) {
    num_threads = n_blocks;
  }
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

} // namespace

void ECB::encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                  core::Bytes &output, size_t threads) {
  process(cipher, input, output, threads, true);
}

void ECB::decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                  core::Bytes &output, size_t threads) {
  process(cipher, input, output, threads, false);
}

void ECB::process(core::SymmetricCipher &cipher, const core::Bytes &input,
                  core::Bytes &output, size_t threads, bool encrypting) {
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
        core::Bytes block(input.begin() + b * bs, input.begin() + (b + 1) * bs);
        core::Bytes result = encrypting ? cipher.encrypt_block(block)
                                        : cipher.decrypt_block(block);
        std::copy(result.begin(), result.end(), output.begin() + b * bs);
      }
    });
  }
  for (auto &w : workers) {
    w.join();
  }
}

CBC::CBC(core::Bytes iv) : m_iv(std::move(iv)) {}

core::Bytes CBC::get_iv(size_t bs) const {
  if (m_iv.empty()) {
    return core::Bytes(bs, 0x00);
  }
  if (m_iv.size() != bs) {
    throw std::invalid_argument("CBC: IV size does not match block size");
  }
  return m_iv;
}

void CBC::encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                  core::Bytes &output, size_t) {
  const size_t bs = cipher.block_size();
  if (input.size() % bs != 0) {
    throw std::invalid_argument("CBC: input not block-aligned");
  }
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

void CBC::decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                  core::Bytes &output, size_t threads) {
  const size_t bs = cipher.block_size();
  if (input.size() % bs != 0) {
    throw std::invalid_argument("CBC: input not block-aligned");
  }
  const size_t n_blocks = input.size() / bs;
  output.resize(input.size());

  std::vector<core::Bytes> ivs(n_blocks);
  ivs[0] = get_iv(bs);
  for (size_t b = 1; b < n_blocks; ++b) {
    ivs[b] = core::Bytes(input.begin() + (b - 1) * bs, input.begin() + b * bs);
  }

  auto ranges = split_work(n_blocks, threads);
  std::vector<std::thread> workers;
  workers.reserve(ranges.size());

  for (auto [start, end] : ranges) {
    workers.emplace_back([&, start, end]() {
      for (size_t b = start; b < end; ++b) {
        core::Bytes block(input.begin() + b * bs, input.begin() + (b + 1) * bs);
        core::Bytes dec = cipher.decrypt_block(block);
        dec = xor_blocks(dec, ivs[b]);
        std::copy(dec.begin(), dec.end(), output.begin() + b * bs);
      }
    });
  }
  for (auto &w : workers) {
    w.join();
  }
}

PCBC::PCBC(core::Bytes iv) : m_iv(std::move(iv)) {}

core::Bytes PCBC::get_iv(size_t bs) const {
  if (m_iv.empty()) {
    return core::Bytes(bs, 0x00);
  }
  if (m_iv.size() != bs) {
    throw std::invalid_argument("PCBC: IV size does not match block size");
  }
  return m_iv;
}

void PCBC::encrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                   core::Bytes &output, size_t) {
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

void PCBC::decrypt(core::SymmetricCipher &cipher, const core::Bytes &input,
                   core::Bytes &output, size_t) {
  const size_t bs = cipher.block_size();
  if (input.size() % bs != 0) {
    throw std::invalid_argument("PCBC: input not block-aligned");
  }
  core::Bytes iv = get_iv(bs);
  const size_t n_blocks = input.size() / bs;
  output.resize(input.size());

  for (size_t b = 0; b < n_blocks; ++b) {
    core::Bytes cipher_block(input.begin() + b * bs, input.begin() + (b + 1) * bs);
    core::Bytes plain = xor_blocks(cipher.decrypt_block(cipher_block), iv);
    std::copy(plain.begin(), plain.end(), output.begin() + b * bs);
    iv = xor_blocks(plain, cipher_block);
  }
}

} // namespace crypto::mode