#include "padding/padding.hpp"
#include <stdexcept>

namespace crypto::padding {

core::Bytes ZerosPadding::apply(const core::Bytes &data, size_t block_size) const {
  if (block_size == 0) {
    throw std::invalid_argument("block_size must be > 0");
  }
  size_t pad_len = block_size - (data.size() % block_size);
  if (pad_len == 0) {
    pad_len = block_size;
  }
  core::Bytes padded = data;
  for (size_t i = 0; i < pad_len; ++i) {
    padded.push_back(0x00);
  }
  return padded;
}

core::Bytes ZerosPadding::remove(const core::Bytes &data, size_t block_size) const {
  if (block_size == 0) {
    throw std::invalid_argument("block_size must be > 0");
  }
  if (data.size() % block_size != 0 || data.empty()) {
    throw std::invalid_argument("data size is not a multiple of block_size");
  }
  size_t end = data.size();
  while (end > 0 && data[end - 1] == 0x00) {
    --end;
  }
  return core::Bytes(data.begin(), data.begin() + end);
}

core::Bytes AnsiX923Padding::apply(const core::Bytes &data, size_t block_size) const {
  if (block_size == 0) {
    throw std::invalid_argument("block_size must be > 0");
  }
  size_t pad_len = block_size - (data.size() % block_size);
  if (pad_len == 0) {
    pad_len = block_size;
  }
  core::Bytes padded = data;
  for (size_t i = 0; i < pad_len - 1; ++i) {
    padded.push_back(0x00);
  }
  padded.push_back(static_cast<uint8_t>(pad_len));
  return padded;
}

core::Bytes AnsiX923Padding::remove(const core::Bytes &data, size_t block_size) const {
  if (block_size == 0) {
    throw std::invalid_argument("block_size must be > 0");
  }
  if (data.size() % block_size != 0 || data.empty()) {
    throw std::invalid_argument("data size is not a multiple of block_size");
  }
  uint8_t pad_len = data.back();
  if (pad_len == 0 || pad_len > block_size || pad_len > data.size()) {
    throw std::invalid_argument("invalid ANSI X.923 padding");
  }
  for (size_t i = data.size() - pad_len; i < data.size() - 1; ++i) {
    if (data[i] != 0x00) {
      throw std::invalid_argument("invalid ANSI X.923 padding: non-zero byte found");
    }
  }
  return core::Bytes(data.begin(), data.end() - pad_len);
}

} // namespace crypto::padding