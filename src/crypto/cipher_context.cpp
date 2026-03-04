#include "cipher_context.hpp"
#include "mode/modes.hpp"
#include "padding/padding.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>

namespace crypto {

void CipherContext::set_encryption_key(const core::Bytes &key) const {
  m_cipher->set_encryption_key(key);
}

void CipherContext::set_decryption_key(const core::Bytes &key) const {
  m_cipher->set_decryption_key(key);
}

void CipherContext::encrypt(const core::Bytes &input, core::Bytes &output, size_t threads) const {
  const size_t bs = m_cipher->block_size();
  core::Bytes padded = m_padding->apply(input, bs);
  m_mode->encrypt(*m_cipher, padded, output, threads);
}

void CipherContext::decrypt(const core::Bytes &input, core::Bytes &output, size_t threads) const {
  core::Bytes raw;
  m_mode->decrypt(*m_cipher, input, raw, threads);
  output = m_padding->remove(raw, m_cipher->block_size());
}

std::future<void> CipherContext::encrypt_file(const std::string &input_path,
                                               const std::string &output_path,
                                               size_t threads) const {
  return std::async(std::launch::async, [this, input_path, output_path, threads]() {
    core::Bytes raw = read_file(input_path);
    core::Bytes result;
    encrypt(raw, result, threads);
    write_file(output_path, result);
  });
}

std::future<void> CipherContext::decrypt_file(const std::string &input_path,
                                               const std::string &output_path,
                                               size_t threads) const {
  return std::async(std::launch::async, [this, input_path, output_path, threads]() {
    core::Bytes raw = read_file(input_path);
    core::Bytes result;
    decrypt(raw, result, threads);
    write_file(output_path, result);
  });
}

core::Bytes CipherContext::read_file(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("CipherContext: cannot open file for reading: " + path);
  }
  return core::Bytes(std::istreambuf_iterator<char>(file),
                     std::istreambuf_iterator<char>());
}

void CipherContext::write_file(const std::string &path, const core::Bytes &data) {
  std::ofstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("CipherContext: cannot open file for writing: " + path);
  }
  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  if (!file) {
    throw std::runtime_error("CipherContext: write error: " + path);
  }
}

void CipherContext::build_mode() {
  switch (m_enc_mode) {
  case EncryptionMode::ECB:
    m_mode = std::make_unique<mode::ECB>();
    break;
  case EncryptionMode::CBC:
    m_mode = std::make_unique<mode::CBC>(m_iv);
    break;
  case EncryptionMode::PCBC:
    m_mode = std::make_unique<mode::PCBC>(m_iv);
    break;
  default:
    throw std::invalid_argument("CipherContext: unknown encryption mode");
  }
}

void CipherContext::build_padding() {
  switch (m_pad_scheme) {
  case PaddingScheme::Zeros:
    m_padding = std::make_unique<padding::ZerosPadding>();
    break;
  case PaddingScheme::AnsiX923:
    m_padding = std::make_unique<padding::AnsiX923Padding>();
    break;
  default:
    throw std::invalid_argument("CipherContext: unknown padding scheme");
  }
}

} // namespace crypto