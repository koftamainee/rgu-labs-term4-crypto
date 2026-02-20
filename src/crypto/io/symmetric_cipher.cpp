#include "symmetric_cipher.hpp"
#include <fstream>
#include <stdexcept>

namespace crypto::io {

SymmetricCipherIO::SymmetricCipherIO(
    std::unique_ptr<core::SymmetricCipher> cipher)
    : m_cipher(std::move(cipher)) {
  if (m_cipher == NULL) {
    throw std::invalid_argument("cipher can not be NULL");
  }
  m_block_size = m_cipher->block_size();
}

void SymmetricCipherIO::set_encryption_key(const std::vector<uint8_t> &key) {
  m_cipher->set_encryption_key(key);
}

void SymmetricCipherIO::set_decryption_key(const std::vector<uint8_t> &key) {
  m_cipher->set_decryption_key(key);
}

std::vector<uint8_t>
SymmetricCipherIO::encrypt_bytes(const std::vector<uint8_t> &data) {
  if (data.size() % m_block_size != 0) {
    throw std::invalid_argument("data size must be multiple of block size");
  }

  std::vector<uint8_t> out;
  out.reserve(data.size());

  for (size_t i = 0; i < data.size(); i += m_block_size) {
    core::Bytes block(data.begin() + i, data.begin() + i + m_block_size);
    core::Bytes enc = m_cipher->encrypt_block(block);
    out.insert(out.end(), enc.begin(), enc.end());
  }

  return out;
}

std::vector<uint8_t>
SymmetricCipherIO::decrypt_bytes(const std::vector<uint8_t> &data) {
  if (data.size() % m_block_size != 0) {
    throw std::invalid_argument("data size must be multiple of block size");
  }

  std::vector<uint8_t> out;
  out.reserve(data.size());

  for (size_t i = 0; i < data.size(); i += m_block_size) {
    core::Bytes block(data.begin() + i, data.begin() + i + m_block_size);
    core::Bytes dec = m_cipher->decrypt_block(block);
    out.insert(out.end(), dec.begin(), dec.end());
  }

  return out;
}

void SymmetricCipherIO::encrypt_file(const std::string &input_path,
                                     const std::string &output_path) {
  std::ifstream in(input_path, std::ios::binary);
  std::ofstream out(output_path, std::ios::binary);

  if (!in || !out) {
    throw std::runtime_error("failed to open file");
  }

  core::Bytes buffer(m_block_size);

  while (true) {
    in.read(reinterpret_cast<char *>(buffer.data()), m_block_size);
    std::streamsize read = in.gcount();

    if (read == 0) {
      break;
    }

    if (read < static_cast<std::streamsize>(m_block_size)) {
      out.write(reinterpret_cast<char *>(buffer.data()), read);
      break;
    }

    core::Bytes enc = m_cipher->encrypt_block(buffer);
    out.write(reinterpret_cast<char *>(enc.data()), enc.size());
  }
}

void SymmetricCipherIO::decrypt_file(const std::string &input_path,
                                     const std::string &output_path) {
  std::ifstream in(input_path, std::ios::binary);
  std::ofstream out(output_path, std::ios::binary);

  if (!in || !out) {
    throw std::runtime_error("failed to open file");
  }

  core::Bytes buffer(m_block_size);

  while (true) {
    in.read(reinterpret_cast<char *>(buffer.data()), m_block_size);
    std::streamsize read = in.gcount();

    if (read == 0) {
      break;
    }

    if (read < static_cast<std::streamsize>(m_block_size)) {
      out.write(reinterpret_cast<char *>(buffer.data()), read);
      break;
    }

    core::Bytes dec = m_cipher->decrypt_block(buffer);
    out.write(reinterpret_cast<char *>(dec.data()), dec.size());
  }
}

} // namespace crypto::io
