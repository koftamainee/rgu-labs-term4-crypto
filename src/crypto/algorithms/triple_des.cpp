#include "triple_des.hpp"
#include <stdexcept>

namespace crypto::des {

TripleDES::TripleDES(TripleDESMode mode) : m_mode(mode) {}

void TripleDES::set_encryption_key(const core::Bytes &key) {
  if (key.size() == 16) {
    m_key1 = core::Bytes(key.begin(), key.begin() + 8);
    m_key2 = core::Bytes(key.begin() + 8, key.end());
    m_key3 = m_key1;
    if (m_mode != TripleDESMode::EEE2 && m_mode != TripleDESMode::EDE2) {
      throw std::runtime_error(
          "Key size 16 bytes is only valid for 2-key modes");
    }
  } else if (key.size() == 24) {
    m_key1 = core::Bytes(key.begin(), key.begin() + 8);
    m_key2 = core::Bytes(key.begin() + 8, key.begin() + 16);
    m_key3 = core::Bytes(key.begin() + 16, key.end());
    if (m_mode != TripleDESMode::EEE3 && m_mode != TripleDESMode::EDE3) {
      throw std::runtime_error(
          "Key size 24 bytes is only valid for 3-key modes");
    }
  } else {
    throw std::runtime_error("Invalid key length for TripleDES");
  }

  m_des1.set_encryption_key(m_key1);
  m_des2.set_encryption_key(m_key2);
  m_des3.set_encryption_key(m_key3);
}

void TripleDES::set_decryption_key(const core::Bytes &key) {

  m_des1.set_decryption_key(m_key1);
  m_des2.set_decryption_key(m_key2);
  m_des3.set_decryption_key(m_key3);
}

core::Bytes TripleDES::encrypt_block(const core::Bytes &block) const {
  return process_block(block, true);
}

core::Bytes TripleDES::decrypt_block(const core::Bytes &block) const {
  return process_block(block, false);
}

core::Bytes TripleDES::process_block(const core::Bytes &block,
                                     bool encrypting) const {
  core::Bytes b = block;

  if (encrypting) {
    switch (m_mode) {
    case TripleDESMode::EEE3:
    case TripleDESMode::EEE2:
      b = m_des1.encrypt_block(b);
      b = m_des2.encrypt_block(b);
      b = m_des3.encrypt_block(b);
      break;
    case TripleDESMode::EDE3:
    case TripleDESMode::EDE2:
      b = m_des1.encrypt_block(b);
      b = m_des2.decrypt_block(b);
      b = m_des3.encrypt_block(b);
      break;
    }
  } else {
    switch (m_mode) {
    case TripleDESMode::EEE3:
    case TripleDESMode::EEE2:
      b = m_des3.decrypt_block(b);
      b = m_des2.decrypt_block(b);
      b = m_des1.decrypt_block(b);
      break;
    case TripleDESMode::EDE3:
    case TripleDESMode::EDE2:
      b = m_des3.decrypt_block(b);
      b = m_des2.encrypt_block(b);
      b = m_des1.decrypt_block(b);
      break;
    }
  }

  return b;
}

size_t TripleDES::block_size() const { return m_des1.block_size(); }

} // namespace crypto::des
