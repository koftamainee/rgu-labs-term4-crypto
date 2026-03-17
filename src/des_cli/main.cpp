#include "cipher_context.hpp"
#include "algorithms/des.hpp"
#include "core/crypto.hpp"

int main() {
  crypto::CipherContext ctx(std::make_unique<crypto::des::DES>(), crypto::EncryptionMode::OFB, crypto::PaddingScheme::Zeros);
  std::vector<uint8_t> key = {0x10, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  ctx.set_encryption_key(key);
  ctx.set_decryption_key(key);
  ctx.encrypt_file("../files/kursach.pdf", "../kursach_ofb.enc", 16).get();
  ctx.decrypt_file("../kursach_ofb.enc", "../kursach_ofb.pdf", 16).get();
}
