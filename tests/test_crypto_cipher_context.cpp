#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>

#include <gtest/gtest.h>

#include "cipher_context.hpp"
#include "mode/modes.hpp"
#include "padding/padding.hpp"

using Bytes = crypto::core::Bytes;

class IdentityCipher final : public crypto::core::SymmetricCipher {
public:
  explicit IdentityCipher(size_t bs = 8) : m_bs(bs) {}
  void set_encryption_key(const Bytes &) override {}
  void set_decryption_key(const Bytes &) override {}
  Bytes encrypt_block(const Bytes &b) const override { return b; }
  Bytes decrypt_block(const Bytes &b) const override { return b; }
  size_t block_size() const override { return m_bs; }
private:
  size_t m_bs;
};

class XorCipher final : public crypto::core::SymmetricCipher {
public:
  explicit XorCipher(size_t bs = 8) : m_bs(bs) {}
  void set_encryption_key(const Bytes &) override {}
  void set_decryption_key(const Bytes &) override {}
  Bytes encrypt_block(const Bytes &b) const override {
    Bytes out(b);
    for (auto &byte : out) byte ^= 0xAA;
    return out;
  }
  Bytes decrypt_block(const Bytes &b) const override { return encrypt_block(b); }
  size_t block_size() const override { return m_bs; }
private:
  size_t m_bs;
};

static std::unique_ptr<crypto::core::SymmetricCipher> make_identity(size_t bs = 8) {
  return std::make_unique<IdentityCipher>(bs);
}

static std::unique_ptr<crypto::core::SymmetricCipher> make_xor(size_t bs = 8) {
  return std::make_unique<XorCipher>(bs);
}

TEST(ZerosPadding, ApplyNotAligned) {
  crypto::padding::ZerosPadding p;
  Bytes data = {0x01, 0x02, 0x03};
  Bytes padded = p.apply(data, 8);
  ASSERT_EQ(padded.size(), 8u);
  ASSERT_EQ(padded[3], 0x00);
  ASSERT_EQ(padded[7], 0x00);
}

TEST(ZerosPadding, ApplyAlreadyAligned) {
  crypto::padding::ZerosPadding p;
  Bytes data(8, 0x01);
  Bytes padded = p.apply(data, 8);
  ASSERT_EQ(padded.size(), 16u);
}

TEST(ZerosPadding, Roundtrip) {
  crypto::padding::ZerosPadding p;
  Bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
  Bytes padded = p.apply(data, 8);
  Bytes recovered = p.remove(padded, 8);
  ASSERT_EQ(recovered, data);
}

TEST(ZerosPadding, EmptyInput) {
  crypto::padding::ZerosPadding p;
  Bytes data;
  Bytes padded = p.apply(data, 8);
  ASSERT_EQ(padded.size(), 8u);
  Bytes recovered = p.remove(padded, 8);
  ASSERT_TRUE(recovered.empty());
}

TEST(ZerosPadding, BlockSizeZeroThrows) {
  crypto::padding::ZerosPadding p;
  ASSERT_THROW(p.apply({0x01}, 0), std::invalid_argument);
  ASSERT_THROW(p.remove({0x01}, 0), std::invalid_argument);
}

TEST(AnsiX923Padding, ApplyNotAligned) {
  crypto::padding::AnsiX923Padding p;
  Bytes data = {0x01, 0x02, 0x03};
  Bytes padded = p.apply(data, 8);
  ASSERT_EQ(padded.size(), 8u);
  ASSERT_EQ(padded.back(), 5u);
  for (size_t i = 3; i < 7; ++i) {
    ASSERT_EQ(padded[i], 0x00);
  }
}

TEST(AnsiX923Padding, ApplyAlreadyAligned) {
  crypto::padding::AnsiX923Padding p;
  Bytes data(8, 0x01);
  Bytes padded = p.apply(data, 8);
  ASSERT_EQ(padded.size(), 16u);
  ASSERT_EQ(padded.back(), 8u);
}

TEST(AnsiX923Padding, Roundtrip) {
  crypto::padding::AnsiX923Padding p;
  Bytes data = {0xDE, 0xAD, 0xBE, 0xEF};
  Bytes padded = p.apply(data, 8);
  Bytes recovered = p.remove(padded, 8);
  ASSERT_EQ(recovered, data);
}

TEST(AnsiX923Padding, RoundtripFullBlock) {
  crypto::padding::AnsiX923Padding p;
  Bytes data(16, 0xFF);
  Bytes padded = p.apply(data, 8);
  ASSERT_EQ(padded.size(), 24u);
  Bytes recovered = p.remove(padded, 8);
  ASSERT_EQ(recovered, data);
}

TEST(AnsiX923Padding, InvalidPaddingThrows) {
  crypto::padding::AnsiX923Padding p;
  Bytes bad(8, 0x00);
  bad.back() = 9;
  ASSERT_THROW(p.remove(bad, 8), std::invalid_argument);
}

TEST(AnsiX923Padding, BlockSizeZeroThrows) {
  crypto::padding::AnsiX923Padding p;
  ASSERT_THROW(p.apply({0x01}, 0), std::invalid_argument);
  ASSERT_THROW(p.remove({0x01, 0x01}, 0), std::invalid_argument);
}

TEST(ECB, EncryptDecryptRoundtrip) {
  IdentityCipher cipher(8);
  crypto::mode::ECB ecb;
  Bytes input(16, 0x42);
  Bytes enc, dec;
  ecb.encrypt(cipher, input, enc, 2);
  ecb.decrypt(cipher, enc, dec, 2);
  ASSERT_EQ(dec, input);
}

TEST(ECB, NotBlockAlignedThrows) {
  IdentityCipher cipher(8);
  crypto::mode::ECB ecb;
  Bytes bad(7, 0x00);
  Bytes out;
  ASSERT_THROW(ecb.encrypt(cipher, bad, out, 1), std::invalid_argument);
}

TEST(ECB, ParallelMatchesSequential) {
  XorCipher cipher(8);
  crypto::mode::ECB ecb;
  Bytes input;
  for (int i = 0; i < 64; ++i) input.push_back(static_cast<uint8_t>(i));
  Bytes enc1, enc4;
  ecb.encrypt(cipher, input, enc1, 1);
  ecb.encrypt(cipher, input, enc4, 4);
  ASSERT_EQ(enc1, enc4);
}

TEST(CBC, EncryptDecryptRoundtrip) {
  IdentityCipher cipher(8);
  Bytes iv(8, 0x01);
  crypto::mode::CBC enc_mode(iv);
  crypto::mode::CBC dec_mode(iv);
  Bytes input(16, 0xAB);
  Bytes enc, dec;
  enc_mode.encrypt(cipher, input, enc, 1);
  dec_mode.decrypt(cipher, enc, dec, 2);
  ASSERT_EQ(dec, input);
}

TEST(CBC, DifferentIvGivesDifferentCiphertext) {
  XorCipher cipher(8);
  Bytes input(16, 0x55);
  Bytes iv1(8, 0x00), iv2(8, 0xFF);
  crypto::mode::CBC mode1(iv1), mode2(iv2);
  Bytes enc1, enc2;
  mode1.encrypt(cipher, input, enc1, 1);
  mode2.encrypt(cipher, input, enc2, 1);
  ASSERT_NE(enc1, enc2);
}

TEST(CBC, WrongIvSizeThrows) {
  IdentityCipher cipher(8);
  Bytes bad_iv(5, 0x00);
  crypto::mode::CBC mode(bad_iv);
  Bytes input(8, 0x00), out;
  ASSERT_THROW(mode.encrypt(cipher, input, out, 1), std::invalid_argument);
}

TEST(CBC, ParallelDecryptMatchesSequential) {
  XorCipher cipher(8);
  Bytes iv(8, 0xCC);
  Bytes plain;
  for (int i = 0; i < 32; ++i) plain.push_back(static_cast<uint8_t>(i * 3));
  Bytes enc;
  { crypto::mode::CBC m(iv); m.encrypt(cipher, plain, enc, 1); }
  Bytes dec1, dec4;
  { crypto::mode::CBC m(iv); m.decrypt(cipher, enc, dec1, 1); }
  { crypto::mode::CBC m(iv); m.decrypt(cipher, enc, dec4, 4); }
  ASSERT_EQ(dec1, dec4);
  ASSERT_EQ(dec1, plain);
}

TEST(PCBC, EncryptDecryptRoundtrip) {
  IdentityCipher cipher(8);
  Bytes iv(8, 0x33);
  crypto::mode::PCBC enc_mode(iv), dec_mode(iv);
  Bytes input(24, 0x77);
  Bytes enc, dec;
  enc_mode.encrypt(cipher, input, enc, 1);
  dec_mode.decrypt(cipher, enc, dec, 1);
  ASSERT_EQ(dec, input);
}

TEST(PCBC, ErrorPropagation) {
  XorCipher cipher(8);
  Bytes iv(8, 0x00);
  crypto::mode::PCBC enc_mode(iv);
  Bytes plain;
  for (int i = 0; i < 24; ++i) plain.push_back(static_cast<uint8_t>(i));
  Bytes enc;
  enc_mode.encrypt(cipher, plain, enc, 1);

  Bytes corrupted = enc;
  corrupted[0] ^= 0xFF;

  Bytes dec;
  crypto::mode::PCBC dec_mode(iv);
  dec_mode.decrypt(cipher, corrupted, dec, 1);

  Bytes orig_b0(plain.begin(), plain.begin() + 8);
  Bytes dec_b0(dec.begin(), dec.begin() + 8);
  ASSERT_NE(orig_b0, dec_b0);
}

TEST(CipherContext, EcbZerosRoundtrip) {
  crypto::CipherContext ctx(make_identity(), crypto::EncryptionMode::ECB,
                            crypto::PaddingScheme::Zeros);
  Bytes plain = {1, 2, 3, 4, 5};
  Bytes enc, dec;
  ctx.encrypt(plain, enc, 1);
  ctx.decrypt(enc, dec, 1);
  ASSERT_EQ(dec, plain);
}

TEST(CipherContext, EcbAnsiX923Roundtrip) {
  crypto::CipherContext ctx(make_xor(), crypto::EncryptionMode::ECB,
                            crypto::PaddingScheme::AnsiX923);
  Bytes plain = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
  Bytes enc, dec;
  ctx.encrypt(plain, enc, 2);
  ctx.decrypt(enc, dec, 2);
  ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CbcZerosRoundtrip) {
  Bytes iv(8, 0x5A);
  crypto::CipherContext ctx(make_xor(), crypto::EncryptionMode::CBC,
                            crypto::PaddingScheme::Zeros, iv);
  Bytes plain(13, 0x11);
  Bytes enc, dec;
  ctx.encrypt(plain, enc, 1);
  ctx.decrypt(enc, dec, 1);
  ASSERT_EQ(dec, plain);
}

TEST(CipherContext, PcbcAnsiX923Roundtrip) {
  Bytes iv(8, 0xF0);
  crypto::CipherContext ctx(make_identity(), crypto::EncryptionMode::PCBC,
                            crypto::PaddingScheme::AnsiX923, iv);
  Bytes plain = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
  Bytes enc, dec;
  ctx.encrypt(plain, enc, 1);
  ctx.decrypt(enc, dec, 1);
  ASSERT_EQ(dec, plain);
}

TEST(CipherContext, NullCipherThrows) {
  ASSERT_THROW(
    crypto::CipherContext(nullptr, crypto::EncryptionMode::ECB,
                          crypto::PaddingScheme::Zeros),
    std::invalid_argument);
}

TEST(CipherContext, CbcEmptyIvUsesZeros) {
  crypto::CipherContext ctx_enc(make_xor(), crypto::EncryptionMode::CBC,
                                crypto::PaddingScheme::AnsiX923);
  crypto::CipherContext ctx_dec(make_xor(), crypto::EncryptionMode::CBC,
                                crypto::PaddingScheme::AnsiX923);
  Bytes plain = {0xAB, 0xCD, 0xEF};
  Bytes enc, dec;
  ctx_enc.encrypt(plain, enc, 1);
  ctx_dec.decrypt(enc, dec, 1);
  ASSERT_EQ(dec, plain);
}

TEST(CipherContext, MultithreadedEcbLargeData) {
  crypto::CipherContext ctx(make_xor(), crypto::EncryptionMode::ECB,
                            crypto::PaddingScheme::AnsiX923);
  Bytes plain(1024);
  for (size_t i = 0; i < plain.size(); ++i)
    plain[i] = static_cast<uint8_t>(i & 0xFF);
  Bytes enc, dec;
  ctx.encrypt(plain, enc, 8);
  ctx.decrypt(enc, dec, 8);
  ASSERT_EQ(dec, plain);
}

TEST(CipherContext, FileEncryptDecryptRoundtrip) {
  const std::string in_path  = "/tmp/ctx_test_plain.bin";
  const std::string enc_path = "/tmp/ctx_test_enc.bin";
  const std::string dec_path = "/tmp/ctx_test_dec.bin";

  Bytes original = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
  {
    std::ofstream f(in_path, std::ios::binary);
    f.write(reinterpret_cast<const char *>(original.data()), original.size());
  }

  crypto::CipherContext ctx_enc(make_xor(), crypto::EncryptionMode::CBC,
                                crypto::PaddingScheme::AnsiX923, Bytes(8, 0x00));
  crypto::CipherContext ctx_dec(make_xor(), crypto::EncryptionMode::CBC,
                                crypto::PaddingScheme::AnsiX923, Bytes(8, 0x00));

  ctx_enc.encrypt_file(in_path, enc_path, 2).get();
  ctx_dec.decrypt_file(enc_path, dec_path, 2).get();

  std::ifstream result_file(dec_path, std::ios::binary);
  Bytes recovered(std::istreambuf_iterator<char>(result_file), {});
  ASSERT_EQ(recovered, original);
}
