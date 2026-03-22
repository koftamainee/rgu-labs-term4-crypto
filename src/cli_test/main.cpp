#include <iostream>
#include <filesystem>

#include "crypto/asymmetric/algorithms/rsa/key_generator.hpp"
#include "crypto/asymmetric/algorithms/rsa/key_serializer.hpp"
#include "crypto/asymmetric/algorithms/rsa/rsa.hpp"
#include "math/miller_rabin_prime_test.hpp"

using namespace crypto;

static constexpr auto KEYS_DIR = "../keys";
static constexpr auto ALICE_PUB_PATH = "../keys/alice_key.pub";
static constexpr auto ALICE_PRIV_PATH = "../keys/alice_key";

static void log(const std::string& msg) {
  std::cout << "[*] " << msg << "\n";
}

static void separator(const std::string& title) {
  std::cout << "\n─── " << title << " ───\n";
}

static void print_bytes(const std::string& label, const Bytes& b) {
  std::cout << "    " << label << " (" << b.size() << " bytes): ";
  for (size_t i = 0; i < std::min(b.size(), static_cast<size_t>(16)); ++i) {
    std::printf("%02x ", b[i]);
  }
  if (b.size() > 16) std::cout << "...";
  std::cout << "\n";
}

int main() {
  std::filesystem::create_directories(KEYS_DIR);

  separator("Alice: key generation");

  log("generating 2048-bit RSA key pair (Miller-Rabin, p=0.9999)...");
  crypto::rsa::KeyGenerator generator(
    std::make_unique<math::MillerRabinPrimeTest>(),
    2048,
    0.9999
  );
  const crypto::rsa::KeyPair alice_keys = generator.generate();
  log("key pair generated");

  crypto::rsa::KeySerializer::save_public_key(alice_keys.public_key, ALICE_PUB_PATH);
  crypto::rsa::KeySerializer::save_private_key(alice_keys.private_key, ALICE_PRIV_PATH);
  log(std::string(ALICE_PUB_PATH) + " saved");
  log(std::string(ALICE_PRIV_PATH) + " saved");

  separator("Alice → Bob: share public key");

  const auto alice_pub = crypto::rsa::KeySerializer::load_public_key(ALICE_PUB_PATH);
  log("Bob loaded alice.pub");
  std::cout << "    n: " << mpz_sizeinbase(alice_pub.n.get_mpz_t(), 2) << " bits\n";
  std::cout << "    e: " << alice_pub.e << "\n";

  separator("Bob: encrypt secret key for Alice");

  const Bytes secret_key = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
  };
  log("secret key (24 bytes, would be a DES/AES session key)");
  print_bytes("secret_key", secret_key);

  crypto::rsa::Rsa rsa_bob(alice_pub);
  const Bytes encrypted = rsa_bob.encrypt(secret_key);
  log("encrypted with Alice's public key");
  print_bytes("encrypted ", encrypted);

  separator("Alice: decrypt");

  const auto alice_priv = crypto::rsa::KeySerializer::load_private_key(ALICE_PRIV_PATH);
  crypto::rsa::Rsa rsa_alice(alice_priv);

  const Bytes decrypted_raw = rsa_alice.decrypt(encrypted);
  const Bytes decrypted(decrypted_raw.end() - secret_key.size(), decrypted_raw.end());
  log("decrypted with Alice's private key");
  print_bytes("decrypted ", decrypted);

  separator("Verify");

  if (decrypted == secret_key) {
    log("PASS: decrypted key matches original");
  }
  else {
    log("FAIL: mismatch");
    return 1;
  }

  return 0;
}
