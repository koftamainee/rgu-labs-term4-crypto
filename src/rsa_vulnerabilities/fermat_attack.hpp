#ifndef RGU_LABS_TERM4_CRYPTO_FERMAT_ATTACK_HPP
#define RGU_LABS_TERM4_CRYPTO_FERMAT_ATTACK_HPP

#include <gmpxx.h>

namespace crypto::rsa {
struct FermatAttackResult {
  bool success;
  mpz_class p;
  mpz_class q;
};

FermatAttackResult fermat_attack(
    const mpz_class &n,
    unsigned long max_steps = std::numeric_limits<unsigned long>::max());
} // namespace crypto::rsa

#endif // RGU_LABS_TERM4_CRYPTO_FERMAT_ATTACK_HPP
