#include <gtest/gtest.h>
#include <gmpxx.h>

#include "math/miller_rabin_prime_test.hpp"
#include "rsa_vulnerabilities/vulnerable_key_generator.hpp"

static crypto::rsa::KeyPair make_fermat_vulnerable(mp_bitcnt_t bits = 512) {
    return crypto::rsa::VulnerableKeyGenerator(
        std::make_unique<math::MillerRabinPrimeTest>(),
        bits,
        0.9999,
        crypto::rsa::VulnerableKeyGenerator::Vulnerability::Fermat
    ).generate();
}

struct FermatResult {
    bool success;
    mpz_class p;
    mpz_class q;
};

static FermatResult fermat_attack(const mpz_class& n, unsigned long max_steps = 1000000) {
    mpz_class a;
    mpz_sqrt(a.get_mpz_t(), n.get_mpz_t());
    a += 1;

    for (unsigned long step = 0; step < max_steps; ++step) {
        const mpz_class b2 = a * a - n;
        mpz_class b;
        mpz_sqrt(b.get_mpz_t(), b2.get_mpz_t());
        if (b * b == b2) {
            return {true, a - b, a + b};
        }
        a += 1;
    }
    return {false, 0, 0};
}

TEST(FermatAttackTest, AttackRecoversPrimes) {
    const auto kp = make_fermat_vulnerable();
    const auto res = fermat_attack(kp.public_key.n);

    ASSERT_TRUE(res.success) << "Fermat attack did not converge";
    ASSERT_GT(res.p, mpz_class(1));
    ASSERT_GT(res.q, mpz_class(1));
    ASSERT_EQ(res.p * res.q, kp.public_key.n);
}

TEST(FermatAttackTest, RecoveredFactorsMatchPrivateKey) {
    const auto kp = make_fermat_vulnerable();
    const auto res = fermat_attack(kp.public_key.n);

    ASSERT_TRUE(res.success) << "Fermat attack did not converge";

    const mpz_class expected_p = kp.private_key.p;
    const mpz_class expected_q = kp.private_key.q;

    const bool match = (res.p == expected_p && res.q == expected_q)
                    || (res.p == expected_q && res.q == expected_p);
    ASSERT_TRUE(match) << "Recovered factors do not match private key primes";
}

TEST(FermatAttackTest, RecoveredFactorsAreActuallyPrime) {
    const auto kp = make_fermat_vulnerable();
    const auto res = fermat_attack(kp.public_key.n);

    ASSERT_TRUE(res.success) << "Fermat attack did not converge";

    math::MillerRabinPrimeTest prime_test;
    ASSERT_TRUE(prime_test.is_prime(res.p, 0.9999));
    ASSERT_TRUE(prime_test.is_prime(res.q, 0.9999));
}

TEST(FermatAttackTest, CanDecryptAfterAttack) {
    const auto kp = make_fermat_vulnerable();
    const auto res = fermat_attack(kp.public_key.n);

    ASSERT_TRUE(res.success) << "Fermat attack did not converge";

    const mpz_class n     = kp.public_key.n;
    const mpz_class e     = kp.public_key.e;
    const mpz_class phi_n = (res.p - 1) * (res.q - 1);

    mpz_class d;
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi_n.get_mpz_t());

    const mpz_class m(42);
    mpz_class c, recovered;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
    mpz_powm(recovered.get_mpz_t(), c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());

    ASSERT_EQ(recovered, m);
}

TEST(FermatAttackTest, SafeKeyResistsAttack) {
    const auto safe_gen = crypto::rsa::KeyGenerator(
        std::make_unique<math::MillerRabinPrimeTest>(),
        512,
        0.9999
    );
    const auto kp = safe_gen.generate();
    const auto res = fermat_attack(kp.public_key.n, 100000);

    ASSERT_FALSE(res.success) << "Fermat attack should not succeed on a safe key";
}