#ifndef RGU_LABS_TERM4_CRYPTO_MILLER_RABIN_PRIME_TEST_H
#define RGU_LABS_TERM4_CRYPTO_MILLER_RABIN_PRIME_TEST_H

#include "prime_test.hpp"

namespace math {

  class MillerRabinPrimeTest : public PrimeTest {
  public:
    MillerRabinPrimeTest();

  protected:
    int calculate_iterations(double min_probability) const override;
    bool single_test_iteration(const mpz_class& n, int iteration_index) const override;

  private:
    mutable gmp_randclass m_rng;
  };

}  // namespace math

#endif  // RGU_LABS_TERM4_CRYPTO_MILLER_RABIN_PRIME_TEST_H