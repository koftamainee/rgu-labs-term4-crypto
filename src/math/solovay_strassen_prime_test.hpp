#ifndef RGU_LABS_TERM4_CRYPTO_SOLOVAY_STRASSEN_PRIME_TEST_H
#define RGU_LABS_TERM4_CRYPTO_SOLOVAY_STRASSEN_PRIME_TEST_H

#include "prime_test.hpp"

namespace math {

  class SolovayStrassenPrimeTest : public PrimeTest {
  public:
    SolovayStrassenPrimeTest();

  protected:
    bool single_test_iteration(const mpz_class& n, int iteration_index) const override;

  private:
    mutable gmp_randclass m_rng;
  };

}  // namespace math

#endif  // RGU_LABS_TERM4_CRYPTO_SOLOVAY_STRASSEN_PRIME_TEST_H