//
// Created by koftamainee on 3/17/26.
//

#ifndef RGU_LABS_TERM4_CRYPTO_PRIME_TEST_HPP
#define RGU_LABS_TERM4_CRYPTO_PRIME_TEST_HPP

#include <cmath>
#include <gmpxx.h>

namespace math {
  class IPrimeTest {
  public:
    virtual ~IPrimeTest() = default;

    virtual bool is_prime(const mpz_class& n, double min_probability) = 0;
  };

  class PrimeTest : public IPrimeTest {
  public:
    bool is_prime(const mpz_class& n, double min_probability) final;

  protected:
    virtual int calculate_iterations(double min_probability) const;

    virtual bool single_test_iteration(const mpz_class& n, int iteration_index) const = 0;

  };
}

#endif //RGU_LABS_TERM4_CRYPTO_PRIME_TEST_HPP