//
// Created by koftamainee on 3/17/26.
//

#ifndef RGU_LABS_TERM4_CRYPTO_FERMAT_PRIME_TEST_H
#define RGU_LABS_TERM4_CRYPTO_FERMAT_PRIME_TEST_H
#include "prime_test.hpp"

namespace math {
  class FermatPrimeTest : public PrimeTest {
  protected:
    bool single_test_iteration(const bigint& n, int iteration_index) const override;
  };
}

#endif //RGU_LABS_TERM4_CRYPTO_FERMAT_PRIME_TEST_H