//
// Created by koftamainee on 3/17/26.
//

#include "fermat_prime_test.h"


namespace math {
  bool FermatPrimeTest::single_test_iteration(const bigint& n, int iteration_index) const {
    bigint a;

    do {
      a = bigint::rand_range(2, n - 2);
    } while (bigint::gcd(a, n) != 1);

    const bigint result = a.mod_pow(n - 1, n);
    return result == 1;
  }
}