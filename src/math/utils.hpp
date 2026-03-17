//
// Created by koftamainee on 3/17/26.
//

#ifndef RGU_LABS_TERM4_CRYPTO_MATH_SERVICE_H
#define RGU_LABS_TERM4_CRYPTO_MATH_SERVICE_H

#include <bigint.h>

namespace math {
  int legendre_symbol(const bigint& a, const bigint& p);

  int jacobi_symbol(const bigint& a, const bigint& n);

  bigint gcd(const bigint& a, const bigint& b);

  struct egcd_result_t {
    bigint gcd;
    bigint x;
    bigint y;
  };

  egcd_result_t egcd(const bigint& a, const bigint& b);

  bigint powm(const bigint &base, const bigint &exp, const bigint &mod);

  bigint mod_inverse(const bigint &a, const bigint &mod);

  bigint euler_phi_definition(const bigint &n);

  bigint euler_phi_factorization(const bigint &n);

  bigint euler_phi_dft(const bigint &n);

}

#endif //RGU_LABS_TERM4_CRYPTO_MATH_SERVICE_H
