#ifndef CRYPTO_DH_PARAMS_HPP
#define CRYPTO_DH_PARAMS_HPP

#include <gmpxx.h>

namespace crypto::dh {

  struct DhParams {
    mpz_class p;
    mpz_class g;
  };

} // namespace crypto::dh

#endif // CRYPTO_DH_PARAMS_HPP