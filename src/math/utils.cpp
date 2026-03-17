//
// Created by koftamainee on 3/17/26.
//

#include "utils.hpp"

#include <cmath>
#include <sys/stat.h>

namespace math {
  int legendre_symbol(const bigint& a, const bigint& p) {
    const bigint a_mod = a % p;
    if (a_mod == 0) {
      return 0;
    }

    const bigint exp = (p - 1) / 2;
    const bigint result = math::powm(a_mod, exp, p);

    if (result == 0) {
      return 0;
    }
    if (result == 1L) {
      return 1;
    }
    return -1;
  }

  int jacobi_symbol(const bigint& a, const bigint& n) {
    if (n <= 0 || n % 2L == 0) {
      throw std::invalid_argument("n must be a positive odd integer");
    }

    bigint a_cur = a % n;
    if (a_cur < 0) {
      a_cur += n;
    }
    bigint n_cur = n;

    int result = 1;

    while (a_cur != 0) {
      while (a_cur != 0) {
        auto div_res = bigint::division(a_cur, 2);
        auto r = div_res.remainder();
        const auto q = div_res.quotient();
        if (r != 0) break;
        a_cur = q;
        if (bigint n_mod8 = n_cur % 8L; n_mod8 == 3L || n_mod8 == 5L) {
          result = -result;
        }
      }

      std::swap(a_cur, n_cur);

      if (a_cur % 4L == 3L && n_cur % 4L == 3L) {
        result = -result;
      }

      a_cur = a_cur % n_cur;
    }

    if (n_cur == 1L) {
      return result;
    }
    return 0;
  }

  bigint gcd(const bigint& a, const bigint& b) {
    return bigint::gcd(a, b);
  }

  egcd_result_t egcd(const bigint& a, const bigint& b) {
    bigint old_r = a, r = b;
    bigint old_s(1), s(0);
    bigint old_t(0), t(1);

    while (r != 0) {
      auto div_res = bigint::division(old_r, r);
      auto q = div_res.quotient();
      const auto new_r = div_res.remainder();

      old_r = r;
      r = new_r;

      bigint new_s = old_s - q * s;
      old_s = s;
      s = new_s;

      bigint new_t = old_t - q * t;
      old_t = t;
      t = new_t;
    }

    return {old_r, old_s, old_t};
  }

  bigint powm(const bigint& base, const bigint& exp, const bigint& mod) {
    return base.mod_pow(exp, mod);
  }

  bigint mod_inverse(const bigint& a, const bigint& mod) {
    std::cout << "TODO\n";
  }

  bigint euler_phi_definition(const bigint& n) {
    if (n <= 0) {
      throw std::invalid_argument("euler_phi_definition: n must be positive");
    }
    if (n == 1L) {
      return 1;
    }

    bigint count(0);
    for (bigint k(1L); k < n; ++k) {
      if (bigint::gcd(k, n) == 1L) {
        ++count;
      }
    }
    return count;
  }

  bigint euler_phi_factorization(const bigint& n) {
    if (n <= 0) {
      throw std::invalid_argument("euler_phi_factorization: n must be positive");
    }
    if (n == 1L) {
      return 1L;
    }

    bigint result = n;
    bigint temp = n;
    bigint i(2L);

    while (i * i <= temp) {
      auto div_res = bigint::division(temp, i);
      auto q = div_res.quotient();
      auto r = div_res.remainder();
      if (r == 0) {
        result /= i;
        result *= (i - 1L);

        while (r == 0) {
          temp = q;
          auto div_res2 = bigint::division(temp, i);
          q = div_res2.quotient();
          r = div_res2.remainder();
        }
      }
      ++i;
    }

    if (temp > 1L) {
      result /= temp;
      result *= (temp - 1L);
    }

    return result;
  }

  bigint euler_phi_dft(const bigint& n) {
    std::cout << "TODO\n";
  }
}
