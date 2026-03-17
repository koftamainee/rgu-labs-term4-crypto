//
// Created by koftamainee on 3/17/26.
//

#include "utils.hpp"

#include <cmath>
#include <sys/stat.h>

#include "bigmath.hpp"

namespace math {
  int legendre_symbol(const bigint& a, const bigint& p) {
    const bigint a_mod = a % p;
    if (a_mod == 0L) {
      return 0;
    }

    const bigint exp = (p - 1) / 2;
    const bigint result = math::powm(a_mod, exp, p);

    if (result == 0L) {
      return 0;
    }
    if (result == 1L) {
      return 1;
    }
    return -1;
  }

  int jacobi_symbol(const bigint& a, const bigint& n) {
    if (n <= 0L || n % 2L == 0L) {
      throw std::invalid_argument("n must be a positive odd integer");
    }

    bigint a_cur = a % n;
    if (a_cur < 0L) {
      a_cur += n;
    }
    bigint n_cur = n;

    int result = 1;

    while (a_cur != 0L) {
      while (a_cur != 0L) {
        auto [q, r] = a_cur.tdiv_qr(bigint(2L));
        if (r != 0L) break;
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
    bigint old_s(1L), s(0L);
    bigint old_t(0L), t(1L);

    while (r != 0L) {
      auto [q, new_r] = old_r.tdiv_qr(r);

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
    return base.powm(exp, mod);
  }

  bigint mod_inverse(const bigint& a, const bigint& mod) {
    bigint result;
    if (!a.invert(result, mod)) {
      throw std::invalid_argument("mod_inverse: a and mod are not coprime");
    }
    return result;
  }

  bigint euler_phi_definition(const bigint& n) {
    if (n <= 0L) {
      throw std::invalid_argument("euler_phi_definition: n must be positive");
    }
    if (n == 1L) {
      return 1;
    }

    bigint count(0L);
    for (bigint k(1L); k < n; ++k) {
      if (bigint::gcd(k, n) == 1L) {
        ++count;
      }
    }
    return count;
  }

  bigint euler_phi_factorization(const bigint& n) {
    if (n <= 0L) {
      throw std::invalid_argument("euler_phi_factorization: n must be positive");
    }
    if (n == 1L) {
      return 1L;
    }

    bigint result = n;
    bigint temp = n;
    bigint i(2L);

    while (i * i <= temp) {
      if (auto [q, r] = temp.tdiv_qr(i); r == 0L) {
        result /= i;
        result *= (i - 1L);

        while (r == 0L) {
          temp = q;
          auto [q2, r2] = temp.tdiv_qr(i);
          q = q2;
          r = r2;
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
    double result = 0.0;
    auto n_val = static_cast<long int>(n);

    for (long int k = 1; k <= n_val; ++k) {
      bigint g = gcd(bigint(k), n);
      double angle = 2.0 * M_PI * static_cast<double>(k) / static_cast<double>(n_val);
      result += static_cast<double>(static_cast<long int>(g)) * std::cos(angle);
    }

    return static_cast<long int>(std::round(result));
  }
}
