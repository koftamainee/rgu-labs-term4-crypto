#ifndef MATH_PRIMITIVE_ROOTS_HPP
#define MATH_PRIMITIVE_ROOTS_HPP

#include <vector>
#include <gmpxx.h>

namespace math {

  std::vector<mpz_class> primitive_roots(const mpz_class& n);

} // namespace math

#endif // MATH_PRIMITIVE_ROOTS_HPP