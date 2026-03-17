#include <stdexcept>
#include <random>

#include "bigint.h"

bigint bigint::factorial(const bigint& n) {
  if (n < 2) {
    return 1;
  }

  bigint result = 1;
  for (bigint i = 2; i <= n; ++i) {
    result *= i;
  }

  return result;
}

bigint bigint::gcd(bigint a, bigint b) {
  if (a == 0) {
    return b < 0 ? -b : b;
  }
  if (b == 0) {
    return a < 0 ? -a : a;
  }

  if (a < 0) {
    a = -a;
  }
  if (b < 0) {
    b = -b;
  }

  while (b != 0) {
    const bigint temp = b;
    b = a % b;
    a = temp;
  }

  return a;
}

bigint bigint::pow(bigint const& exponent) const {
  if (exponent < bigint(0)) {
    throw std::runtime_error("bigint::pow: Negative exponent not supported");
  }

  if (exponent == bigint(0)) {
    return 1;
  }

  bigint base = *this;
  bigint result(1);
  bigint exp = exponent;

  while (exp > bigint(0)) {
    if (exp % bigint(2) == bigint(1)) {
      result *= base;
    }
    base *= base;
    exp /= bigint(2);
  }

  return result;
}

bigint bigint::mod_pow(bigint exponent, bigint const& modulus) const {
  if (modulus == bigint(0)) {
    throw zero_division_exception();
  }

  if (exponent < bigint(0)) {
    throw mathematical_uncertainty_exception();
  }

  bigint base = *this % modulus;
  bigint result = bigint(1);
  bigint zero = bigint(0);
  bigint two = bigint(2);

  while (exponent > zero) {
    if ((exponent % two) == bigint(1)) {
      result = (result * base) % modulus;
    }

    exponent /= two;
    base = (base * base) % modulus;
  }

  return result;
}

bigint bigint::rand_range(bigint const& a, bigint const& b) {
  if (a > b) {
    throw mathematical_uncertainty_exception();
  }

  static std::random_device rd;
  static std::mt19937 gen(rd());

  bigint range = b - a;
  // ++range;

  const int bits = range.bit_length();

  while (true) {
    bigint candidate(0);

    const int full_words = bits / SHIFT;
    const int remaining_bits = bits % SHIFT;

    for (int i = 0; i < full_words; ++i) {
      std::uniform_int_distribution<unsigned int> dist(0, MASK);
      unsigned int word = dist(gen);

      bigint part(static_cast<int>(word));
      part <<= (i * SHIFT);
      candidate += part;
    }

    if (remaining_bits > 0) {
      std::uniform_int_distribution<unsigned int> dist(
          0, (1u << remaining_bits) - 1);
      const unsigned int word = dist(gen);

      bigint part(static_cast<int>(word));
      part <<= (full_words * SHIFT);
      candidate += part;
    }

    if (candidate < range) {
      return a + candidate;
    }
  }
}