#include "bigint.h"

void bigint::accumulate_multiplication(
    bigint &result, unsigned int *words_multiplication_result_digits,
    unsigned int a, unsigned int b, size_t position_shift) {
  if (a == 0 || b == 0) {
    return;
  }
  unsigned int product = a * b;
  words_multiplication_result_digits[0] = product;

  bigint temp(reinterpret_cast<int *>(words_multiplication_result_digits), 2);
  _add_with_shift(result, temp, position_shift);
}

bigint &bigint::scholarbook_multiply(bigint const &other) & {
  unsigned int words_multiplication_result_digits[2] = {0};
  int this_size  = size();
  int other_size = other.size();
  bigint const *first = this;

  const unsigned int* fp = first->inner_words();
  const unsigned int* op = other.inner_words();

  bigint result = 0;

  for (int i = 0; i < this_size; ++i) {
    unsigned int this_digit = (i == this_size - 1)
                                  ? static_cast<unsigned int>(first->oldest_digit_)
                                  : fp[i];
    unsigned int this_lo = loword(this_digit);
    unsigned int this_hi = hiword(this_digit);

    for (int j = 0; j < other_size; ++j) {
      unsigned int other_digit = (j == other_size - 1)
                                     ? static_cast<unsigned int>(other.oldest_digit_)
                                     : op[j];
      unsigned int other_lo = loword(other_digit);
      unsigned int other_hi = hiword(other_digit);

      accumulate_multiplication(
          result, words_multiplication_result_digits, this_lo, other_lo,
          (static_cast<long long>(i + j)) * sizeof(int) * 8);

      accumulate_multiplication(result, words_multiplication_result_digits,
                                this_lo, other_hi,
                                ((i + j) * (sizeof(int) * 8)) + SHIFT);

      accumulate_multiplication(result, words_multiplication_result_digits,
                                this_hi, other_lo,
                                ((i + j) * sizeof(int) * 8) + SHIFT);

      accumulate_multiplication(
          result, words_multiplication_result_digits, this_hi, other_hi,
          static_cast<size_t>(i + j + 1) * sizeof(int) * 8);
    }
  }
  return *this = std::move(result);
}

bigint &bigint::karatsuba_multiply(bigint const &other) & {
  int this_size  = this->size();
  int other_size = other.size();

  size_t const m = static_cast<size_t>(std::max(this_size, other_size)) / 2;

  bigint const high1 = this->get_upper(m);
  bigint const low1  = this->get_lower(m);
  bigint const high2 = other.get_upper(m);
  bigint const low2  = other.get_lower(m);

  bigint z0 = low1 * low2;
  bigint z2 = high1 * high2;
  bigint z1 = (low1 + high1) * (low2 + high2);

  z1 -= z2;
  z1 -= z0;

  bigint result = std::move(z0);
  _add_with_word_shift(result, z1, m);
  _add_with_word_shift(result, z2, 2 * m);

  return *this = std::move(result);
}

bigint &bigint::multiply(bigint const &other) {
  if (size() >= KARATSUBA_THRESHOLD && other.size() >= KARATSUBA_THRESHOLD) {
    return karatsuba_multiply(other);
  }
  return scholarbook_multiply(other);
}