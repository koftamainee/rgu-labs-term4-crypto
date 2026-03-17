#include <climits>
#include <algorithm>

#include "bigint.h"

bigint bigint::operator-() const {
  bigint negative = *this;
  return negative.negate();
}

bigint bigint::abs() const { return sign() < 0 ? -*this : *this; }

bigint &bigint::negate() & {
  if (sign() == 0) {
    return *this;
  }
  if (size() == 1 && oldest_digit_ == INT_MIN) {
    int arr[] = {INT_MIN, 0};
    return from_array(arr, 2);
  }
  if (sign() == 1) {
    bit_inverse();
    _raw_negative_increment();
    return *this;
  }
  _raw_positive_decrement();
  bit_inverse();
  return *this;
}

bigint &bigint::operator++() & {
  if (sign() == -1) {
    return _raw_negative_increment();
  }
  return _raw_positive_increment();
}

bigint const bigint::operator++(int) & {
  auto const copy = *this;
  ++(*this);
  return copy;
}

bigint &bigint::operator--() & {
  if (sign() == -1) {
    return _raw_negative_decrement();
  }
  return _raw_positive_decrement();
}

bigint const bigint::operator--(int) & {
  auto const copy = *this;
  --(*this);
  return copy;
}

static int compare_abs(bigint const &a, bigint const &b) {
  int a_size = a.size();
  int b_size = b.size();
  if (a_size != b_size) {
    return a_size < b_size ? -1 : 1;
  }
  for (int i = a_size - 1; i >= 0; --i) {
    unsigned int da = a[i];
    unsigned int db = b[i];
    if (da != db) return da < db ? -1 : 1;
  }
  return 0;
}

bigint &bigint::operator+=(bigint const &other) & {
  int this_sign  = sign();
  int other_sign = other.sign();

  if (this_sign == -1 && other_sign == -1) {
    negate();
    bigint pos_other = -other;
    *this += pos_other;
    return negate();
  }

  if (this_sign == 0) {
    return *this = other;
  }

  if (other_sign == 0) {
    return *this;
  }

  int result_sign = 0;

  if (this_sign == other_sign) {
    result_sign = this_sign;
  } else {
    int cmp = compare_abs(*this, other);
    if (cmp == 0) {
      return *this = 0;
    }
    result_sign = (cmp > 0) ? this_sign : other_sign;
  }

  int this_size  = size();
  int other_size = other.size();
  unsigned int max_size = static_cast<unsigned int>(std::max(this_size, other_size)) + 1;

  constexpr unsigned int STACK_LIMIT = 32;
  unsigned int  stack_buf[STACK_LIMIT];
  unsigned int *result =
      (max_size <= STACK_LIMIT) ? stack_buf : new unsigned int[max_size];

  const unsigned int* tp = inner_words();
  const unsigned int* op = other.inner_words();
  int t_last  = this_size  - 1;
  int o_last  = other_size - 1;
  bool mixed_signs = (this_sign ^ other_sign) < 0;

  unsigned int extra_digit = 0;

  for (unsigned int i = 0; i < max_size; ++i) {
    unsigned int this_digit;
    if (static_cast<int>(i) < this_size) {
      this_digit = (static_cast<int>(i) == t_last)
                       ? static_cast<unsigned int>(oldest_digit_)
                       : tp[i];
    } else {
      this_digit = 0;
    }

    unsigned int other_digit;
    if (static_cast<int>(i) < other_size) {
      other_digit = (static_cast<int>(i) == o_last)
                        ? static_cast<unsigned int>(other.oldest_digit_)
                        : op[i];
    } else {
      other_digit = 0;
    }

    result[i] = 0;

    if (this_digit == 0 && other_digit == 0 && extra_digit == 0) {
      continue;
    }

    unsigned long long sum =
        static_cast<unsigned long long>(this_digit) + other_digit + extra_digit;
    result[i]   = static_cast<unsigned int>(sum);
    extra_digit = static_cast<unsigned int>(sum >> (sizeof(int) * 8));

    if (mixed_signs) {
      const bigint    &negative      = this_sign < 0 ? *this : other;
      const unsigned int* neg_inner  = negative.inner_words();
      int              negative_size = (this_sign < 0 ? this_size : other_size);
      int              neg_last      = negative_size - 1;
      bool all_zeros = true;
      for (int j = static_cast<int>(i) + 1; j <= neg_last; ++j) {
        unsigned int w = (j == neg_last)
                             ? static_cast<unsigned int>(negative.oldest_digit_)
                             : neg_inner[j];
        if (w != 0) {
          all_zeros = false;
          break;
        }
      }
      if (all_zeros) {
        extra_digit = 0;
      }
    }
  }

  if (result_sign == -1 && result[max_size - 1] == 0) {
    --max_size;
  }

  if (result == stack_buf) {
    from_array(reinterpret_cast<int *>(result), max_size);
  } else {
    move_from_array(reinterpret_cast<int *>(result), max_size);
  }
  return *this;
}

bigint operator+(bigint const &first, bigint const &second) {
  bigint temp = first;
  return temp += second;
}

bigint &bigint::operator-=(bigint const &other) & {
  if (other.sign() == 0) {
    return *this;
  }
  bigint neg_other = other;
  neg_other.negate();
  return *this += neg_other;
}

bigint operator-(bigint const &first, bigint const &second) {
  bigint temp = first;
  return temp -= second;
}

bigint &bigint::operator*=(bigint const &other) & {
  if (this->sign() == 0 || other.sign() == 0) {
    *this = 0;
    return *this;
  }
  if (other == 1)  return *this;
  if (*this == 1)  return *this = other;
  if (other == -1) return this->negate();
  if (*this == -1) return *this = -other;

  bool result_negative = (this->sign() == -1) != (other.sign() == -1);

  if (this->sign() == -1) {
    this->negate();
  }

  if (other.sign() == -1) {
    bigint pos_other = -other;
    multiply(pos_other);
  } else {
    multiply(other);
  }

  if (result_negative) {
    this->negate();
  }
  return *this;
}

bigint operator*(bigint const &first, bigint const &second) {
  bigint copy = first;
  return copy *= second;
}

bigint &bigint::operator/=(bigint const &other) & {
  return *this = std::move(division(*this, other).quotient());
}

bigint operator/(bigint const &first, bigint const &second) {
  return bigint::division(first, second).quotient();
}

bigint &bigint::operator%=(bigint const &other) & {
  return *this = std::move(division(*this, other).remainder());
}

bigint operator%(bigint const &first, bigint const &second) {
  return bigint::division(first, second).remainder();
}