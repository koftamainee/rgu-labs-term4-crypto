#include <climits>
#include <cstring>

#include "bigint.h"

bigint &bigint::_raw_positive_increment() {
  auto const digits_count = size();

  if (other_digits_ != nullptr) {
    unsigned int *p = inner_words_mutable();
    for (int i = 0; i < digits_count - 1; ++i) {
      if (++p[i] != 0) {
        return *this;
      }
    }
  }

  oldest_digit_ = static_cast<int>(static_cast<unsigned int>(oldest_digit_) + 1u);
  if (oldest_digit_ != INT_MIN) {
    return *this;
  }

  if (other_digits_ == nullptr) {
    other_digits_ = new int[2];
    other_digits_[0] = 2;
    other_digits_[1] = oldest_digit_;
    oldest_digit_ = 0;
    return *this;
  }

  int *new_array = new int[digits_count + 1];
  std::memcpy(new_array, other_digits_, sizeof(int) * digits_count);
  delete[] other_digits_;
  other_digits_ = new_array;

  other_digits_[digits_count] = oldest_digit_;
  ++other_digits_[0];
  oldest_digit_ = 0;

  remove_leading_zeros();
  return *this;
}

bigint &bigint::_raw_positive_decrement() {
  if (sign() == 0) {
    oldest_digit_ = -1;
    remove_leading_zeros();
    return *this;
  }
  auto const digits_count = size();

  if (other_digits_ != nullptr) {
    unsigned int *p = inner_words_mutable();
    for (int i = 0; i < digits_count - 1; ++i) {
      if (--p[i] != static_cast<unsigned int>(-1)) {
        remove_leading_zeros();
        return *this;
      }
    }
  }

  if (--oldest_digit_ != INT_MAX) {
    remove_leading_zeros();
    return *this;
  }

  if (other_digits_ == nullptr) {
    other_digits_ = new int[2];
    other_digits_[0] = 2;
    other_digits_[1] = oldest_digit_;
    oldest_digit_ = -1;
    remove_leading_zeros();
    return *this;
  }

  int *new_array = new int[digits_count + 1];
  memcpy(new_array, other_digits_, sizeof(int) * digits_count);
  delete[] other_digits_;
  other_digits_ = new_array;

  other_digits_[digits_count] = oldest_digit_;
  ++other_digits_[0];
  oldest_digit_ = 0;

  remove_leading_zeros();
  return *this;
}

bigint &bigint::_raw_negative_increment() {
  return _raw_positive_increment();
}

bigint &bigint::_raw_negative_decrement() {
  auto const digits_count = size();

  if (other_digits_ != nullptr) {
    unsigned int* p = inner_words_mutable();
    for (int i = 0; i < digits_count - 1; ++i) {
      if (--p[i] != static_cast<unsigned int>(-1)) {
        remove_leading_zeros();
        return *this;
      }
    }
  }

  unsigned int old_oldest = static_cast<unsigned int>(oldest_digit_);
  unsigned int new_oldest = old_oldest - 1u;
  oldest_digit_ = static_cast<int>(new_oldest);

  if (new_oldest != static_cast<unsigned int>(INT_MAX)) {
    remove_leading_zeros();
    return *this;
  }

  if (other_digits_ == nullptr) {
    other_digits_ = new int[2];
    other_digits_[0] = 2;
    other_digits_[1] = oldest_digit_;
    oldest_digit_ = -1;
    remove_leading_zeros();
    return *this;
  }

  int *new_array = new int[digits_count + 1];
  std::memcpy(new_array, other_digits_, sizeof(int) * digits_count);
  delete[] other_digits_;
  other_digits_ = new_array;

  other_digits_[digits_count] = oldest_digit_;
  ++other_digits_[0];
  oldest_digit_ = -1;

  remove_leading_zeros();
  return *this;
}

void bigint::_add_with_shift(bigint &adding_to, bigint &summand, size_t shift) {
  if (summand == 0) {
    return;
  }

  if (adding_to == 0) {
    adding_to = std::move(summand << shift);
    return;
  }

  if (shift == 0) {
    adding_to += summand;
    return;
  }

  constexpr size_t bits_per_word = sizeof(int) << 3;
  size_t bit_shift  = shift % bits_per_word;
  size_t word_shift = shift / bits_per_word;

  if (bit_shift != 0) {
    summand <<= bit_shift;
  }

  _add_with_word_shift(adding_to, summand, word_shift);
}

void bigint::_add_with_word_shift(bigint &adding_to, bigint &summand,
                                  size_t word_shift) {
  int adding_to_size         = adding_to.size();
  int summand_size           = summand.size();
  size_t total_summand_size  = word_shift + summand_size;

  size_t max_size = (total_summand_size > static_cast<size_t>(adding_to_size))
                        ? total_summand_size
                        : static_cast<size_t>(adding_to_size);
  if (static_cast<size_t>(adding_to_size) == total_summand_size) {
    ++max_size;
  }

  constexpr size_t STACK_LIMIT = 32;
  unsigned int  stack_buf[STACK_LIMIT];
  unsigned int *result =
      (max_size <= STACK_LIMIT) ? stack_buf : new unsigned int[max_size];

  unsigned int extra_digit = 0;

  const unsigned int* at_inner = adding_to.inner_words();
  int                 at_last  = adding_to_size - 1;
  const unsigned int* sm_inner = summand.inner_words();
  int                 sm_last  = summand_size - 1;

  for (size_t i = 0; i < word_shift; ++i) {
    if (static_cast<int>(i) < adding_to_size) {
      result[i] = (static_cast<int>(i) == at_last)
                      ? static_cast<unsigned int>(adding_to.oldest_digit_)
                      : at_inner[i];
    } else {
      result[i] = 0;
    }
  }

  int summand_pos = 0;
  for (size_t i = word_shift; i < max_size; ++i) {
    unsigned int this_digit;
    if (static_cast<int>(i) < adding_to_size) {
      this_digit = (static_cast<int>(i) == at_last)
                       ? static_cast<unsigned int>(adding_to.oldest_digit_)
                       : at_inner[i];
    } else {
      this_digit = 0;
    }

    unsigned int other_digit;
    if (summand_pos < summand_size) {
      other_digit = (summand_pos == sm_last)
                        ? static_cast<unsigned int>(summand.oldest_digit_)
                        : sm_inner[summand_pos];
    } else {
      other_digit = 0;
    }
    ++summand_pos;

    unsigned long long sum =
        static_cast<unsigned long long>(this_digit) + other_digit + extra_digit;

    result[i]   = static_cast<unsigned int>(sum);
    extra_digit = static_cast<unsigned int>(sum >> (sizeof(int) * 8));
  }

  if (result == stack_buf) {
    adding_to.from_array(reinterpret_cast<int *>(result), max_size);
  } else {
    adding_to.move_from_array(reinterpret_cast<int *>(result), max_size);
  }
}