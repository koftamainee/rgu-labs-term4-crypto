#include "bigint.h"

int bigint::compare(bigint const &first, bigint const &second) {
  auto const first_sign  = first.sign();
  auto const second_sign = second.sign();
  auto const first_size  = first.size();
  auto const second_size = second.size();
  int positives = 1;

  if (first_sign == -1 && second_sign >= 0) return -1;
  if (first_sign >= 0 && second_sign == -1) return 1;
  if (first_sign == -1 && second_sign == -1) positives = -1;

  if (first_size > second_size) return  1 * positives;
  if (second_size > first_size) return -1 * positives;

  if (first_size == 1) {
    unsigned int a = static_cast<unsigned int>(first.oldest_digit_);
    unsigned int b = static_cast<unsigned int>(second.oldest_digit_);
    if (a > b) return  1 * positives;
    if (b > a) return -1 * positives;
    return 0;
  }

  unsigned int fa = static_cast<unsigned int>(first.oldest_digit_);
  unsigned int sa = static_cast<unsigned int>(second.oldest_digit_);
  if (fa > sa) return  1 * positives;
  if (sa > fa) return -1 * positives;

  const unsigned int* fp = first.inner_words();
  const unsigned int* sp = second.inner_words();
  for (int i = first_size - 2; i >= 0; --i) {
    if (fp[i] > sp[i]) return  1 * positives;
    if (sp[i] > fp[i]) return -1 * positives;
  }
  return 0;
}

bool operator==(bigint const &first, bigint const &second) {
  return bigint::compare(first, second) == 0;
}
bool operator!=(bigint const &first, bigint const &second) {
  return bigint::compare(first, second) != 0;
}
bool operator<(bigint const &first, bigint const &second) {
  return bigint::compare(first, second) < 0;
}
bool operator<=(bigint const &first, bigint const &second) {
  return bigint::compare(first, second) <= 0;
}
bool operator>(bigint const &first, bigint const &second) {
  return bigint::compare(first, second) > 0;
}
bool operator>=(bigint const &first, bigint const &second) {
  return bigint::compare(first, second) >= 0;
}