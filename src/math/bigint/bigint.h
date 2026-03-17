#pragma once

#include <cstddef>
#include <exception>
#include <iostream>
#include <optional>

class bigint final {
 public:
  class mathematical_uncertainty_exception : public std::exception {};
  class zero_division_exception : public std::exception {};

  class division_result final {
   public:
    division_result(bigint const& quotient, bigint const& remainder);
    ~division_result() noexcept;
    division_result(division_result const& other);
    division_result& operator=(division_result const& other);
    division_result(division_result&& other) noexcept;
    division_result& operator=(division_result&& other) noexcept;

    bigint quotient() const;
    bigint remainder() const;

   private:
    bigint* quotient_;
    bigint* remainder_;

    void cleanup();
    void clone(division_result const& other);
    void move(division_result&& other) noexcept;
  };

  static division_result division(bigint const& dividend,
                                  bigint const& divisor);

  bigint() noexcept;
  bigint(char const* value, std::size_t base = 10);
  bigint(int const* value, std::size_t size);
  bigint(int value) noexcept;
  bigint(bigint const& other);
  bigint(bigint&& other) noexcept;
  ~bigint() noexcept;

  bigint& operator=(bigint const& other);
  bigint& operator=(bigint&& other) noexcept;

  bigint& from_array(int const* digits, std::size_t size);
  bigint& move_from_array(int* digits, std::size_t size);
  bigint& from_string(std::string const& str, std::size_t base);
  std::string to_string() const;
  std::optional<int> to_int() const noexcept;

  bigint& negate() &;
  bigint operator-() const;
  bigint& bit_inverse() &;
  bigint operator~() const;

  bigint& operator++() &;
  bigint const operator++(int) &;
  bigint& operator--() &;
  bigint const operator--(int) &;

  bigint& operator+=(bigint const& other) &;
  friend bigint operator+(bigint const& first, bigint const& second);

  bigint& operator-=(bigint const& other) &;
  friend bigint operator-(bigint const& first, bigint const& second);

  bigint& operator*=(bigint const& other) &;
  friend bigint operator*(bigint const& first, bigint const& second);

  bigint& operator/=(bigint const& other) &;
  friend bigint operator/(bigint const& first, bigint const& second);

  bigint& operator%=(bigint const& other) &;
  friend bigint operator%(bigint const& first, bigint const& second);

  bigint& operator&=(bigint const& other) &;
  friend bigint operator&(bigint const& first, bigint const& second);

  bigint& operator|=(bigint const& other) &;
  friend bigint operator|(bigint const& first, bigint const& second);

  bigint& operator^=(bigint const& other) &;
  friend bigint operator^(bigint const& first, bigint const& second);

  bigint& operator<<=(size_t shift) &;
  bigint operator<<(size_t shift) const;

  bigint& operator>>=(size_t shift) &;
  bigint operator>>(size_t shift) const;

  friend bool operator==(bigint const& first, bigint const& second);
  friend bool operator!=(bigint const& first, bigint const& second);
  friend bool operator<(bigint const& first, bigint const& second);
  friend bool operator<=(bigint const& first, bigint const& second);
  friend bool operator>(bigint const& first, bigint const& second);
  friend bool operator>=(bigint const& first, bigint const& second);

  static bigint factorial(bigint const& n);
  static bigint gcd(bigint a, bigint b);
  bigint pow(bigint const& exponent) const;
  bigint mod_pow(bigint exponent, bigint const& modulus) const;
  static bigint rand_range(const bigint& lower, const bigint& upper);

  bigint abs() const;

  friend std::ostream& operator<<(std::ostream& out,
                                  bigint const& num) noexcept;
  friend std::istream& operator>>(std::istream& in, bigint& num);

  // private:
  static constexpr unsigned int SHIFT = (sizeof(int) << 2);
  static constexpr unsigned int MASK = (1 << SHIFT) - 1;
  static constexpr unsigned int KARATSUBA_THRESHOLD = 4;

  int oldest_digit_;
  int* other_digits_;

  bigint& _raw_positive_increment();
  bigint& _raw_positive_decrement();
  bigint& _raw_negative_increment();
  bigint& _raw_negative_decrement();
  static void _add_with_shift(bigint& adding_to, bigint& summand, size_t shift);
  static void _add_with_word_shift(bigint& adding_to, bigint& summand,
                                   size_t shift);

  void cleanup();
  void clone(bigint const& other);
  void move(bigint&& other);

  bigint& multiply(bigint const& other);
  bigint& scholarbook_multiply(bigint const& other) &;
  bigint& karatsuba_multiply(bigint const& other) &;

  void remove_leading_zeros();
  int get_oldest_positive_bit_index() const noexcept;

  unsigned int operator[](std::size_t index) const noexcept;
  int& operator[](std::size_t index);

  inline unsigned int word_at(std::size_t index) const noexcept {
    if (index == static_cast<std::size_t>(size() - 1))
      return static_cast<unsigned int>(oldest_digit_);
    return static_cast<unsigned int>(other_digits_[index + 1]);
  }

  inline int& word_at_mutable(std::size_t index) noexcept {
    if (index == static_cast<std::size_t>(size() - 1))
      return oldest_digit_;
    return other_digits_[index + 1];
  }

  inline const unsigned int* inner_words() const noexcept {
    return other_digits_
               ? reinterpret_cast<const unsigned int*>(other_digits_ + 1)
               : nullptr;
  }

  inline unsigned int* inner_words_mutable() noexcept {
    return other_digits_
               ? reinterpret_cast<unsigned int*>(other_digits_ + 1)
               : nullptr;
  }

  int sign() const noexcept;
  int size() const noexcept;
  int bit_length() const noexcept;
  bigint get_lower(size_t m) const;
  bigint get_upper(size_t m) const;

  static int compare(bigint const& first, bigint const& second);
  static unsigned int loword(unsigned int value);
  static unsigned int hiword(unsigned int value);
  static void accumulate_multiplication(
      bigint& result, unsigned int* words_multiplication_result_digits,
      unsigned int a, unsigned int b, size_t position_shift);
  static void remove_insignificant_numbers_from_digits_array(int const* digits,
                                                             std::size_t& size);
};