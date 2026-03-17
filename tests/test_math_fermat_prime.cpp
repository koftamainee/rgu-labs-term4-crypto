//
// Created by koftamainee on 3/17/26.
//
#include "math/fermat_prime_test.h"
#include <gtest/gtest.h>

TEST(FermatPrimeTest, SmallPrimesAreDetected) {
  math::FermatPrimeTest test;
  ASSERT_TRUE(test.is_prime(bigint(2L), 0.99));
  ASSERT_TRUE(test.is_prime(bigint(3L), 0.99));
  ASSERT_TRUE(test.is_prime(bigint(5L), 0.99));
  ASSERT_TRUE(test.is_prime(bigint(7L), 0.99));
  ASSERT_TRUE(test.is_prime(bigint(13L), 0.99));
}

TEST(FermatPrimeTest, SmallCompositesAreRejected) {
  math::FermatPrimeTest test;
  ASSERT_FALSE(test.is_prime(bigint(4L), 0.99));
  ASSERT_FALSE(test.is_prime(bigint(6L), 0.99));
  ASSERT_FALSE(test.is_prime(bigint(8L), 0.99));
  ASSERT_FALSE(test.is_prime(bigint(9L), 0.99));
  ASSERT_FALSE(test.is_prime(bigint(15L), 0.99));
}

TEST(FermatPrimeTest, LargePrime) {
  math::FermatPrimeTest test;
  ASSERT_TRUE(test.is_prime(bigint(7919L), 0.99));
}

TEST(FermatPrimeTest, LargeComposite) {
  math::FermatPrimeTest test;
  ASSERT_FALSE(test.is_prime(bigint(8000L), 0.99));
}

TEST(FermatPrimeTest, OneIsNotPrime) {
  math::FermatPrimeTest test;
  ASSERT_FALSE(test.is_prime(bigint(1L), 0.99));
}

TEST(FermatPrimeTest, TwoIsPrime) {
  math::FermatPrimeTest test;
  ASSERT_TRUE(test.is_prime(bigint(2L), 0.99));
}

TEST(FermatPrimeTest, PseudoprimeFailsOccasionally) {
  math::FermatPrimeTest test;
  ASSERT_FALSE(test.is_prime(bigint(561L), 0.99));
  ASSERT_FALSE(test.is_prime(bigint(1105L), 0.99));
}

TEST(FermatPrimeTest, EdgeCases) {
  math::FermatPrimeTest test;
  ASSERT_FALSE(test.is_prime(bigint(0), 0.99));
  ASSERT_FALSE(test.is_prime(bigint(-7L), 0.99));
}

