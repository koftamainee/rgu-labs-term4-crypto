#include <gtest/gtest.h>
#include "math/utils.hpp"
TEST(LegendreSymbol, ZeroReturnsZero) {
    ASSERT_EQ(math::legendre_symbol(bigint(0L), bigint(7L)), 0);
}

TEST(LegendreSymbol, QuadraticResidue) {
    ASSERT_EQ(math::legendre_symbol(bigint(2L), bigint(7L)), 1);
}

TEST(LegendreSymbol, QuadraticNonResidue) {
    ASSERT_EQ(math::legendre_symbol(bigint(3L), bigint(7L)), -1);
}

TEST(LegendreSymbol, MultipleOfP) {
    ASSERT_EQ(math::legendre_symbol(bigint(14L), bigint(7L)), 0);
}

TEST(LegendreSymbol, OneIsAlwaysResidue) {
    ASSERT_EQ(math::legendre_symbol(bigint(1L), bigint(11L)), 1);
    ASSERT_EQ(math::legendre_symbol(bigint(1L), bigint(13L)), 1);
    ASSERT_EQ(math::legendre_symbol(bigint(1L), bigint(17L)), 1);
}

TEST(LegendreSymbol, LargePrime) {
    ASSERT_EQ(math::legendre_symbol(bigint(2L), bigint(17L)), 1);
}

TEST(JacobiSymbol, InvalidEvenNThrows) {
    ASSERT_THROW(math::jacobi_symbol(bigint(1L), bigint(4L)), std::invalid_argument);
}

TEST(JacobiSymbol, InvalidNonPositiveNThrows) {
    ASSERT_THROW(math::jacobi_symbol(bigint(1L), bigint(0L)), std::invalid_argument);
    ASSERT_THROW(math::jacobi_symbol(bigint(1L), bigint(-1L)), std::invalid_argument);
}

TEST(JacobiSymbol, ZeroReturnsZero) {
    ASSERT_EQ(math::jacobi_symbol(bigint(0L), bigint(9L)), 0);
}

TEST(JacobiSymbol, OneReturnsOne) {
    ASSERT_EQ(math::jacobi_symbol(bigint(1L), bigint(9L)), 1);
}

TEST(JacobiSymbol, MatchesLegendreForPrime) {
    ASSERT_EQ(math::jacobi_symbol(bigint(2L), bigint(7L)), 1);
    ASSERT_EQ(math::jacobi_symbol(bigint(3L), bigint(7L)), -1);
}

TEST(JacobiSymbol, CompositeN) {
    ASSERT_EQ(math::jacobi_symbol(bigint(2L), bigint(9L)), 1);
}

TEST(JacobiSymbol, NegativeA) {
    ASSERT_EQ(math::jacobi_symbol(bigint(-1L), bigint(15L)), -1);
}

TEST(Gcd, BothZero) {
    ASSERT_EQ(math::gcd(bigint(0L), bigint(0L)), bigint(0L));
}

TEST(Gcd, OneZero) {
    ASSERT_EQ(math::gcd(bigint(5L), bigint(0L)), bigint(5L));
    ASSERT_EQ(math::gcd(bigint(0L), bigint(7L)), bigint(7L));
}

TEST(Gcd, Coprime) {
    ASSERT_EQ(math::gcd(bigint(7L), bigint(13L)), bigint(1L));
}

TEST(Gcd, CommonDivisor) {
    ASSERT_EQ(math::gcd(bigint(12L), bigint(8L)), bigint(4L));
}

TEST(Gcd, SameNumbers) {
    ASSERT_EQ(math::gcd(bigint(6L), bigint(6L)), bigint(6L));
}

TEST(Gcd, NegativeInputs) {
    ASSERT_EQ(math::gcd(bigint(-12L), bigint(8L)), bigint(4L));
    ASSERT_EQ(math::gcd(bigint(12L), bigint(-8L)), bigint(4L));
}

TEST(Gcd, Commutative) {
    ASSERT_EQ(math::gcd(bigint(48L), bigint(18L)), bigint(6L));
    ASSERT_EQ(math::gcd(bigint(18L), bigint(48L)), bigint(6L));
}

TEST(Egcd, Basic) {
    auto res = math::egcd(bigint(35L), bigint(15L));
    ASSERT_EQ(res.gcd, bigint(5L));
    ASSERT_EQ(res.x, bigint(1L));
    ASSERT_EQ(res.y, bigint(-2L));
}

TEST(Egcd, Coprime) {
    auto res = math::egcd(bigint(7L), bigint(13L));
    ASSERT_EQ(res.gcd, bigint(1L));
    ASSERT_EQ(res.x, bigint(2L));
    ASSERT_EQ(res.y, bigint(-1L));
}

TEST(Egcd, OneZero) {
    auto res = math::egcd(bigint(5L), bigint(0L));
    ASSERT_EQ(res.gcd, bigint(5L));
    ASSERT_EQ(res.x, bigint(1L));
    ASSERT_EQ(res.y, bigint(0L));
}

TEST(Egcd, LargeNumbers) {
    auto res = math::egcd(bigint(1234567890L), bigint(987654321L));
    ASSERT_EQ(res.gcd, bigint(9L));
    ASSERT_EQ(res.x, bigint(21947873L));
    ASSERT_EQ(res.y, bigint(-27434841L));
}

TEST(Powm, BaseZero) {
    ASSERT_EQ(math::powm(bigint(0L), bigint(5L), bigint(7L)), bigint(0L));
}

TEST(Powm, ExpZero) {
    ASSERT_EQ(math::powm(bigint(5L), bigint(0L), bigint(7L)), bigint(1L));
}

TEST(Powm, ExpOne) {
    ASSERT_EQ(math::powm(bigint(5L), bigint(1L), bigint(7L)), bigint(5L));
}

TEST(Powm, BasicCase) {
    ASSERT_EQ(math::powm(bigint(2L), bigint(10L), bigint(1000L)), bigint(24L));
}

TEST(Powm, FermatLittleTheorem) {
    ASSERT_EQ(math::powm(bigint(3L), bigint(6L), bigint(7L)), bigint(1L));
}

TEST(Powm, ModOneAlwaysZero) {
    ASSERT_EQ(math::powm(bigint(123L), bigint(456L), bigint(1L)), bigint(0L));
}

TEST(Powm, LargeBase) {
    ASSERT_EQ(math::powm(bigint(123456789L), bigint(2L), bigint(1000000007L)), bigint(643499475L));
}

TEST(ModInverse, BasicCase) {
    ASSERT_EQ(math::mod_inverse(bigint(3L), bigint(7L)), bigint(5L));
}

TEST(ModInverse, VerifyResult) {
    ASSERT_EQ(math::mod_inverse(bigint(17L), bigint(31L)), bigint(11L));
}

TEST(ModInverse, NotCoprimeThrows) {
    ASSERT_THROW(math::mod_inverse(bigint(4L), bigint(8L)), std::invalid_argument);
}

TEST(ModInverse, OneAlwaysOne) {
    ASSERT_EQ(math::mod_inverse(bigint(1L), bigint(7L)), bigint(1L));
}

TEST(ModInverse, ResultInRange) {
    bigint inv = math::mod_inverse(bigint(3L), bigint(11L));
    ASSERT_EQ(inv, bigint(4L));
}

TEST(EulerPhiDefinition, One) {
    ASSERT_EQ(math::euler_phi_definition(bigint(1L)), bigint(1L));
}

TEST(EulerPhiDefinition, Two) {
    ASSERT_EQ(math::euler_phi_definition(bigint(2L)), bigint(1L));
}

TEST(EulerPhiDefinition, Prime) {
    ASSERT_EQ(math::euler_phi_definition(bigint(7L)), bigint(6L));
    ASSERT_EQ(math::euler_phi_definition(bigint(13L)), bigint(12L));
}

TEST(EulerPhiDefinition, PrimePower) {
    ASSERT_EQ(math::euler_phi_definition(bigint(8L)), bigint(4L));
}

TEST(EulerPhiDefinition, Composite) {
    ASSERT_EQ(math::euler_phi_definition(bigint(12L)), bigint(4L));
}

TEST(EulerPhiFactorization, MatchesDefinitionUpTo50) {
    for (long int n = 1; n <= 50; ++n) {
        ASSERT_EQ(math::euler_phi_factorization(bigint(n)),
                  math::euler_phi_definition(bigint(n))) << "n = " << n;
    }
}

TEST(EulerPhiFactorization, LargePrime) {
    ASSERT_EQ(math::euler_phi_factorization(bigint(9973L)), bigint(9972L));
}

TEST(EulerPhiFactorization, PowerOfTwo) {
    ASSERT_EQ(math::euler_phi_factorization(bigint(64L)), bigint(32L));
}

TEST(EulerPhiDft, MatchesDefinitionUpTo20) {
    for (long int n = 1; n <= 20; ++n) {
        ASSERT_EQ(math::euler_phi_dft(bigint(n)),
                  math::euler_phi_definition(bigint(n))) << "n = " << n;
    }
}

TEST(EulerPhiDft, Prime) {
    ASSERT_EQ(math::euler_phi_dft(bigint(11L)), bigint(10L));
}

TEST(EulerPhiDft, Composite) {
    ASSERT_EQ(math::euler_phi_dft(bigint(12L)), bigint(4L));
}