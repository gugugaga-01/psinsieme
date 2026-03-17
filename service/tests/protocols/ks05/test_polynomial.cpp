#include <gtest/gtest.h>
#include "protocols/ks05/crypto/polynomial.h"
#include "protocols/ks05/crypto/paillier.h"

using namespace mpsi::ks05;

class PolynomialTest : public ::testing::Test {
protected:
    ZZ mod = NTL::to_ZZ(97); // small prime for readable tests
};

TEST_F(PolynomialTest, EncodeRoots) {
    // Polynomial with roots {2, 5} mod 97: (x-2)(x-5) = x^2 - 7x + 10
    std::vector<ZZ> roots = {NTL::to_ZZ(2), NTL::to_ZZ(5)};
    Polynomial poly = encodeAsPolynomial(roots, mod);

    EXPECT_EQ(poly.degree(), 2u);
    EXPECT_EQ(poly.evaluateAt(NTL::to_ZZ(2), mod), NTL::to_ZZ(0));
    EXPECT_EQ(poly.evaluateAt(NTL::to_ZZ(5), mod), NTL::to_ZZ(0));
    EXPECT_NE(poly.evaluateAt(NTL::to_ZZ(3), mod), NTL::to_ZZ(0));
}

TEST_F(PolynomialTest, EvaluateAtNonRoot) {
    std::vector<ZZ> roots = {NTL::to_ZZ(1), NTL::to_ZZ(3)};
    Polynomial poly = encodeAsPolynomial(roots, mod);

    // (x-1)(x-3) evaluated at x=0: (-1)(-3) = 3
    EXPECT_EQ(poly.evaluateAt(NTL::to_ZZ(0), mod), NTL::to_ZZ(3));
}

TEST_F(PolynomialTest, PolynomialMultiplication) {
    // (x + 1) * (x + 2) = x^2 + 3x + 2
    Polynomial p1({NTL::to_ZZ(1), NTL::to_ZZ(1)}); // 1 + x
    Polynomial p2({NTL::to_ZZ(2), NTL::to_ZZ(1)}); // 2 + x

    p1.mulPoly(p2);
    EXPECT_EQ(p1.degree(), 2u);
    EXPECT_EQ(p1.coefficients[0], NTL::to_ZZ(2)); // constant term
    EXPECT_EQ(p1.coefficients[1], NTL::to_ZZ(3)); // x coefficient
    EXPECT_EQ(p1.coefficients[2], NTL::to_ZZ(1)); // x^2 coefficient
}

TEST_F(PolynomialTest, Derivative) {
    // f(x) = 3 + 2x + 5x^2 => f'(x) = 2 + 10x
    std::vector<ZZ> coeffs = {NTL::to_ZZ(3), NTL::to_ZZ(2), NTL::to_ZZ(5)};
    Polynomial poly(coeffs);

    poly.derivative();
    EXPECT_EQ(poly.degree(), 1u);
    EXPECT_EQ(poly.coefficients[0], NTL::to_ZZ(2));
    EXPECT_EQ(poly.coefficients[1], NTL::to_ZZ(10));
}

TEST_F(PolynomialTest, DerivativeHigherOrder) {
    // f(x) = x^3 => f'(x) = 3x^2 => f''(x) = 6x
    std::vector<ZZ> coeffs = {NTL::to_ZZ(0), NTL::to_ZZ(0), NTL::to_ZZ(0), NTL::to_ZZ(1)};
    Polynomial poly(coeffs);

    poly.derivative();
    poly.derivative();
    EXPECT_EQ(poly.degree(), 1u);
    EXPECT_EQ(poly.coefficients[0], NTL::to_ZZ(0));
    EXPECT_EQ(poly.coefficients[1], NTL::to_ZZ(6));
}

class PaillierPolynomialTest : public ::testing::Test {
protected:
    void SetUp() override {
        NTL::SetSeed(NTL::to_ZZ(99UL));
        distributedKeyGen(512, 2, pub, privKeys);
    }

    ZZ decrypt(const Ciphertext& ct) {
        std::vector<Ciphertext> partials;
        for (auto& sk : privKeys)
            partials.push_back(partialDec(ct, pub, sk));
        return fuseDec(partials, pub);
    }

    PubKey pub;
    std::vector<PrivKey> privKeys;
};

TEST_F(PaillierPolynomialTest, EncryptedScalarMulPoly) {
    // Encrypted [3, 5] * plaintext (1 + 2x) = [3, 11, 10]
    std::vector<Ciphertext> enc_coeffs = {enc(NTL::to_ZZ(3), pub), enc(NTL::to_ZZ(5), pub)};
    PaillierPolynomial epoly(enc_coeffs, pub);

    Polynomial plain({NTL::to_ZZ(1), NTL::to_ZZ(2)});
    epoly.mulPoly(plain);

    EXPECT_EQ(epoly.degree(), 2u);
    EXPECT_EQ(decrypt(epoly.coefficients[0]), NTL::to_ZZ(3));
    EXPECT_EQ(decrypt(epoly.coefficients[1]), NTL::to_ZZ(11) % pub.n);
    EXPECT_EQ(decrypt(epoly.coefficients[2]), NTL::to_ZZ(10));
}

TEST_F(PaillierPolynomialTest, EncryptedPolyAdd) {
    std::vector<Ciphertext> enc1 = {enc(NTL::to_ZZ(1), pub), enc(NTL::to_ZZ(2), pub)};
    std::vector<Ciphertext> enc2 = {enc(NTL::to_ZZ(3), pub), enc(NTL::to_ZZ(4), pub), enc(NTL::to_ZZ(5), pub)};

    PaillierPolynomial p1(enc1, pub);
    PaillierPolynomial p2(enc2, pub);

    p1.addPoly(p2);

    EXPECT_EQ(p1.degree(), 2u);
    EXPECT_EQ(decrypt(p1.coefficients[0]), NTL::to_ZZ(4));
    EXPECT_EQ(decrypt(p1.coefficients[1]), NTL::to_ZZ(6));
    EXPECT_EQ(decrypt(p1.coefficients[2]), NTL::to_ZZ(5));
}

TEST_F(PolynomialTest, SingleRoot) {
    // Polynomial with root {3} mod 97: (x-3)
    std::vector<ZZ> roots = {NTL::to_ZZ(3)};
    Polynomial poly = encodeAsPolynomial(roots, mod);

    EXPECT_EQ(poly.degree(), 1u);
    EXPECT_EQ(poly.evaluateAt(NTL::to_ZZ(3), mod), NTL::to_ZZ(0));
    EXPECT_NE(poly.evaluateAt(NTL::to_ZZ(4), mod), NTL::to_ZZ(0));
}

TEST_F(PolynomialTest, PolynomialAddition) {
    // (1 + 2x) + (3 + 4x) = (4 + 6x)
    Polynomial p1({NTL::to_ZZ(1), NTL::to_ZZ(2)});
    Polynomial p2({NTL::to_ZZ(3), NTL::to_ZZ(4)});

    p1.addPoly(p2);
    EXPECT_EQ(p1.degree(), 1u);
    EXPECT_EQ(p1.coefficients[0], NTL::to_ZZ(4));
    EXPECT_EQ(p1.coefficients[1], NTL::to_ZZ(6));
}

TEST_F(PaillierPolynomialTest, EncryptedEvalAtRoot) {
    // Polynomial with root {5} mod n — evaluating at 5 should decrypt to 0
    std::vector<ZZ> roots = {NTL::to_ZZ(5)};
    PaillierPolynomial epoly = encodeAsPaillierPolynomial(roots, pub);

    Ciphertext ct = epoly.evaluateAt(NTL::to_ZZ(5));
    EXPECT_EQ(decrypt(ct), NTL::to_ZZ(0));
}

TEST_F(PaillierPolynomialTest, EncryptedEvalAtNonRoot) {
    std::vector<ZZ> roots = {NTL::to_ZZ(5)};
    PaillierPolynomial epoly = encodeAsPaillierPolynomial(roots, pub);

    Ciphertext ct = epoly.evaluateAt(NTL::to_ZZ(7));
    EXPECT_NE(decrypt(ct), NTL::to_ZZ(0));
}
