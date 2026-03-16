#include <gtest/gtest.h>
#include "ks05_t_mpsi/crypto/paillier.h"

using namespace mpsi::ks05;

class PaillierTest : public ::testing::Test {
protected:
    void SetUp() override {
        NTL::SetSeed(NTL::to_ZZ(42UL));
        distributedKeyGen(512, 3, pub, privKeys);
    }

    PubKey pub;
    std::vector<PrivKey> privKeys;
};

TEST_F(PaillierTest, EncryptDecrypt) {
    ZZ msg = NTL::to_ZZ(12345);
    Ciphertext ct = enc(msg, pub);

    // Partial decrypt with all parties, then fuse
    std::vector<Ciphertext> partials;
    for (auto& sk : privKeys)
        partials.push_back(partialDec(ct, pub, sk));

    ZZ result = fuseDec(partials, pub);
    EXPECT_EQ(result, msg);
}

TEST_F(PaillierTest, EncryptZero) {
    ZZ msg = NTL::to_ZZ(0);
    Ciphertext ct = enc(msg, pub);

    std::vector<Ciphertext> partials;
    for (auto& sk : privKeys)
        partials.push_back(partialDec(ct, pub, sk));

    EXPECT_EQ(fuseDec(partials, pub), msg);
}

TEST_F(PaillierTest, HomomorphicAdd) {
    ZZ a = NTL::to_ZZ(100);
    ZZ b = NTL::to_ZZ(200);

    Ciphertext ct_a = enc(a, pub);
    Ciphertext ct_b = enc(b, pub);
    Ciphertext ct_sum = add(ct_a, ct_b, pub);

    std::vector<Ciphertext> partials;
    for (auto& sk : privKeys)
        partials.push_back(partialDec(ct_sum, pub, sk));

    EXPECT_EQ(fuseDec(partials, pub), a + b);
}

TEST_F(PaillierTest, HomomorphicScalarMul) {
    ZZ msg = NTL::to_ZZ(7);
    ZZ scalar = NTL::to_ZZ(6);

    Ciphertext ct = enc(msg, pub);
    Ciphertext ct_mul = mul(ct, scalar, pub);

    std::vector<Ciphertext> partials;
    for (auto& sk : privKeys)
        partials.push_back(partialDec(ct_mul, pub, sk));

    EXPECT_EQ(fuseDec(partials, pub), msg * scalar);
}

TEST_F(PaillierTest, DifferentRandomness) {
    ZZ msg = NTL::to_ZZ(42);
    Ciphertext ct1 = enc(msg, pub);
    Ciphertext ct2 = enc(msg, pub);

    // Same plaintext, different ciphertexts (probabilistic encryption)
    EXPECT_NE(ct1, ct2);

    // But both decrypt to same value
    auto decrypt = [&](const Ciphertext& ct) {
        std::vector<Ciphertext> partials;
        for (auto& sk : privKeys)
            partials.push_back(partialDec(ct, pub, sk));
        return fuseDec(partials, pub);
    };

    EXPECT_EQ(decrypt(ct1), decrypt(ct2));
}

TEST_F(PaillierTest, HomomorphicSub) {
    ZZ a = NTL::to_ZZ(300);
    ZZ b = NTL::to_ZZ(100);

    Ciphertext ct_a = enc(a, pub);
    Ciphertext ct_b = enc(b, pub);
    Ciphertext ct_diff = sub(ct_a, ct_b, pub);

    std::vector<Ciphertext> partials;
    for (auto& sk : privKeys)
        partials.push_back(partialDec(ct_diff, pub, sk));

    EXPECT_EQ(fuseDec(partials, pub), a - b);
}

TEST_F(PaillierTest, Rerandomization) {
    ZZ msg = NTL::to_ZZ(77);
    Ciphertext ct = enc(msg, pub);
    Ciphertext ct_rerand = rerand(ct, pub);

    // Ciphertext changes
    EXPECT_NE(ct, ct_rerand);

    // But plaintext preserved
    auto decrypt = [&](const Ciphertext& c) {
        std::vector<Ciphertext> partials;
        for (auto& sk : privKeys)
            partials.push_back(partialDec(c, pub, sk));
        return fuseDec(partials, pub);
    };

    EXPECT_EQ(decrypt(ct), decrypt(ct_rerand));
}

TEST_F(PaillierTest, LargeMessage) {
    // Encrypt a value near the upper bound of the plaintext space
    ZZ msg = pub.n - 1;
    Ciphertext ct = enc(msg, pub);

    std::vector<Ciphertext> partials;
    for (auto& sk : privKeys)
        partials.push_back(partialDec(ct, pub, sk));

    EXPECT_EQ(fuseDec(partials, pub), msg);
}

TEST(PaillierSingleKeyTest, SingleKeyGen) {
    NTL::SetSeed(NTL::to_ZZ(123UL));
    PubKey pub;
    PrivKey sk;
    keyGen(pub, sk, 512);

    ZZ msg = NTL::to_ZZ(42);
    Ciphertext ct = enc(msg, pub);
    Plaintext pt = dec(ct, pub, sk);
    EXPECT_EQ(pt, msg);
}
