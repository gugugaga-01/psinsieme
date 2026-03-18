#include <gtest/gtest.h>
#include "protocols/beh21/protocol/ot_mpsi.h"
#include "protocols/ks05/crypto/paillier.h"

using namespace mpsi::ks05;
using namespace mpsi::beh21;

class SignedPlaintextTest : public ::testing::Test {
protected:
    void SetUp() override {
        NTL::SetSeed(NTL::to_ZZ(123UL));
        keyGen(pk, sk, 512); // small key for fast tests
    }

    PubKey pk;
    PrivKey sk;
};

TEST_F(SignedPlaintextTest, ZeroIsNonPositive) {
    EXPECT_TRUE(signedNonPositive(NTL::to_ZZ(0), pk));
}

TEST_F(SignedPlaintextTest, SmallPositiveIsNotNonPositive) {
    EXPECT_FALSE(signedNonPositive(NTL::to_ZZ(1), pk));
    EXPECT_FALSE(signedNonPositive(NTL::to_ZZ(42), pk));
    EXPECT_FALSE(signedNonPositive(NTL::to_ZZ(100), pk));
}

TEST_F(SignedPlaintextTest, LargeValueIsNonPositive) {
    // Values > n/2 represent negative numbers in the signed interpretation
    NTL::ZZ large = pk.n - 1; // represents -1
    EXPECT_TRUE(signedNonPositive(large, pk));

    NTL::ZZ alsoNeg = pk.n - 42; // represents -42
    EXPECT_TRUE(signedNonPositive(alsoNeg, pk));
}

TEST_F(SignedPlaintextTest, BoundaryValues) {
    NTL::ZZ halfN = pk.n / 2;
    // halfN is still positive (barely)
    EXPECT_FALSE(signedNonPositive(halfN, pk));

    // halfN + 1 crosses into negative territory
    EXPECT_TRUE(signedNonPositive(halfN + 1, pk));
}

TEST_F(SignedPlaintextTest, EncryptDecryptSignedComparison) {
    // Encrypt k - c where c == k, so difference = 0
    // After SCP blinding: result should decrypt to a non-positive value
    NTL::ZZ k = NTL::to_ZZ(5);
    NTL::ZZ c = NTL::to_ZZ(5);

    // k - c = 0 mod n, which is non-positive
    NTL::ZZ diff = (k - c) % pk.n;
    if (diff < 0) diff += pk.n;
    EXPECT_TRUE(signedNonPositive(diff, pk));

    // k - c = 3 when c < k, positive
    NTL::ZZ diff2 = (k - NTL::to_ZZ(2)) % pk.n;
    if (diff2 < 0) diff2 += pk.n;
    EXPECT_FALSE(signedNonPositive(diff2, pk));

    // k - c = -2 mod n when c > k, wraps to n-2 which is > n/2, so negative
    NTL::ZZ diff3 = (k - NTL::to_ZZ(7) + pk.n) % pk.n;
    EXPECT_TRUE(signedNonPositive(diff3, pk));
}
