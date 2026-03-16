#include <gtest/gtest.h>
#include "ks05_t_mpsi/protocol/t_mpsi.h"
#include "ks05_t_mpsi/crypto/paillier.h"

using namespace mpsi::ks05;

TEST(SerializationTest, CiphertextRoundTrip) {
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pub;
    std::vector<PrivKey> sks;
    distributedKeyGen(512, 2, pub, sks);

    Ciphertext ct = enc(NTL::to_ZZ(12345), pub);
    std::string buf;
    serializeCiphertext(ct, buf);

    Ciphertext ct2;
    deserializeCiphertext(buf, ct2);
    EXPECT_EQ(ct, ct2);
}

TEST(SerializationTest, ZZRoundTrip) {
    ZZ val = NTL::to_ZZ(987654321);
    std::string buf;
    serializeZZ(val, buf);

    ZZ val2;
    deserializeZZ(buf, val2);
    EXPECT_EQ(val, val2);
}

TEST(SerializationTest, ZeroZZ) {
    ZZ val = NTL::to_ZZ(0);
    std::string buf;
    serializeZZ(val, buf);

    ZZ val2;
    deserializeZZ(buf, val2);
    EXPECT_EQ(val2, NTL::to_ZZ(0));
}

TEST(SerializationTest, LargeZZ) {
    // 2^1024 - 1
    ZZ val = NTL::power2_ZZ(1024) - 1;
    std::string buf;
    serializeZZ(val, buf);

    ZZ val2;
    deserializeZZ(buf, val2);
    EXPECT_EQ(val, val2);
}
