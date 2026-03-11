#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <set>

#include "dealer/dealer_service.h"
#include "ks05_t_mpsi/crypto/paillier.h"
#include "ks05_t_mpsi/protocol/t_mpsi.h"

using namespace mpsi::ks05;
using namespace mpsi;

class DealerServiceTest : public ::testing::Test {
protected:
    // Helper: build a KeyShareRequest for a given party_id and num_parties.
    static KeyShareRequest makeRequest(uint64_t party_id, uint64_t num_parties) {
        KeyShareRequest req;
        req.set_party_id(party_id);
        req.set_num_parties(num_parties);
        return req;
    }

    // Helper: deserialize a ZZ from a raw byte string (inverse of
    // KeyDealerImpl's internal serializeZZ).
    static NTL::ZZ deserializeZZ(const std::string& bytes) {
        return NTL::ZZFromBytes(
            reinterpret_cast<const unsigned char*>(bytes.data()),
            bytes.size());
    }

    // Helper: reconstruct a PubKey from a KeyShareResponse.
    static PubKey extractPubKey(const KeyShareResponse& resp) {
        PubKey pk;
        pk.n     = deserializeZZ(resp.public_key_n());
        pk.n2    = pk.n * pk.n;
        pk.g     = pk.n + 1;
        pk.theta = deserializeZZ(resp.public_key_theta());
        pk.delta = deserializeZZ(resp.public_key_delta());
        return pk;
    }

    // Helper: reconstruct a PrivKey from a KeyShareResponse.
    static PrivKey extractPrivKey(const KeyShareResponse& resp) {
        PrivKey sk;
        sk.s = deserializeZZ(resp.secret_key_share());
        return sk;
    }
};

// All parties should receive the same public key.
TEST_F(DealerServiceTest, AllPartiesGetSamePublicKey) {
    const uint64_t n = 3;
    mpsi::KeyDealerImpl dealer(n);

    std::vector<KeyShareResponse> responses(n);
    for (uint64_t i = 0; i < n; i++) {
        auto req = makeRequest(i, n);
        grpc::ServerContext ctx;
        ASSERT_TRUE(dealer.GetKeyShare(&ctx, &req, &responses[i]).ok());
        ASSERT_EQ(responses[i].status().code(), STATUS_OK);
    }

    PubKey pk0 = extractPubKey(responses[0]);
    for (uint64_t i = 1; i < n; i++) {
        PubKey pki = extractPubKey(responses[i]);
        EXPECT_EQ(pk0.n, pki.n)
            << "Party " << i << " got a different modulus n";
        EXPECT_EQ(pk0.theta, pki.theta)
            << "Party " << i << " got a different theta";
        EXPECT_EQ(pk0.delta, pki.delta)
            << "Party " << i << " got a different delta";
    }
}

// Each party should receive a distinct secret key share.
TEST_F(DealerServiceTest, EachPartyGetsDifferentSecretKey) {
    const uint64_t n = 3;
    mpsi::KeyDealerImpl dealer(n);

    std::set<std::string> shares;
    for (uint64_t i = 0; i < n; i++) {
        auto req = makeRequest(i, n);
        KeyShareResponse resp;
        grpc::ServerContext ctx;
        ASSERT_TRUE(dealer.GetKeyShare(&ctx, &req, &resp).ok());
        ASSERT_EQ(resp.status().code(), STATUS_OK);

        // The raw serialized share must be unique per party.
        bool inserted = shares.insert(resp.secret_key_share()).second;
        EXPECT_TRUE(inserted)
            << "Party " << i << " got a duplicate secret key share";
    }
}

// waitUntilDone() should return once all expected parties have collected.
TEST_F(DealerServiceTest, WaitUntilDoneReturnsAfterAllCollect) {
    const uint64_t n = 3;
    mpsi::KeyDealerImpl dealer(n);

    EXPECT_FALSE(dealer.allCollected());

    // Serve all parties.
    for (uint64_t i = 0; i < n; i++) {
        auto req = makeRequest(i, n);
        KeyShareResponse resp;
        grpc::ServerContext ctx;
        ASSERT_TRUE(dealer.GetKeyShare(&ctx, &req, &resp).ok());
    }

    // waitUntilDone() should return immediately now.
    std::thread waiter([&]() { dealer.waitUntilDone(); });
    waiter.join();

    EXPECT_TRUE(dealer.allCollected());
}

// Invalid party_id should be rejected.
TEST_F(DealerServiceTest, RejectsInvalidPartyId) {
    const uint64_t n = 3;
    mpsi::KeyDealerImpl dealer(n);

    auto req = makeRequest(5, n); // party_id >= num_parties
    KeyShareResponse resp;
    grpc::ServerContext ctx;
    ASSERT_TRUE(dealer.GetKeyShare(&ctx, &req, &resp).ok());
    EXPECT_EQ(resp.status().code(), STATUS_INVALID_PARAMS);
}

// Mismatched num_parties should be rejected.
TEST_F(DealerServiceTest, RejectsNumPartiesMismatch) {
    const uint64_t n = 3;
    mpsi::KeyDealerImpl dealer(n);

    auto req = makeRequest(0, 5); // dealer expects 3, request says 5
    KeyShareResponse resp;
    grpc::ServerContext ctx;
    ASSERT_TRUE(dealer.GetKeyShare(&ctx, &req, &resp).ok());
    EXPECT_EQ(resp.status().code(), STATUS_INVALID_PARAMS);
}

// Distributed keys from the dealer should produce a valid Paillier
// encrypt-then-threshold-decrypt round trip.
TEST_F(DealerServiceTest, DealerKeysEnableEncryptDecrypt) {
    const uint64_t n = 3;
    mpsi::KeyDealerImpl dealer(n);

    PubKey pk;
    std::vector<PrivKey> sks(n);

    for (uint64_t i = 0; i < n; i++) {
        auto req = makeRequest(i, n);
        KeyShareResponse resp;
        grpc::ServerContext ctx;
        ASSERT_TRUE(dealer.GetKeyShare(&ctx, &req, &resp).ok());
        ASSERT_EQ(resp.status().code(), STATUS_OK);

        if (i == 0) pk = extractPubKey(resp);
        sks[i] = extractPrivKey(resp);
    }

    // Encrypt a message and threshold-decrypt it.
    NTL::ZZ msg = NTL::to_ZZ(12345);
    ks05::Ciphertext ct = enc(msg, pk);

    std::vector<ks05::Ciphertext> partials;
    for (auto& sk : sks)
        partials.push_back(partialDec(ct, pk, sk));

    NTL::ZZ result = fuseDec(partials, pk);
    EXPECT_EQ(result, msg);
}
