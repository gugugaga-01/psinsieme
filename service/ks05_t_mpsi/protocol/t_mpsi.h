#pragma once

#include <vector>
#include <string>
#include <functional>
#include "../crypto/defines.h"
#include "../crypto/paillier.h"
#include "../../core/transport/channel.h"

namespace mpsi::ks05 {

// Paillier modulus bit length.  3072 bits = 128-bit security (NIST SP 800-57).
constexpr long PAILLIER_KEY_BITS = 3072;

struct TMpsiBase {
    u64 mNumberOfParties;
    u64 mThreshold;
    u64 mPartyID;
    u64 mSenderSize;
    u64 mRecverSize;
    u64 mLocalSetSize;      // This party's actual input size
    u64 mNegotiatedSetSize; // Max set size across all parties (set during negotiation)
    u64 mNumThreads = 1;
    bool mDebug = false;
    bool mCryptoInitialized = false;

    PubKey mPubKey;
    PrivKey mPrivKey;

    void init(u64 numberOfParties,
              u64 threshold,
              u64 partyID,
              u64 senderSize,
              u64 recverSize,
              bool debug);

    // Set pre-distributed keys from the dealer.
    void setKeys(const PubKey& pk, const PrivKey& sk);

    virtual ~TMpsiBase() = default;
};

class TMpsiMember : public TMpsiBase {
public:
    // Run the member protocol.
    // inputs: member's private set elements (as ZZ values mod n)
    // channels: [0]=leader, [1]=prev party (if not P0), [2]=next party (if not last)
    void run(const std::vector<ZZ>& inputs, std::vector<mpsi::Channel*>& channels);

private:
    // Negotiate set sizes with leader at the start of run().
    void negotiateSetSize(mpsi::Channel* leaderChannel);
};

class TMpsiLeader : public TMpsiBase {
public:
    // Run the leader protocol. Returns intersection elements.
    // inputs: leader's private set elements (as ZZ values mod n)
    // channels: one per member [0..n-2]
    std::vector<ZZ> run(const std::vector<ZZ>& inputs, std::vector<mpsi::Channel*>& channels);

private:
    // Negotiate set sizes with all members at the start of run().
    void negotiateSetSize(std::vector<mpsi::Channel*>& channels);
};

// Serialization helpers for ciphertexts over channels
void serializeCiphertext(const Ciphertext& ct, std::string& out);
void deserializeCiphertext(const std::string& in, Ciphertext& ct);

// Serialization helpers for ZZ values
void serializeZZ(const ZZ& val, std::string& out);
void deserializeZZ(const std::string& in, ZZ& val);

} // namespace mpsi::ks05
