#pragma once

#include <vector>
#include <array>
#include <cstdint>
#include "protocols/ks05/crypto/paillier.h"
#include "core/transport/channel.h"

namespace mpsi::beh21 {

using Element = std::array<uint8_t, 16>;

struct OtMpsiBase {
    uint64_t mNumberOfParties;
    uint64_t mThreshold;
    uint64_t mPartyID;
    uint64_t mSenderSize;      // This party's actual input size
    uint64_t mRecverSize;      // Leader's input size
    uint64_t mNegotiatedSetSize = 0; // Max set size across all parties (set during negotiation)
    bool mDebug = false;

    ks05::PubKey mPubKey;
    ks05::PrivKey mPrivKey;

    void init(uint64_t numberOfParties,
              uint64_t threshold,
              uint64_t partyID,
              uint64_t senderSize,
              uint64_t recverSize,
              bool debug);

    void setKeys(const ks05::PubKey& pk, const ks05::PrivKey& sk);

    virtual ~OtMpsiBase() = default;
};

class OtMpsiLeader : public OtMpsiBase {
public:
    std::vector<Element> run(const std::vector<Element>& inputs,
                              std::vector<mpsi::Channel*>& channels);
private:
    void negotiateSetSize(std::vector<mpsi::Channel*>& channels);
};

class OtMpsiMember : public OtMpsiBase {
public:
    void run(const std::vector<Element>& inputs,
             std::vector<mpsi::Channel*>& channels);
private:
    void negotiateSetSize(mpsi::Channel* leaderChannel);
};

// Signed plaintext helper: values > n/2 are interpreted as negative.
// Returns true if the plaintext represents a non-positive value (i.e. <= 0).
bool signedNonPositive(const NTL::ZZ& plaintext, const ks05::PubKey& pk);

} // namespace mpsi::beh21
