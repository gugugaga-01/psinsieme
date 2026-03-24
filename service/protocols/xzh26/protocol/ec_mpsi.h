#pragma once

#include <vector>
#include <cstdint>
#include "core/transport/channel.h"
#include "protocols/xzh26/crypto/point.h"
#include "protocols/xzh26/crypto/common.h"

namespace mpsi::xzh26 {

using Element = uint32_t;

struct EcMpsiBase {
    uint64_t mNumberOfParties = 0;
    uint64_t mThreshold = 0;
    uint64_t mPartyID = 0;
    uint64_t mSetSize = 0;
    bool mDebug = false;

    void init(uint64_t numberOfParties,
              uint64_t threshold,
              uint64_t partyID,
              uint64_t setSize,
              bool debug);

    virtual ~EcMpsiBase() = default;
};

class EcMpsiLeader : public EcMpsiBase {
public:
    // Run the leader side of the protocol.
    // channels[i] = connection to member i (0..n-2)
    // Returns elements in the intersection.
    std::vector<Element> run(const std::vector<Element>& inputs,
                              std::vector<mpsi::Channel*>& channels);
};

class EcMpsiMember : public EcMpsiBase {
public:
    // Run the member side of the protocol.
    // channels[0] = connection to leader
    void run(const std::vector<Element>& inputs,
             std::vector<mpsi::Channel*>& channels);
};

} // namespace mpsi::xzh26
