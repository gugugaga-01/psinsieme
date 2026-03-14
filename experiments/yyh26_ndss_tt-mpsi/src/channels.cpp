#include "channels.h"
#include <memory>

namespace yyh26 {

ChannelSet::ChannelSet(u64 myIdx_, u64 nParties_, u64 numThreads_)
    : myIdx(myIdx_), nParties(nParties_), numThreads(numThreads_), name("psi")
{
}

void ChannelSet::setupOPPRF() {
    u64 leaderIdx = nParties - 1;
    u64 x = (myIdx == leaderIdx) ? nParties - 1 : 1;
    opprfIos = std::make_unique<osuCrypto::BtIOService>(x);

    opprfEp.resize(nParties);
    for (u64 i = 0; i < nParties; ++i) {
        opprfEp[i] = std::make_unique<osuCrypto::BtEndpoint>();
        if (i < myIdx) {
            u32 port = opprfPort(i, myIdx);
            opprfEp[i]->start(*opprfIos, "localhost", port, false, name);
        } else if (i > myIdx) {
            u32 port = opprfPort(myIdx, i);
            opprfEp[i]->start(*opprfIos, "localhost", port, true, name);
        }
    }

    opprfChls.resize(nParties);
    for (u64 i = 0; i < nParties; ++i) {
        if (i != myIdx) {
            opprfChls[i].resize(numThreads);
            for (u64 j = 0; j < numThreads; ++j) {
                opprfChls[i][j] = &opprfEp[i]->addChannel(name, name);
            }
        }
    }
}

void ChannelSet::teardownOPPRF() {
    for (u64 i = 0; i < nParties; ++i) {
        if (i != myIdx) {
            for (u64 j = 0; j < numThreads; ++j) {
                opprfChls[i][j]->close();
            }
        }
    }
    for (u64 i = 0; i < nParties; ++i) {
        if (i != myIdx)
            opprfEp[i]->stop();
    }
    opprfIos->stop();
    opprfChls.clear();
    opprfEp.clear();
    opprfIos.reset();
}

void ChannelSet::setupOLE() {
    oleIos = std::make_unique<osuCryptoNew::IOService>();

    oleEp.resize(nParties);
    for (u64 i = 0; i < nParties; ++i) {
        if (i < myIdx) {
            u32 port = olePort(i, myIdx);
            oleEp[i].start(*oleIos, "localhost", port,
                           osuCryptoNew::SessionMode::Client, name);
        } else if (i > myIdx) {
            u32 port = olePort(myIdx, i);
            oleEp[i].start(*oleIos, "localhost", port,
                           osuCryptoNew::SessionMode::Server, name);
        }
    }

    oleChls.resize(nParties);
    for (u64 i = 0; i < nParties; ++i) {
        if (i != myIdx) {
            oleChls[i].resize(numThreads);
            for (u64 j = 0; j < numThreads; ++j) {
                oleChls[i][j] = oleEp[i].addChannel(name, name);
            }
        }
    }
}

void ChannelSet::teardownOLE() {
    // Stop sessions first (matching original code pattern)
    for (u64 i = 0; i < nParties; ++i) {
        if (i != myIdx)
            oleEp[i].stop();
    }
    // Don't call oleIos->stop() — it hangs waiting for async work.
    // Let the destructor handle cleanup when oleIos is reset.
    oleChls.clear();
    oleEp.clear();
    oleIos.reset();
}

void syncParties(u64 myIdx, std::vector<std::vector<osuCrypto::Channel*>>& chls) {
    u64 nParties = chls.size();
    std::vector<u8> dummy(nParties);
    std::vector<u8> recvDummy(nParties);

    for (u64 i = 0; i < nParties; ++i) {
        if (i != myIdx) {
            dummy[i] = static_cast<u8>(myIdx * 10 + i);
        }
    }
    for (u64 i = 0; i < nParties; ++i) {
        if (i < myIdx) {
            chls[i][0]->asyncSendCopy(&dummy[i], 1);
        }
    }
    for (u64 i = 0; i < nParties; ++i) {
        if (i < myIdx) {
            chls[i][0]->recv(&recvDummy[i], 1);
        }
    }
    for (u64 i = 0; i < nParties; ++i) {
        if (i > myIdx) {
            chls[i][0]->recv(&recvDummy[i], 1);
        }
    }
    for (u64 i = 0; i < nParties; ++i) {
        if (i > myIdx) {
            chls[i][0]->asyncSendCopy(&dummy[i], 1);
        }
    }
}

} // namespace yyh26
