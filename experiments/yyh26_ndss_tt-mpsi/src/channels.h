#pragma once
#include "config.h"
#include "types.h"
#include "Network/BtEndpoint.h"
#include "Network/BtChannel.h"
#include "Network/BtIOService.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <vector>
#include <string>
#include <memory>

namespace yyh26 {

// Manages both OPPRF channels (osuCrypto::BtEndpoint) and OLE channels
// (osuCryptoNew::Session) on SEPARATE port ranges.
// OPPRF channels stay open for the entire protocol.
// OLE channels are opened only for Phase 2 and closed after.
class ChannelSet {
public:
    u64 myIdx;
    u64 nParties;
    u64 numThreads;
    std::string name;

    // ── OPPRF channels (osuCrypto namespace) ──
    std::unique_ptr<osuCrypto::BtIOService> opprfIos;
    std::vector<std::unique_ptr<osuCrypto::BtEndpoint>> opprfEp;
    std::vector<std::vector<osuCrypto::Channel*>> opprfChls;

    // ── OLE channels (osuCryptoNew namespace) ──
    std::unique_ptr<osuCryptoNew::IOService> oleIos;
    std::vector<osuCryptoNew::Session> oleEp;
    std::vector<std::vector<osuCryptoNew::Channel>> oleChls;

    ChannelSet(u64 myIdx, u64 nParties, u64 numThreads);

    // Open BtEndpoint channels for OPPRF (kept open whole protocol)
    void setupOPPRF();
    void teardownOPPRF();

    // Open Session channels for OLE phase (separate port range)
    void setupOLE();
    void teardownOLE();

private:
    u32 opprfPort(u64 smaller, u64 larger) const {
        return CHANNEL_BASE_PORT + static_cast<u32>(smaller) * 100 + static_cast<u32>(larger);
    }
    u32 olePort(u64 smaller, u64 larger) const {
        return OLE_BASE_PORT + static_cast<u32>(smaller) * 100 + static_cast<u32>(larger);
    }
};

// Synchronize all parties via a dummy send/recv
void syncParties(u64 myIdx, std::vector<std::vector<osuCrypto::Channel*>>& chls);

} // namespace yyh26
