#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Forward declarations for cryptoTools/libOPRF/libOLE types.
// Full includes only in the .cpp to avoid header pollution.
namespace osuCrypto {
    class BtIOService;
    class BtEndpoint;
    class Channel;
    class PRNG;
}

namespace mpsi::yyh26 {

using u64 = uint64_t;

// Protocol constants
constexpr u64 PSI_SEC_PARAM = 40;
constexpr u64 BIT_SIZE = 128;
constexpr u64 NUM_THREADS = 1;

// Configuration for YYH26 TT-MPSI protocol.
// Internal crypto channels use unencrypted TCP via BtEndpoint.
struct TTMpsiConfig {
    u64 numParties;
    u64 threshold;
    u64 partyID;

    // TCP base port for internal crypto channels.
    // Port scheme: basePort + min(i,j)*100 + max(i,j)
    uint32_t tcpBasePort = 1100;

    // Hostname for each party ID. If a party is missing, defaults to "localhost".
    std::map<u64, std::string> partyHostnames;

    std::string getHostname(u64 pid) const {
        auto it = partyHostnames.find(pid);
        return (it != partyHostnames.end()) ? it->second : "localhost";
    }
};

class TTMpsiLeader {
public:
    void init(const TTMpsiConfig& config);

    // Run the leader protocol.
    // inputs: leader's private set elements (arbitrary byte strings)
    // Returns intersection elements (matching input strings).
    std::vector<std::string> run(const std::vector<std::string>& inputs);

private:
    TTMpsiConfig config_;
};

class TTMpsiMember {
public:
    void init(const TTMpsiConfig& config);

    // Run the member protocol.
    // inputs: member's private set elements (arbitrary byte strings)
    // Members learn nothing about the intersection.
    void run(const std::vector<std::string>& inputs);

private:
    TTMpsiConfig config_;
};

} // namespace mpsi::yyh26
