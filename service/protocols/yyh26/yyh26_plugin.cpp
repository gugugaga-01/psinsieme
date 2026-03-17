#include "core/protocol.h"
#include "protocols/yyh26/protocol/tt_mpsi.h"

#include <iostream>
#include <string>

namespace mpsi {

class Yyh26Protocol : public PsiProtocol {
public:
    std::string name() const override { return "yyh26_tt_mpsi"; }

    // YYH26 does not need dealer keys; setup is a no-op.
    bool setup(const PartyConfig& config) override {
        config_ = config;
        return true;
    }

    std::vector<std::string> run(const ProtocolContext& ctx,
                                  const std::vector<std::string>& elements) override {
        yyh26::TTMpsiConfig cfg;
        cfg.numParties = config_.num_parties;
        cfg.threshold = ctx.threshold;
        cfg.partyID = config_.party_id;

        // Derive TCP ports from inter-party addresses.
        cfg.tcpBasePort = 11000 + static_cast<uint32_t>(ctx.leader_id * 1000);

        // Map party IDs to hostnames from inter-party addresses.
        for (uint64_t i = 0; i < config_.party_addresses.size(); i++) {
            auto addr = config_.party_addresses[i];
            auto colon = addr.rfind(':');
            cfg.partyHostnames[i] = (colon != std::string::npos)
                ? addr.substr(0, colon) : addr;
        }

        if (ctx.is_leader) {
            yyh26::TTMpsiLeader leader;
            leader.init(cfg);
            return leader.run(elements);
        } else {
            yyh26::TTMpsiMember member;
            member.init(cfg);
            member.run(elements);
            return {};
        }
    }

private:
    PartyConfig config_;
};

REGISTER_PROTOCOL(Yyh26Protocol)

} // namespace mpsi
