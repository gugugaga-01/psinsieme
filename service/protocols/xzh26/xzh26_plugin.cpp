#include "core/protocol.h"
#include "core/transport/party_server.h"
#include "core/transport/grpc_channel.h"
#include "protocols/xzh26/protocol/ec_mpsi.h"
#include "protocols/xzh26/crypto/murmurhash3.h"

#include <grpcpp/grpcpp.h>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace mpsi {

class Xzh26Protocol : public PsiProtocol {
public:
    std::string name() const override { return "xzh26_ec_mpsi"; }

    bool setup(const PartyConfig& config) override {
        config_ = config;
        // No dealer needed — DKG is part of the protocol itself
        std::cerr << "[Party " << config.party_id
                  << "] XZH26: Ready (no dealer required)" << std::endl;
        return true;
    }

    std::string validate(const ProtocolContext& ctx,
                          const std::vector<std::string>& elements) override {
        (void)elements;
        (void)ctx;
        return "";
    }

    std::vector<std::string> run(const ProtocolContext& ctx,
                                  const std::vector<std::string>& elements) override {
        // Convert string elements to uint32 via MurmurHash
        std::vector<xzh26::Element> inputs;
        std::unordered_map<uint32_t, std::string> elemToString;
        inputs.reserve(elements.size());

        for (const auto& elem : elements) {
            uint64_t hash[2];
            MurmurHash3_x86_128(elem.data(), static_cast<int>(elem.size()), 0, hash);
            uint32_t val = static_cast<uint32_t>(hash[0]);
            inputs.push_back(val);
            elemToString[val] = elem;
        }

        uint64_t setSize = inputs.size();

        if (ctx.is_leader) {
            return runLeader(inputs, elemToString, ctx.threshold, setSize, ctx.member_ids);
        } else {
            runMember(inputs, ctx.threshold, setSize, ctx.leader_id, ctx.member_ids);
            return {};
        }
    }

private:
    std::vector<std::string> runLeader(
        const std::vector<xzh26::Element>& inputs,
        const std::unordered_map<uint32_t, std::string>& elemToString,
        uint64_t threshold,
        uint64_t setSize,
        const std::vector<uint64_t>& member_ids)
    {
        std::vector<std::unique_ptr<GrpcIdentifiedClientChannel>> client_channels;
        std::vector<Channel*> channels;

        auto creds = makeClientCredentials(config_.inter_party_tls);
        for (uint64_t mid : member_ids) {
            client_channels.push_back(std::make_unique<GrpcIdentifiedClientChannel>(
                config_.party_addresses[mid], creds, config_.party_id));
            channels.push_back(client_channels.back().get());
        }

        xzh26::EcMpsiLeader leader;
        leader.init(config_.num_parties, threshold, config_.party_id, setSize, true);
        std::vector<xzh26::Element> intersection = leader.run(inputs, channels);

        for (auto& ch : client_channels)
            ch->close();

        // Map intersection elements back to original strings
        std::vector<std::string> result;
        for (const auto& elem : intersection) {
            auto it = elemToString.find(elem);
            if (it != elemToString.end())
                result.push_back(it->second);
        }
        return result;
    }

    void runMember(
        const std::vector<xzh26::Element>& inputs,
        uint64_t threshold,
        uint64_t setSize,
        uint64_t leader_id,
        const std::vector<uint64_t>& member_ids)
    {
        PartyServer inter_server(config_.party_addresses[config_.party_id],
                                  config_.inter_party_tls);

        std::atomic<bool> done{false};
        std::mutex mu;
        std::condition_variable cv;

        GrpcServerChannel* ch_from_leader = nullptr;

        inter_server.service().expectParty(leader_id, [&](GrpcServerChannel* ch) {
            ch_from_leader = ch;
            cv.notify_all();
            std::unique_lock<std::mutex> lk(mu);
            cv.wait(lk, [&] { return done.load(); });
        });

        inter_server.start();

        {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait(lk, [&] { return ch_from_leader != nullptr; });
        }

        // Star topology: member only talks to leader
        std::vector<Channel*> channels = { ch_from_leader };

        xzh26::EcMpsiMember member;
        member.init(config_.num_parties, threshold, config_.party_id, setSize, true);
        member.run(inputs, channels);

        done = true;
        cv.notify_all();

        inter_server.shutdown();
    }

    PartyConfig config_;
};

REGISTER_PROTOCOL(Xzh26Protocol)

} // namespace mpsi
