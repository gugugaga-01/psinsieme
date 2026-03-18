#include "core/protocol.h"
#include "core/transport/party_server.h"
#include "core/transport/grpc_channel.h"
#include "protocols/beh21/protocol/ot_mpsi.h"
#include "protocols/beh21/crypto/bloom_filter.h"
#include "dealer.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace mpsi {

class Beh21Protocol : public PsiProtocol {
public:
    std::string name() const override { return "beh21_ot_mpsi"; }

    bool setup(const PartyConfig& config) override {
        config_ = config;
        if (config.dealer_addr.empty()) {
            std::cerr << "[Party " << config.party_id
                      << "] No dealer configured. BEH21 protocol unavailable."
                      << std::endl;
            return false;
        }

        TlsConfig dealer_tls;
        if (config.inter_party_tls.enable_mtls)
            dealer_tls = config.inter_party_tls;

        std::cerr << "[Party " << config.party_id
                  << "] BEH21: Connecting to dealer at " << config.dealer_addr
                  << (dealer_tls.enable_mtls ? " (mTLS)" : " (insecure)")
                  << "..." << std::endl;

        if (!fetchKeyShareFromDealer(config.dealer_addr, config.party_id,
                                     config.num_parties, dealer_tls)) {
            std::cerr << "[Party " << config.party_id
                      << "] BEH21: Failed to get key share from dealer" << std::endl;
            return false;
        }

        has_keys_ = true;
        return true;
    }

    std::string validate(const ProtocolContext& ctx,
                          const std::vector<std::string>& elements) override {
        (void)elements;
        if (!has_keys_)
            return "No keys available. Start a dealer first.";
        return "";
    }

    std::vector<std::string> run(const ProtocolContext& ctx,
                                  const std::vector<std::string>& elements) override {
        // Convert string elements to Element (16-byte hash)
        std::vector<beh21::Element> inputs;
        std::unordered_map<std::string, std::string> hashToString;
        inputs.reserve(elements.size());

        for (const auto& elem : elements) {
            beh21::Element el{};
            MurmurHash3_x86_128(elem.data(), static_cast<int>(elem.size()), 0, el.data());
            inputs.push_back(el);
            // Store reverse mapping using the element bytes as key
            std::string hashKey(reinterpret_cast<const char*>(el.data()), 16);
            hashToString[hashKey] = elem;
        }

        uint64_t setSize = inputs.size();

        if (ctx.is_leader) {
            return runLeader(inputs, hashToString, ctx.threshold, setSize, ctx.member_ids);
        } else {
            runMember(inputs, ctx.threshold, setSize, ctx.leader_id, ctx.member_ids);
            return {};
        }
    }

private:
    bool fetchKeyShareFromDealer(const std::string& dealer_addr,
                                  uint64_t party_id,
                                  uint64_t num_parties,
                                  const TlsConfig& dealer_tls) {
        grpc::ChannelArguments args;
        args.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);

        std::shared_ptr<grpc::ChannelCredentials> creds;
        if (!dealer_tls.ca_cert.empty())
            creds = makeClientCredentials(dealer_tls);
        else
            creds = grpc::InsecureChannelCredentials();
        auto channel = grpc::CreateCustomChannel(dealer_addr, creds, args);

        auto stub = KeyDealer::NewStub(channel);

        KeyShareRequest req;
        req.set_party_id(party_id);
        req.set_num_parties(num_parties);
        req.set_protocol("beh21_ot_mpsi");

        KeyShareResponse resp;
        grpc::ClientContext grpc_ctx;
        grpc_ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(120));

        auto status = stub->GetKeyShare(&grpc_ctx, req, &resp);
        if (!status.ok()) {
            std::cerr << "[Party " << party_id << "] Dealer RPC failed: "
                      << status.error_message() << std::endl;
            return false;
        }

        if (resp.status().code() != STATUS_OK) {
            std::cerr << "[Party " << party_id << "] Dealer error: "
                      << resp.status().message() << std::endl;
            return false;
        }

        pub_key_.n = NTL::ZZFromBytes(
            reinterpret_cast<const unsigned char*>(resp.public_key_n().data()),
            resp.public_key_n().size());
        pub_key_.n2 = pub_key_.n * pub_key_.n;
        pub_key_.g = pub_key_.n + 1;
        pub_key_.theta = NTL::ZZFromBytes(
            reinterpret_cast<const unsigned char*>(resp.public_key_theta().data()),
            resp.public_key_theta().size());
        pub_key_.delta = NTL::ZZFromBytes(
            reinterpret_cast<const unsigned char*>(resp.public_key_delta().data()),
            resp.public_key_delta().size());

        priv_key_.s = NTL::ZZFromBytes(
            reinterpret_cast<const unsigned char*>(resp.secret_key_share().data()),
            resp.secret_key_share().size());

        std::cerr << "[Party " << party_id << "] BEH21: Received key share from dealer"
                  << std::endl;
        return true;
    }

    std::vector<std::string> runLeader(const std::vector<beh21::Element>& inputs,
                                       const std::unordered_map<std::string, std::string>& hashToString,
                                       uint64_t threshold,
                                       uint64_t setSize,
                                       const std::vector<uint64_t>& member_ids) {
        std::vector<std::unique_ptr<GrpcIdentifiedClientChannel>> client_channels;
        std::vector<Channel*> channels;

        auto creds = makeClientCredentials(config_.inter_party_tls);
        for (uint64_t mid : member_ids) {
            client_channels.push_back(std::make_unique<GrpcIdentifiedClientChannel>(
                config_.party_addresses[mid], creds, config_.party_id));
            channels.push_back(client_channels.back().get());
        }

        beh21::OtMpsiLeader leader;
        leader.init(config_.num_parties, threshold, config_.party_id,
                    setSize, setSize, true);
        leader.setKeys(pub_key_, priv_key_);
        std::vector<beh21::Element> intersection = leader.run(inputs, channels);

        for (auto& ch : client_channels)
            ch->close();

        // Map intersection elements back to original strings
        std::vector<std::string> result;
        for (const auto& elem : intersection) {
            std::string hashKey(reinterpret_cast<const char*>(elem.data()), 16);
            auto it = hashToString.find(hashKey);
            if (it != hashToString.end())
                result.push_back(it->second);
        }
        return result;
    }

    void runMember(const std::vector<beh21::Element>& inputs,
                   uint64_t threshold,
                   uint64_t setSize,
                   uint64_t leader_id,
                   const std::vector<uint64_t>& member_ids) {
        PartyServer inter_server(config_.party_addresses[config_.party_id],
                                  config_.inter_party_tls);

        int my_chain_pos = -1;
        for (size_t i = 0; i < member_ids.size(); i++) {
            if (member_ids[i] == config_.party_id) {
                my_chain_pos = static_cast<int>(i);
                break;
            }
        }

        std::atomic<bool> done{false};
        std::mutex mu;
        std::condition_variable cv;

        GrpcServerChannel* ch_from_leader = nullptr;
        GrpcServerChannel* ch_from_prev = nullptr;
        std::atomic<int> incoming_count{0};
        int expected_incoming = 1;

        bool has_prev = (my_chain_pos > 0);
        if (has_prev)
            expected_incoming = 2;

        inter_server.service().expectParty(leader_id, [&](GrpcServerChannel* ch) {
            ch_from_leader = ch;
            incoming_count++;
            cv.notify_all();
            std::unique_lock<std::mutex> lk(mu);
            cv.wait(lk, [&] { return done.load(); });
        });

        if (has_prev) {
            uint64_t prev_party_id = member_ids[my_chain_pos - 1];
            inter_server.service().expectParty(prev_party_id, [&](GrpcServerChannel* ch) {
                ch_from_prev = ch;
                incoming_count++;
                cv.notify_all();
                std::unique_lock<std::mutex> lk(mu);
                cv.wait(lk, [&] { return done.load(); });
            });
        }

        inter_server.start();

        {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait(lk, [&] { return incoming_count.load() >= expected_incoming; });
        }

        bool is_last_member = (my_chain_pos == static_cast<int>(member_ids.size()) - 1);
        std::unique_ptr<GrpcIdentifiedClientChannel> ch_to_next;

        if (!is_last_member) {
            uint64_t next_party_id = member_ids[my_chain_pos + 1];
            auto creds = makeClientCredentials(config_.inter_party_tls);
            ch_to_next = std::make_unique<GrpcIdentifiedClientChannel>(
                config_.party_addresses[next_party_id], creds, config_.party_id);
        }

        std::vector<Channel*> channels = {
            ch_from_leader,
            ch_from_prev,
            is_last_member ? nullptr : ch_to_next.get(),
        };

        beh21::OtMpsiMember member;
        member.init(config_.num_parties, threshold, config_.party_id,
                    setSize, setSize, true);
        member.setKeys(pub_key_, priv_key_);
        member.run(inputs, channels);

        if (ch_to_next)
            ch_to_next->close();

        done = true;
        cv.notify_all();

        inter_server.shutdown();
    }

    PartyConfig config_;
    ks05::PubKey pub_key_;
    ks05::PrivKey priv_key_;
    bool has_keys_ = false;
};

REGISTER_PROTOCOL(Beh21Protocol)

} // namespace mpsi
