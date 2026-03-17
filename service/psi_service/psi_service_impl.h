#pragma once

#include "psi_service.grpc.pb.h"
#include "dealer.grpc.pb.h"
#include "core/transport/party_server.h"
#include "core/transport/grpc_channel.h"
#include "protocols/ks05/protocol/t_mpsi.h"
#include "protocols/ks05/protocol/logger.h"

#ifdef MPSI_HAS_YYH26
#include "protocols/yyh26/protocol/tt_mpsi.h"
#endif

#include <grpcpp/grpcpp.h>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <functional>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

namespace mpsi {

// Configuration for a single party in the PSI deployment.
struct PartyConfig {
    uint64_t party_id;          // This party's ID (0-indexed, from sorted addresses)
    uint64_t num_parties;       // Total number of parties

    // Addresses of all parties' inter-party gRPC servers (index = party ID)
    std::vector<std::string> party_addresses;

    // TLS config for inter-party communication
    TlsConfig inter_party_tls;

    // Address for this party's client-facing PsiService
    std::string client_listen_addr;
    TlsConfig client_tls;

    // Dealer address (empty = no dealer; KS05 protocol unavailable)
    std::string dealer_addr;

    // Default protocol (clients can override per-request)
    std::string protocol = "ks05_t_mpsi";
};

// Fetch key share from the dealer service.
// Returns true on success, false on failure.
// If dealer_tls has certificates set, uses mTLS; otherwise insecure.
inline bool fetchKeyShareFromDealer(
    const std::string& dealer_addr,
    uint64_t party_id,
    uint64_t num_parties,
    ks05::PubKey& pk,
    ks05::PrivKey& sk,
    const TlsConfig& dealer_tls = {})
{
    // Bypass HTTP proxy for dealer connections
    grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);

    std::shared_ptr<grpc::ChannelCredentials> creds;
    if (!dealer_tls.ca_cert.empty()) {
        creds = makeClientCredentials(dealer_tls);
    } else {
        creds = grpc::InsecureChannelCredentials();
    }
    auto channel = grpc::CreateCustomChannel(dealer_addr, creds, args);

    auto stub = KeyDealer::NewStub(channel);

    KeyShareRequest req;
    req.set_party_id(party_id);
    req.set_num_parties(num_parties);
    req.set_protocol("ks05_t_mpsi");

    KeyShareResponse resp;
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(120));

    auto status = stub->GetKeyShare(&ctx, req, &resp);
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

    // Deserialize key components
    pk.n = NTL::ZZFromBytes(
        reinterpret_cast<const unsigned char*>(resp.public_key_n().data()),
        resp.public_key_n().size());
    pk.n2 = pk.n * pk.n;
    pk.g = pk.n + 1;
    pk.theta = NTL::ZZFromBytes(
        reinterpret_cast<const unsigned char*>(resp.public_key_theta().data()),
        resp.public_key_theta().size());
    pk.delta = NTL::ZZFromBytes(
        reinterpret_cast<const unsigned char*>(resp.public_key_delta().data()),
        resp.public_key_delta().size());

    sk.s = NTL::ZZFromBytes(
        reinterpret_cast<const unsigned char*>(resp.secret_key_share().data()),
        resp.secret_key_share().size());

    std::cerr << "[Party " << party_id << "] Received key share from dealer"
              << std::endl;
    return true;
}

// PsiService implementation: accepts client input and runs the protocol.
class PsiServiceImpl final : public PsiService::Service {
public:
    explicit PsiServiceImpl(const PartyConfig& config)
        : config_(config) {}

    // Set pre-distributed keys (from dealer).
    void setKeys(const ks05::PubKey& pk, const ks05::PrivKey& sk) {
        pub_key_ = pk;
        priv_key_ = sk;
        has_keys_ = true;
    }

    grpc::Status ComputeIntersection(
        grpc::ServerContext* /*context*/,
        const ComputeRequest* request,
        ComputeResponse* response) override {

        ks05::Logger::getInstance().setEnabled(true);

        // Determine which protocol to run (per-request, with fallback to config)
        std::string protocol = request->protocol();
        if (protocol.empty())
            protocol = config_.protocol;

        // Validate protocol name
        std::vector<std::string> supported = {"ks05_t_mpsi"};
#ifdef MPSI_HAS_YYH26
        supported.push_back("yyh26_tt_mpsi");
#endif
        if (std::find(supported.begin(), supported.end(), protocol) == supported.end()) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            std::string msg = "Unsupported protocol: " + protocol + ". Supported: ";
            for (size_t i = 0; i < supported.size(); i++) {
                if (i > 0) msg += ", ";
                msg += supported[i];
            }
            status->set_message(msg);
            return grpc::Status::OK;
        }

        if (request->elements_size() == 0 || request->elements_size() > 100000) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            status->set_message("elements size must be between 1 and 100000");
            return grpc::Status::OK;
        }

        if (request->num_parties() != config_.num_parties) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            status->set_message("num_parties mismatch: expected " +
                std::to_string(config_.num_parties));
            return grpc::Status::OK;
        }

        if (request->threshold() < 2 || request->threshold() > request->num_parties()) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            status->set_message("threshold must be >= 2 and <= num_parties");
            return grpc::Status::OK;
        }

        if (request->role() == DEALER) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            status->set_message("Dealer role is not supported via ComputeIntersection. "
                                "Use psi_dealer binary instead.");
            return grpc::Status::OK;
        }

        if (protocol == "ks05_t_mpsi" && !has_keys_) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_ERROR);
            status->set_message("No keys available. Start a dealer first.");
            return grpc::Status::OK;
        }

        bool is_leader = (request->role() == LEADER);

        // Determine leader's party_id from leader_address
        std::string leader_addr = request->leader_address();
        if (leader_addr.empty()) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            status->set_message("leader_address is required");
            return grpc::Status::OK;
        }

        auto leader_it = std::find(config_.party_addresses.begin(),
                                    config_.party_addresses.end(), leader_addr);
        if (leader_it == config_.party_addresses.end()) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            status->set_message("leader_address not found in party addresses");
            return grpc::Status::OK;
        }
        uint64_t leader_id = std::distance(config_.party_addresses.begin(), leader_it);

        // Build member chain: all party IDs except the leader, in order
        std::vector<uint64_t> member_ids;
        for (uint64_t i = 0; i < config_.num_parties; i++) {
            if (i != leader_id)
                member_ids.push_back(i);
        }

        // Convert string elements to ZZ
        std::vector<NTL::ZZ> inputs;
        inputs.reserve(request->elements_size());
        for (const auto& elem : request->elements()) {
            NTL::ZZ val = NTL::ZZFromBytes(
                reinterpret_cast<const unsigned char*>(elem.data()), elem.size());
            inputs.push_back(val);
        }

        uint64_t threshold = request->threshold();
        uint64_t setSize = inputs.size();

        try {
#ifdef MPSI_HAS_YYH26
            if (protocol == "yyh26_tt_mpsi") {
                // Convert ZZ inputs to string elements for yyh26
                std::vector<std::string> str_elements;
                str_elements.reserve(request->elements_size());
                for (const auto& elem : request->elements())
                    str_elements.push_back(elem);

                if (is_leader) {
                    auto result = runYYH26Leader(str_elements, threshold, leader_id);

                    for (const auto& elem : result)
                        response->add_intersection(elem);

                    auto* status = response->mutable_status();
                    status->set_code(STATUS_OK);
                    status->set_message("Intersection computed: " +
                        std::to_string(result.size()) + " elements");
                } else {
                    runYYH26Member(str_elements, threshold, leader_id);

                    auto* status = response->mutable_status();
                    status->set_code(STATUS_OK);
                    status->set_message("Protocol completed (member, no intersection returned)");
                }
            } else
#endif
            if (is_leader) {
                auto result = runLeader(inputs, threshold, setSize, member_ids);

                for (const auto& elem : result)
                    response->add_intersection(elem);

                auto* status = response->mutable_status();
                status->set_code(STATUS_OK);
                status->set_message("Intersection computed: " +
                    std::to_string(result.size()) + " elements");
            } else {
                runMember(inputs, threshold, setSize, leader_id, member_ids);

                auto* status = response->mutable_status();
                status->set_code(STATUS_OK);
                status->set_message("Protocol completed (member, no intersection returned)");
            }
        } catch (const std::exception& e) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_ERROR);
            status->set_message(std::string("Protocol error: ") + e.what());
        }

        return grpc::Status::OK;
    }

private:
    std::vector<std::string> runLeader(const std::vector<NTL::ZZ>& inputs,
                                       uint64_t threshold,
                                       uint64_t setSize,
                                       const std::vector<uint64_t>& member_ids) {
        // Connect to all member parties (in member_ids order)
        std::vector<std::unique_ptr<GrpcIdentifiedClientChannel>> client_channels;
        std::vector<Channel*> channels;

        auto creds = makeClientCredentials(config_.inter_party_tls);
        for (uint64_t mid : member_ids) {
            client_channels.push_back(std::make_unique<GrpcIdentifiedClientChannel>(
                config_.party_addresses[mid], creds, config_.party_id));
            channels.push_back(client_channels.back().get());
        }

        // Run leader protocol with pre-distributed keys
        ks05::TMpsiLeader leader;
        leader.init(config_.num_parties, threshold, config_.party_id,
                    setSize, setSize, true);
        leader.setKeys(pub_key_, priv_key_);
        std::vector<NTL::ZZ> intersection = leader.run(inputs, channels);

        for (auto& ch : client_channels)
            ch->close();

        // Map ZZ back to original string elements
        std::vector<std::string> result;
        for (const auto& val : intersection) {
            long numBytes = NTL::NumBytes(val);
            std::vector<unsigned char> buf(numBytes);
            NTL::BytesFromZZ(buf.data(), val, numBytes);
            result.emplace_back(reinterpret_cast<const char*>(buf.data()), numBytes);
        }
        return result;
    }

    void runMember(const std::vector<NTL::ZZ>& inputs,
                   uint64_t threshold,
                   uint64_t setSize,
                   uint64_t leader_id,
                   const std::vector<uint64_t>& member_ids) {
        PartyServer inter_server(config_.party_addresses[config_.party_id],
                                  config_.inter_party_tls);

        // Find my position in the member chain
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

        // Run member protocol with pre-distributed keys
        ks05::TMpsiMember member;
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

#ifdef MPSI_HAS_YYH26
    std::vector<std::string> runYYH26Leader(const std::vector<std::string>& inputs,
                                             uint64_t threshold,
                                             uint64_t leader_id) {
        yyh26::TTMpsiConfig cfg;
        cfg.numParties = config_.num_parties;
        cfg.threshold = threshold;
        cfg.partyID = config_.party_id;

        // Derive TCP ports from inter-party addresses.
        // Use a base port offset from the party config to avoid collisions.
        cfg.tcpBasePort = 11000 + static_cast<uint32_t>(leader_id * 1000);

        // Map party IDs to hostnames from inter-party addresses.
        for (uint64_t i = 0; i < config_.party_addresses.size(); i++) {
            auto addr = config_.party_addresses[i];
            auto colon = addr.rfind(':');
            cfg.partyHostnames[i] = (colon != std::string::npos)
                ? addr.substr(0, colon) : addr;
        }

        yyh26::TTMpsiLeader leader;
        leader.init(cfg);
        return leader.run(inputs);
    }

    void runYYH26Member(const std::vector<std::string>& inputs,
                         uint64_t threshold,
                         uint64_t leader_id) {
        yyh26::TTMpsiConfig cfg;
        cfg.numParties = config_.num_parties;
        cfg.threshold = threshold;
        cfg.partyID = config_.party_id;
        cfg.tcpBasePort = 11000 + static_cast<uint32_t>(leader_id * 1000);

        for (uint64_t i = 0; i < config_.party_addresses.size(); i++) {
            auto addr = config_.party_addresses[i];
            auto colon = addr.rfind(':');
            cfg.partyHostnames[i] = (colon != std::string::npos)
                ? addr.substr(0, colon) : addr;
        }

        yyh26::TTMpsiMember member;
        member.init(cfg);
        member.run(inputs);
    }
#endif

    PartyConfig config_;
    ks05::PubKey pub_key_;
    ks05::PrivKey priv_key_;
    bool has_keys_ = false;
};

} // namespace mpsi
