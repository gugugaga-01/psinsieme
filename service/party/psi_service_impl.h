#pragma once

#include "psi_service.grpc.pb.h"
#include "core/protocol.h"
#include "core/party_config.h"

#include <grpcpp/grpcpp.h>
#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace mpsi {

// PsiService implementation: accepts client input and dispatches to
// registered protocol plugins via the ProtocolRegistry.
class PsiServiceImpl final : public PsiService::Service {
public:
    explicit PsiServiceImpl(const PartyConfig& config)
        : config_(config) {
        // Setup all registered protocols
        for (const auto& name : ProtocolRegistry::instance().availableProtocols()) {
            auto proto = ProtocolRegistry::instance().create(name);
            if (proto && proto->setup(config)) {
                protocols_[name] = std::move(proto);
                std::cerr << "[Party " << config.party_id
                          << "] Protocol '" << name << "' ready" << std::endl;
            }
        }
    }

    grpc::Status ComputeIntersection(
        grpc::ServerContext* /*context*/,
        const ComputeRequest* request,
        ComputeResponse* response) override {

        // Determine which protocol to run (per-request, with fallback to config)
        std::string protocol = request->protocol();
        if (protocol.empty())
            protocol = config_.protocol;

        // Look up protocol in registry
        auto it = protocols_.find(protocol);
        if (it == protocols_.end()) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_INVALID_PARAMS);
            std::string msg = "Unsupported protocol: " + protocol + ". Available: ";
            bool first = true;
            for (const auto& [name, _] : protocols_) {
                if (!first) msg += ", ";
                msg += name;
                first = false;
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

        // Collect elements
        std::vector<std::string> elements;
        elements.reserve(request->elements_size());
        for (const auto& elem : request->elements())
            elements.push_back(elem);

        ProtocolContext ctx{config_, is_leader, leader_id, member_ids,
                           request->threshold()};

        // Validate
        auto err = it->second->validate(ctx, elements);
        if (!err.empty()) {
            auto* status = response->mutable_status();
            status->set_code(STATUS_ERROR);
            status->set_message(err);
            return grpc::Status::OK;
        }

        try {
            auto result = it->second->run(ctx, elements);

            for (const auto& elem : result)
                response->add_intersection(elem);

            auto* status = response->mutable_status();
            status->set_code(STATUS_OK);
            if (is_leader) {
                status->set_message("Intersection computed: " +
                    std::to_string(result.size()) + " elements");
            } else {
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
    PartyConfig config_;
    std::map<std::string, std::unique_ptr<PsiProtocol>> protocols_;
};

} // namespace mpsi
