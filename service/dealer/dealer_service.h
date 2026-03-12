#pragma once

#include "dealer.grpc.pb.h"
#include "ks05_t_mpsi/crypto/paillier.h"
#include "ks05_t_mpsi/protocol/t_mpsi.h"

#include <grpcpp/grpcpp.h>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <fstream>
#include <iostream>

namespace mpsi {

// Key dealer service implementation.
//
// Generates Paillier threshold key material and distributes individual
// shares to each party.  After all parties have collected their shares,
// the dealer wipes all sensitive material (factorization, shares).
class KeyDealerImpl final : public KeyDealer::Service {
public:
    explicit KeyDealerImpl(uint64_t expected_parties)
        : expected_parties_(expected_parties) {}

    grpc::Status GetKeyShare(
        grpc::ServerContext* context,
        const KeyShareRequest* request,
        KeyShareResponse* response) override {

        std::unique_lock<std::mutex> lock(mu_);

        // When mTLS is enabled, verify the peer's certificate CN matches
        // the requested party_id.  The expected CN format is "party{id}"
        // (e.g., "party0", "party1").  This prevents a semi-honest party
        // from requesting another party's key share.
        auto auth_ctx = context->auth_context();
        auto cn_props = auth_ctx ? auth_ctx->FindPropertyValues("x509_common_name")
                                 : std::vector<grpc::string_ref>{};
        if (!cn_props.empty()) {
            std::string peer_cn(cn_props[0].begin(), cn_props[0].end());
            std::string expected_cn = "party" + std::to_string(request->party_id());
            if (peer_cn != expected_cn) {
                auto* s = response->mutable_status();
                s->set_code(STATUS_ERROR);
                s->set_message("Certificate CN '" + peer_cn +
                    "' does not match requested party_id " +
                    std::to_string(request->party_id()));
                return grpc::Status::OK;
            }
        }

        // Validate request
        if (request->party_id() >= request->num_parties()) {
            auto* s = response->mutable_status();
            s->set_code(STATUS_INVALID_PARAMS);
            s->set_message("party_id must be < num_parties");
            return grpc::Status::OK;
        }

        if (request->num_parties() > 100) {
            auto* s = response->mutable_status();
            s->set_code(STATUS_INVALID_PARAMS);
            s->set_message("num_parties must be <= 100");
            return grpc::Status::OK;
        }

        if (request->num_parties() != expected_parties_) {
            auto* s = response->mutable_status();
            s->set_code(STATUS_INVALID_PARAMS);
            s->set_message("num_parties mismatch: dealer configured for " +
                std::to_string(expected_parties_));
            return grpc::Status::OK;
        }

        // Generate keys on first request
        if (!keys_generated_) {
            generateKeys(request->num_parties());
            keys_generated_ = true;
            std::cerr << "[Dealer] Generated " << ks05::PAILLIER_KEY_BITS
                      << "-bit Paillier keys for " << expected_parties_
                      << " parties" << std::endl;
        }

        uint64_t pid = request->party_id();

        if (collected_.count(pid)) {
            auto* s = response->mutable_status();
            s->set_code(STATUS_ERROR);
            s->set_message("Party already collected its key share");
            return grpc::Status::OK;
        }

        if (pid >= secret_keys_.size()) {
            auto* s = response->mutable_status();
            s->set_code(STATUS_ERROR);
            s->set_message("Invalid party_id");
            return grpc::Status::OK;
        }

        // Serialize and send public key components
        response->set_public_key_n(serializeZZ(pub_key_.n));
        response->set_public_key_theta(serializeZZ(pub_key_.theta));
        response->set_public_key_delta(serializeZZ(pub_key_.delta));

        // Send this party's individual secret key share
        response->set_secret_key_share(serializeZZ(secret_keys_[pid].s));

        auto* s = response->mutable_status();
        s->set_code(STATUS_OK);
        s->set_message("Key share delivered for party " + std::to_string(pid));

        // Track which parties have collected their shares
        collected_.insert(pid);
        std::cerr << "[Dealer] Delivered key share to party " << pid
                  << " (" << collected_.size() << "/" << expected_parties_
                  << ")" << std::endl;

        // If all parties have collected, wipe secrets
        if (collected_.size() == expected_parties_) {
            wipeSecrets();
            all_collected_ = true;
            all_collected_cv_.notify_all();
            std::cerr << "[Dealer] All parties served. Secrets wiped."
                      << std::endl;
        }

        return grpc::Status::OK;
    }

    // Block until all parties have collected their shares.
    void waitUntilDone() {
        std::unique_lock<std::mutex> lock(mu_);
        all_collected_cv_.wait(lock, [this] { return all_collected_; });
    }

    bool allCollected() const { return all_collected_; }

private:
    void generateKeys(uint64_t n) {
        // Seed NTL's PRNG from /dev/urandom
        unsigned char entropy[32];
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (!urandom.good())
            throw std::runtime_error("Cannot open /dev/urandom");
        urandom.read(reinterpret_cast<char*>(entropy), sizeof(entropy));
        NTL::SetSeed(NTL::ZZFromBytes(entropy, sizeof(entropy)));

        ks05::distributedKeyGen(ks05::PAILLIER_KEY_BITS, n,
                                pub_key_, secret_keys_);
    }

    void wipeSecrets() {
        for (auto& sk : secret_keys_)
            NTL::clear(sk.s);
        secret_keys_.clear();
    }

    static std::string serializeZZ(const NTL::ZZ& val) {
        long numBytes = NTL::NumBytes(val);
        std::vector<unsigned char> buf(numBytes);
        NTL::BytesFromZZ(buf.data(), val, numBytes);
        return std::string(reinterpret_cast<const char*>(buf.data()), numBytes);
    }

    uint64_t expected_parties_;
    std::mutex mu_;
    std::condition_variable all_collected_cv_;
    bool keys_generated_ = false;
    bool all_collected_ = false;
    std::set<uint64_t> collected_;

    ks05::PubKey pub_key_;
    std::vector<ks05::PrivKey> secret_keys_;
};

} // namespace mpsi
