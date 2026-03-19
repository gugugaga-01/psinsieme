#pragma once

#include "grpc_channel.h"
#include "core/tls/tls_config.h"
#include "ks05_party.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <functional>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <map>
#include <string>

namespace mpsi {

// gRPC service that identifies connecting parties by a handshake.
// Protocol: client sends a ChannelMessage with value=partyID as the first message.
// The server routes the connection to the appropriate handler based on partyID.
class PartyServiceImpl final : public ks05::Ks05PartyService::Service {
public:
    // Register a handler for a specific party ID.
    // When party `partyId` connects, its handler will be called.
    void expectParty(uint64_t partyId, std::function<void(GrpcServerChannel*)> handler) {
        std::lock_guard<std::mutex> lock(mu_);
        handlers_[partyId] = std::move(handler);
    }

    grpc::Status ProtocolChannel(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<ks05::ChannelMessage, ks05::ChannelMessage>* stream) override {

        // Handshake: read party ID from first message
        ks05::ChannelMessage handshake;
        if (!stream->Read(&handshake)) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "No handshake message");
        }
        uint64_t partyId = handshake.value();

        // CN verification: in mTLS mode the server requests client certs,
        // so cn_props will contain the peer's CN.  In TLS-only or insecure
        // mode no client cert is requested, so cn_props is empty and this
        // block is skipped.
        auto auth_ctx = context->auth_context();
        auto cn_props = auth_ctx ? auth_ctx->FindPropertyValues("x509_common_name")
                                 : std::vector<grpc::string_ref>{};
        if (!cn_props.empty()) {
            std::string peer_cn(cn_props[0].begin(), cn_props[0].end());
            std::string expected_cn = "party" + std::to_string(partyId);
            if (peer_cn != expected_cn) {
                return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                    "Certificate CN '" + peer_cn +
                    "' does not match claimed party_id " + std::to_string(partyId));
            }
        }

        std::function<void(GrpcServerChannel*)> handler;
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto it = handlers_.find(partyId);
            if (it == handlers_.end()) {
                return grpc::Status(grpc::StatusCode::NOT_FOUND,
                    "No handler for party " + std::to_string(partyId));
            }
            handler = std::move(it->second);
            handlers_.erase(it);
        }

        GrpcServerChannel channel(stream);
        handler(&channel);

        return grpc::Status::OK;
    }

private:
    std::mutex mu_;
    std::map<uint64_t, std::function<void(GrpcServerChannel*)>> handlers_;
};

// Create a gRPC channel with proxy bypassed (avoids http_proxy interference).
inline std::shared_ptr<grpc::Channel> createGrpcChannel(
    const std::string& target,
    const std::shared_ptr<grpc::ChannelCredentials>& creds) {
    grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);
    return grpc::CreateCustomChannel(target, creds, args);
}

// Client channel that sends a handshake with the caller's party ID.
class GrpcIdentifiedClientChannel : public Channel {
public:
    GrpcIdentifiedClientChannel(const std::string& target,
                                 const std::shared_ptr<grpc::ChannelCredentials>& creds,
                                 uint64_t myPartyId)
        : inner_(createGrpcChannel(target, creds)) {
        // Send handshake
        inner_.sendU64(myPartyId);
    }

    void sendBytes(const std::string& data) override { inner_.sendBytes(data); }
    std::string recvBytes() override { return inner_.recvBytes(); }
    void sendU64(uint64_t value) override { inner_.sendU64(value); }
    uint64_t recvU64() override { return inner_.recvU64(); }
    void flush() override { inner_.flush(); }
    void close() override { inner_.close(); }

private:
    GrpcClientChannel inner_;
};

// PartyServer wraps a gRPC server for a single party.
class PartyServer {
public:
    PartyServer(const std::string& listen_addr, const TlsConfig& tls = {})
        : listen_addr_(listen_addr), tls_(tls) {}

    PartyServiceImpl& service() { return service_; }

    void start() {
        grpc::ServerBuilder builder;
        builder.AddListeningPort(listen_addr_, makeServerCredentials(tls_));
        builder.RegisterService(&service_);
        server_ = builder.BuildAndStart();
    }

    void wait() {
        if (server_) server_->Wait();
    }

    void shutdown() {
        if (server_) server_->Shutdown();
    }

private:
    std::string listen_addr_;
    TlsConfig tls_;
    PartyServiceImpl service_;
    std::unique_ptr<grpc::Server> server_;
};

} // namespace mpsi
