#pragma once

#include "channel.h"
#include "ks05_party.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <memory>
#include <mutex>

namespace mpsi {

// GrpcChannel wraps a gRPC bidirectional stream (ProtocolChannel RPC)
// behind the abstract Channel interface.
//
// Two usage patterns:
//   1. Server-side: constructed from a ServerReaderWriter provided by gRPC
//   2. Client-side: constructed by connecting to a remote party's gRPC server

class GrpcServerChannel : public Channel {
public:
    using Stream = grpc::ServerReaderWriter<ks05::ChannelMessage, ks05::ChannelMessage>;

    explicit GrpcServerChannel(Stream* stream) : stream_(stream) {}

    void sendBytes(const std::string& data) override {
        ks05::ChannelMessage msg;
        msg.set_data(data);
        std::lock_guard<std::mutex> lock(write_mu_);
        if (!stream_->Write(msg))
            throw std::runtime_error("gRPC Write failed (stream closed)");
    }

    std::string recvBytes() override {
        ks05::ChannelMessage msg;
        std::lock_guard<std::mutex> lock(read_mu_);
        if (!stream_->Read(&msg))
            throw std::runtime_error("gRPC Read failed (stream closed)");
        return msg.data();
    }

    void sendU64(uint64_t value) override {
        ks05::ChannelMessage msg;
        msg.set_value(value);
        std::lock_guard<std::mutex> lock(write_mu_);
        if (!stream_->Write(msg))
            throw std::runtime_error("gRPC Write failed (stream closed)");
    }

    uint64_t recvU64() override {
        ks05::ChannelMessage msg;
        std::lock_guard<std::mutex> lock(read_mu_);
        if (!stream_->Read(&msg))
            throw std::runtime_error("gRPC Read failed (stream closed)");
        return msg.value();
    }

    void flush() override {}
    void close() override {}

private:
    Stream* stream_;
    std::mutex read_mu_;
    std::mutex write_mu_;
};

class GrpcClientChannel : public Channel {
public:
    using Stream = std::unique_ptr<grpc::ClientReaderWriter<ks05::ChannelMessage, ks05::ChannelMessage>>;

    GrpcClientChannel(std::shared_ptr<grpc::Channel> grpc_channel)
        : stub_(ks05::Ks05PartyService::NewStub(grpc_channel)) {
        stream_ = stub_->ProtocolChannel(&context_);
    }

    void sendBytes(const std::string& data) override {
        ks05::ChannelMessage msg;
        msg.set_data(data);
        std::lock_guard<std::mutex> lock(write_mu_);
        if (!stream_->Write(msg))
            throw std::runtime_error("gRPC Write failed (stream closed)");
    }

    std::string recvBytes() override {
        ks05::ChannelMessage msg;
        std::lock_guard<std::mutex> lock(read_mu_);
        if (!stream_->Read(&msg))
            throw std::runtime_error("gRPC Read failed (stream closed)");
        return msg.data();
    }

    void sendU64(uint64_t value) override {
        ks05::ChannelMessage msg;
        msg.set_value(value);
        std::lock_guard<std::mutex> lock(write_mu_);
        if (!stream_->Write(msg))
            throw std::runtime_error("gRPC Write failed (stream closed)");
    }

    uint64_t recvU64() override {
        ks05::ChannelMessage msg;
        std::lock_guard<std::mutex> lock(read_mu_);
        if (!stream_->Read(&msg))
            throw std::runtime_error("gRPC Read failed (stream closed)");
        return msg.value();
    }

    void flush() override {}

    void close() override {
        stream_->WritesDone();
        stream_->Finish();
    }

private:
    grpc::ClientContext context_;
    std::unique_ptr<ks05::Ks05PartyService::Stub> stub_;
    Stream stream_;
    std::mutex read_mu_;
    std::mutex write_mu_;
};

} // namespace mpsi
