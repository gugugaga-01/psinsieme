#pragma once

#include "Network/Channel.h"
#include "Common/ByteStream.h"
#include "core/transport/channel.h"
#include <stdexcept>
#include <cstring>

namespace mpsi::xzh26 {

// Adapts mpsi::Channel (gRPC-based) to osuCrypto::Channel interface
// so that OPPRF code can use it without modification.
class ChannelAdapter : public osuCrypto::Channel {
public:
    explicit ChannelAdapter(mpsi::Channel* inner) : inner_(inner) {}

    osuCrypto::Endpoint& getEndpoint() override {
        throw std::runtime_error("getEndpoint() not supported on adapter");
    }

    std::string getName() const override { return "adapter"; }

    osuCrypto::u64 getTotalDataSent() const override { return sent_; }
    osuCrypto::u64 getTotalDataRecv() const override { return recv_; }
    osuCrypto::u64 getMaxOutstandingSendData() const override { return 0; }

    void asyncSend(const void* bufferPtr, osuCrypto::u64 length) override {
        send(bufferPtr, length);
    }

    void asyncSend(std::unique_ptr<osuCrypto::ChannelBuffer> mH) override {
        // ChannelBuffer methods are protected; cast to ByteStream which has public API
        auto* bs = dynamic_cast<osuCrypto::ByteStream*>(mH.get());
        if (bs) {
            send(bs->data(), bs->size());
        } else {
            throw std::runtime_error("ChannelAdapter: unsupported ChannelBuffer type");
        }
    }

    void send(const void* bufferPtr, osuCrypto::u64 length) override {
        std::string data(reinterpret_cast<const char*>(bufferPtr), length);
        inner_->sendBytes(data);
        sent_ += length;
    }

    std::future<void> asyncRecv(void* dest, osuCrypto::u64 length) override {
        recv(dest, length);
        std::promise<void> p;
        p.set_value();
        return p.get_future();
    }

    std::future<void> asyncRecv(osuCrypto::ChannelBuffer& mH) override {
        recv(mH);
        std::promise<void> p;
        p.set_value();
        return p.get_future();
    }

    void recv(void* dest, osuCrypto::u64 length) override {
        std::string data = inner_->recvBytes();
        if (data.size() != length) {
            throw std::runtime_error("ChannelAdapter::recv size mismatch: expected "
                + std::to_string(length) + " got " + std::to_string(data.size()));
        }
        std::memcpy(dest, data.data(), length);
        recv_ += length;
    }

    void recv(osuCrypto::ChannelBuffer& mH) override {
        std::string data = inner_->recvBytes();
        // ChannelBuffer methods are protected; cast to ByteStream which has public API
        auto* bs = dynamic_cast<osuCrypto::ByteStream*>(&mH);
        if (bs) {
            bs->resize(data.size());
            std::memcpy(bs->data(), data.data(), data.size());
        } else {
            throw std::runtime_error("ChannelAdapter: unsupported ChannelBuffer type for recv");
        }
        recv_ += data.size();
    }

    bool opened() override { return true; }
    void waitForOpen() override {}
    void close() override {}

private:
    mpsi::Channel* inner_;
    osuCrypto::u64 sent_ = 0;
    osuCrypto::u64 recv_ = 0;
};

} // namespace mpsi::xzh26
