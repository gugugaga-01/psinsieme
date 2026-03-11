#pragma once

#include <string>
#include <cstdint>

namespace mpsi {

// Abstract bidirectional channel for inter-party communication.
// Implementations: InProcessChannel (testing), GrpcChannel (gRPC transport).
class Channel {
public:
    virtual ~Channel() = default;

    virtual void sendBytes(const std::string& data) = 0;
    virtual std::string recvBytes() = 0;

    virtual void sendU64(uint64_t value) = 0;
    virtual uint64_t recvU64() = 0;

    virtual void flush() = 0;
    virtual void close() = 0;
};

} // namespace mpsi
