#include <gtest/gtest.h>
#include <thread>
#include "core/transport/channel.h"
#include "core/transport/in_process_channel.h"

using namespace mpsi;

TEST(InProcessChannelTest, SendRecvU64) {
    auto [ch_a, ch_b] = InProcessChannel::createPair();

    std::thread sender([&]() {
        ch_a->sendU64(42);
        ch_a->sendU64(100);
    });

    EXPECT_EQ(ch_b->recvU64(), 42u);
    EXPECT_EQ(ch_b->recvU64(), 100u);

    sender.join();
}

TEST(InProcessChannelTest, SendRecvBytes) {
    auto [ch_a, ch_b] = InProcessChannel::createPair();

    std::string payload(1024, 'x');

    std::thread sender([&]() {
        ch_a->sendBytes("hello");
        ch_a->sendBytes(payload);
    });

    EXPECT_EQ(ch_b->recvBytes(), "hello");
    EXPECT_EQ(ch_b->recvBytes(), payload);

    sender.join();
}

TEST(InProcessChannelTest, Bidirectional) {
    auto [ch_a, ch_b] = InProcessChannel::createPair();

    std::thread t([&]() {
        ch_b->sendU64(ch_b->recvU64() * 2);
    });

    ch_a->sendU64(21);
    EXPECT_EQ(ch_a->recvU64(), 42u);

    t.join();
}

TEST(InProcessChannelTest, MixedTypes) {
    auto [ch_a, ch_b] = InProcessChannel::createPair();

    std::thread sender([&]() {
        ch_a->sendU64(1);
        ch_a->sendBytes("data");
        ch_a->sendU64(2);
    });

    EXPECT_EQ(ch_b->recvU64(), 1u);
    EXPECT_EQ(ch_b->recvBytes(), "data");
    EXPECT_EQ(ch_b->recvU64(), 2u);

    sender.join();
}

TEST(SerializationTest, RoundTripU64) {
    auto [ch_a, ch_b] = InProcessChannel::createPair();

    std::vector<uint64_t> values = {0, 1, UINT64_MAX, 12345678901234ULL};

    std::thread sender([&]() {
        for (auto v : values) ch_a->sendU64(v);
    });

    for (auto expected : values)
        EXPECT_EQ(ch_b->recvU64(), expected);

    sender.join();
}
