#pragma once

#include "channel.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <variant>

namespace mpsi {

// Thread-safe message queue for in-process communication.
class MessageQueue {
public:
    using Message = std::variant<std::string, uint64_t>;

    void push(Message msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(msg));
        cv_.notify_one();
    }

    Message pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty(); });
        Message msg = std::move(queue_.front());
        queue_.pop();
        return msg;
    }

private:
    std::queue<Message> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

// In-process channel backed by two message queues (one per direction).
// Used for testing: run the full protocol in a single process.
class InProcessChannel : public Channel {
public:
    InProcessChannel(std::shared_ptr<MessageQueue> send_queue,
                     std::shared_ptr<MessageQueue> recv_queue)
        : send_queue_(std::move(send_queue))
        , recv_queue_(std::move(recv_queue)) {}

    void sendBytes(const std::string& data) override {
        send_queue_->push(data);
    }

    std::string recvBytes() override {
        auto msg = recv_queue_->pop();
        return std::get<std::string>(msg);
    }

    void sendU64(uint64_t value) override {
        send_queue_->push(value);
    }

    uint64_t recvU64() override {
        auto msg = recv_queue_->pop();
        return std::get<uint64_t>(msg);
    }

    void flush() override {}
    void close() override {}

    // Create a pair of connected channels (A->B, B->A).
    static std::pair<std::unique_ptr<InProcessChannel>, std::unique_ptr<InProcessChannel>>
    createPair() {
        auto q1 = std::make_shared<MessageQueue>();
        auto q2 = std::make_shared<MessageQueue>();
        return {
            std::make_unique<InProcessChannel>(q1, q2),
            std::make_unique<InProcessChannel>(q2, q1)
        };
    }

private:
    std::shared_ptr<MessageQueue> send_queue_;
    std::shared_ptr<MessageQueue> recv_queue_;
};

} // namespace mpsi
