#pragma once

#include <mutex>
#include <iostream>
#include <string>

namespace mpsi::ks05 {

class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void setEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = enabled;
    }

    template <typename... Args>
    void log(Args&&... args) {
        if (!enabled_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        (std::cout << ... << args) << std::endl;
    }

    template <typename... Args>
    void error(Args&&... args) {
        if (!enabled_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        (std::cerr << ... << args) << std::endl;
    }

    bool isEnabled() { return enabled_; }

private:
    Logger() : enabled_(false) {}
    bool enabled_;
    std::mutex mutex_;
};

} // namespace mpsi::ks05
