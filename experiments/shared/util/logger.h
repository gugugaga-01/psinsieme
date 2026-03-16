// Logger.h

#ifndef LOGGER_H
#define LOGGER_H

#include <mutex>
#include <iostream>
#include <iomanip>
#include <string>

class Logger
{
public:
    // Get the singleton instance
    static Logger &getInstance()
    {
        static Logger instance;
        return instance;
    }

    // Delete copy constructor and assignment operator
    Logger(const Logger &) = delete;
    Logger &operator=(const Logger &) = delete;

    // Method to enable or disable logging
    void setEnabled(bool enabled)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = enabled;
    }

    // Log method for regular messages
    template <typename... Args>
    void log(Args &&...args)
    {
        if (!enabled_)
            return;
        std::lock_guard<std::mutex> lock(mutex_);
        (std::cout << ... << args) << std::endl;
    }

    // Log method for error messages
    template <typename... Args>
    void error(Args &&...args)
    {
        if (!enabled_)
            return;
        std::lock_guard<std::mutex> lock(mutex_);
        (std::cerr << ... << args) << std::endl;
    }

    // Method to enable or disable logging
    bool isEnabled()
    {
        return enabled_;
    }

private:
    // Private constructor for singleton
    Logger() : enabled_(false) {}
    bool enabled_;
    std::mutex mutex_;
};

#endif // LOGGER_H