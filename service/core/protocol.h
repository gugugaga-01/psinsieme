#pragma once

#include "core/party_config.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace mpsi {

// Context passed to protocol plugins for each ComputeIntersection request.
struct ProtocolContext {
    const PartyConfig& config;
    bool is_leader;
    uint64_t leader_id;
    std::vector<uint64_t> member_ids;
    uint64_t threshold;
};

// Base class for PSI protocol plugins.
//
// Each protocol (KS05, YYH26, etc.) implements this interface. Protocols
// self-register via REGISTER_PROTOCOL so the service discovers them
// automatically without protocol-specific code in the core.
class PsiProtocol {
public:
    virtual ~PsiProtocol() = default;

    // Protocol identifier (e.g. "ks05_t_mpsi", "yyh26_tt_mpsi").
    virtual std::string name() const = 0;

    // Called once at startup. Protocols that need keys (KS05) fetch them here.
    // Returns true on success, false if setup fails (protocol will be unavailable).
    virtual bool setup(const PartyConfig& config) { (void)config; return true; }

    // Validate a request before running. Return empty string on success,
    // or an error message on failure.
    virtual std::string validate(const ProtocolContext& ctx,
                                  const std::vector<std::string>& elements) {
        (void)ctx; (void)elements; return "";
    }

    // Run the protocol. Returns intersection elements for the leader,
    // or an empty vector for members.
    virtual std::vector<std::string> run(const ProtocolContext& ctx,
                                          const std::vector<std::string>& elements) = 0;
};

// Singleton registry for protocol plugins.
class ProtocolRegistry {
public:
    using Factory = std::function<std::unique_ptr<PsiProtocol>()>;

    static ProtocolRegistry& instance() {
        static ProtocolRegistry reg;
        return reg;
    }

    void registerProtocol(const std::string& name, Factory factory) {
        factories_[name] = std::move(factory);
    }

    std::unique_ptr<PsiProtocol> create(const std::string& name) const {
        auto it = factories_.find(name);
        if (it == factories_.end()) return nullptr;
        return it->second();
    }

    std::vector<std::string> availableProtocols() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : factories_)
            names.push_back(name);
        return names;
    }

private:
    ProtocolRegistry() = default;
    std::map<std::string, Factory> factories_;
};

// Self-registration macro. Place in a .cpp file:
//   REGISTER_PROTOCOL(MyProtocol)
// The protocol class must have a default constructor.
#define REGISTER_PROTOCOL(ClassName) \
    static const bool ClassName##_registered_ = [] { \
        mpsi::ProtocolRegistry::instance().registerProtocol( \
            ClassName().name(), \
            [] { return std::make_unique<ClassName>(); }); \
        return true; \
    }();

} // namespace mpsi
