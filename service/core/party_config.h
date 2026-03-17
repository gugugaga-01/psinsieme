#pragma once

#include "core/tls/tls_config.h"

#include <string>
#include <vector>

namespace mpsi {

// Configuration for a single party in the PSI deployment.
struct PartyConfig {
    uint64_t party_id;          // This party's ID (0-indexed, from sorted addresses)
    uint64_t num_parties;       // Total number of parties

    // Addresses of all parties' inter-party gRPC servers (index = party ID)
    std::vector<std::string> party_addresses;

    // TLS config for inter-party communication
    TlsConfig inter_party_tls;

    // Address for this party's client-facing PsiService
    std::string client_listen_addr;
    TlsConfig client_tls;

    // Dealer address (empty = no dealer; KS05 protocol unavailable)
    std::string dealer_addr;

    // Default protocol (clients can override per-request)
    std::string protocol = "ks05_t_mpsi";
};

} // namespace mpsi
