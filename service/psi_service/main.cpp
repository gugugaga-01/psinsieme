#include "psi_service_impl.h"
#include "core/config_file.h"
#include "ks05_t_mpsi/protocol/logger.h"

#include <grpcpp/grpcpp.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <sstream>

// Usage: psi_party --address <my_inter_party_addr>
//                  --addresses <other_addr0>,<other_addr1>,...
//                  --dealer <dealer_addr>
//                  [--listen <client_listen_addr>]
//                  [--protocol <protocol_name>]
//                  [--certs-dir <dir>]
//                  [--config <file>]
//
// --address is this party's own inter-party address.
// --addresses lists the OTHER parties' inter-party addresses.
// These are merged and sorted internally to assign consistent indices.
//
// Config file format (key = value, one per line):
//   address = 10.0.0.1:53000
//   addresses = 10.0.0.2:53000,10.0.0.3:53000
//   dealer = 10.0.0.1:53050
//   listen = 0.0.0.0:50090
//   protocol = ks05_t_mpsi
//   certs-dir = /path/to/certs
//
// Command-line flags override config file values.

static void printUsage() {
    std::cerr << "Usage: psi_party --address ADDR --addresses ADDR,ADDR,...\n"
              << "                 --dealer ADDR [--listen ADDR]\n"
              << "                 [--protocol NAME] [--certs-dir DIR]\n"
              << "                 [--config FILE]\n";
}

int main(int argc, char** argv) {
    mpsi::PartyConfig config;
    std::string addresses_csv;
    std::string my_address;
    std::string certs_dir;
    std::string config_file;
    config.client_listen_addr = "0.0.0.0:50090";

    // First pass: find --config if present
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_file = argv[++i];
        }
    }

    // Load config file defaults (if provided)
    if (!config_file.empty()) {
        auto kv = mpsi::parseConfigFile(config_file);
        if (kv.count("address"))   my_address = kv["address"];
        if (kv.count("addresses")) addresses_csv = kv["addresses"];
        if (kv.count("dealer"))    config.dealer_addr = kv["dealer"];
        if (kv.count("listen"))    config.client_listen_addr = kv["listen"];
        if (kv.count("protocol"))  config.protocol = kv["protocol"];
        if (kv.count("certs-dir")) certs_dir = kv["certs-dir"];
    }

    // Second pass: command-line flags override config file
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--address" && i + 1 < argc)
            my_address = argv[++i];
        else if (arg == "--addresses" && i + 1 < argc)
            addresses_csv = argv[++i];
        else if (arg == "--listen" && i + 1 < argc)
            config.client_listen_addr = argv[++i];
        else if (arg == "--dealer" && i + 1 < argc)
            config.dealer_addr = argv[++i];
        else if (arg == "--protocol" && i + 1 < argc)
            config.protocol = argv[++i];
        else if (arg == "--certs-dir" && i + 1 < argc)
            certs_dir = argv[++i];
        else if (arg == "--config" && i + 1 < argc)
            ++i; // already handled
        else if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
    }

    if (my_address.empty()) {
        std::cerr << "Error: --address is required" << std::endl;
        printUsage();
        return 1;
    }

    if (config.dealer_addr.empty()) {
        std::cerr << "Error: --dealer is required" << std::endl;
        printUsage();
        return 1;
    }

    // Parse other parties' addresses and merge with our own
    {
        std::istringstream ss(addresses_csv);
        std::string addr;
        while (std::getline(ss, addr, ','))
            config.party_addresses.push_back(addr);
    }
    config.party_addresses.push_back(my_address);

    // Sort so all parties agree on the same ordering
    std::sort(config.party_addresses.begin(), config.party_addresses.end());
    config.num_parties = config.party_addresses.size();

    if (config.num_parties < 2) {
        std::cerr << "Error: need at least 1 other address in --addresses" << std::endl;
        printUsage();
        return 1;
    }

    // Determine party index by finding our address in the sorted list
    auto it = std::find(config.party_addresses.begin(),
                        config.party_addresses.end(), my_address);
    config.party_id = std::distance(config.party_addresses.begin(), it);

    // TLS setup from certs directory
    if (!certs_dir.empty()) {
        std::string ca = mpsi::readFile(certs_dir + "/ca.pem");
        std::string cert = mpsi::readFile(certs_dir + "/party" +
            std::to_string(config.party_id) + ".pem");
        std::string key = mpsi::readFile(certs_dir + "/party" +
            std::to_string(config.party_id) + "-key.pem");
        config.inter_party_tls = {cert, key, ca, true};
        config.client_tls = config.inter_party_tls;
    }

    mpsi::TlsConfig dealer_tls;
    if (config.inter_party_tls.enable_mtls) {
        dealer_tls = config.inter_party_tls;
    }

    mpsi::ks05::Logger::getInstance().setEnabled(true);

    // Fetch keys from dealer
    mpsi::ks05::PubKey pk;
    mpsi::ks05::PrivKey sk;
    std::cerr << "[Party " << config.party_id
              << "] Connecting to dealer at " << config.dealer_addr
              << (dealer_tls.enable_mtls ? " (mTLS)" : " (insecure)")
              << "..." << std::endl;

    if (!mpsi::fetchKeyShareFromDealer(
            config.dealer_addr, config.party_id, config.num_parties,
            pk, sk, dealer_tls)) {
        std::cerr << "[Party " << config.party_id
                  << "] Failed to get key share from dealer" << std::endl;
        return 1;
    }

    // Start client-facing PsiService
    mpsi::PsiServiceImpl psi_service(config);
    psi_service.setKeys(pk, sk);

    auto creds = mpsi::makeServerCredentials(config.client_tls);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(config.client_listen_addr, creds);
    builder.RegisterService(&psi_service);

    auto server = builder.BuildAndStart();
    if (!server) {
        std::cerr << "Failed to start PsiService on "
                  << config.client_listen_addr << std::endl;
        return 1;
    }

    std::cerr << "[Party " << config.party_id
              << "] Ready on " << config.client_listen_addr << std::endl;

    server->Wait();
    return 0;
}
