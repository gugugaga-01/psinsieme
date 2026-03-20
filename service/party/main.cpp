#include "psi_service_impl.h"
#include "core/config.h"
#include "core/tls/tls_config.h"

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
              << "                 [--dealer ADDR] [--listen ADDR]\n"
              << "                 [--protocol NAME] [--certs-dir DIR]\n"
              << "                 [--cert FILE --key FILE --ca FILE]\n"
              << "                 [--tls-mode insecure|tls|mtls]\n"
              << "                 [--config FILE]\n"
              << "\n"
              << "  --cert/--key   Server certificate and private key (PEM).\n"
              << "  --ca           CA certificate for mTLS verification (optional).\n"
              << "  --tls-mode     insecure (no TLS), tls (encrypt-only), mtls (mutual TLS).\n"
              << "                 Defaults to mtls when certs are provided.\n"
              << "\n"
              << "  --dealer is required for ks05_t_mpsi but optional for other protocols.\n"
              << "  If provided, Paillier keys are fetched at startup, enabling KS05 requests.\n"
              << "  The protocol can also be selected per-request by the client.\n";
}

int main(int argc, char** argv) {
    mpsi::PartyConfig config;
    std::string addresses_csv;
    std::string my_address;
    std::string certs_dir;
    std::string certFile, keyFile, caFile;
    std::string tls_mode_str;
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
        if (kv.count("cert"))      certFile = kv["cert"];
        if (kv.count("key"))       keyFile = kv["key"];
        if (kv.count("ca"))        caFile = kv["ca"];
        if (kv.count("tls-mode"))  tls_mode_str = kv["tls-mode"];
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
        else if (arg == "--cert" && i + 1 < argc)
            certFile = argv[++i];
        else if (arg == "--key" && i + 1 < argc)
            keyFile = argv[++i];
        else if (arg == "--ca" && i + 1 < argc)
            caFile = argv[++i];
        else if (arg == "--tls-mode" && i + 1 < argc)
            tls_mode_str = argv[++i];
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

    // TLS setup: --cert/--key take precedence over --certs-dir
    mpsi::TlsConfig tls;
    if (!certFile.empty() && !keyFile.empty()) {
        tls.server_cert = mpsi::readFile(certFile);
        tls.server_key = mpsi::readFile(keyFile);
        if (!caFile.empty())
            tls.ca_cert = mpsi::readFile(caFile);
    } else if (!certs_dir.empty()) {
        tls.server_cert = mpsi::readFile(certs_dir + "/party" +
            std::to_string(config.party_id) + ".pem");
        tls.server_key = mpsi::readFile(certs_dir + "/party" +
            std::to_string(config.party_id) + "-key.pem");
        tls.ca_cert = mpsi::readFile(certs_dir + "/ca.pem");
    }

    // Determine TLS mode
    if (!tls.server_cert.empty()) {
        if (tls_mode_str == "insecure")
            tls.mode = mpsi::TlsMode::INSECURE;
        else if (tls_mode_str == "tls")
            tls.mode = mpsi::TlsMode::TLS;
        else
            tls.mode = mpsi::TlsMode::MTLS;  // default when certs provided
    }

    config.inter_party_tls = tls;
    config.client_tls = tls;

    // Create PsiService — protocol plugins are set up automatically
    // (KS05 fetches dealer keys, YYH26 is a no-op, etc.)
    mpsi::PsiServiceImpl psi_service(config);

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
