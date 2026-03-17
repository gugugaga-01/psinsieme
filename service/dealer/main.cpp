// psi_dealer: Trusted key dealer for Paillier-based PSI protocols.
//
// Generates threshold Paillier keys and distributes individual secret
// key shares to each party.  After all parties have collected their
// shares, the dealer securely wipes all key material and exits.
//
// SECURITY-CRITICAL: The dealer temporarily holds ALL secret key shares
// and the factorization of N.  It must run in a trusted environment.
// See CLAUDE.md for the full trust model discussion.
//
// Usage:
//   psi_dealer --parties N --listen ADDR
//              [--cert FILE --key FILE --ca FILE]
//              [--certs-dir DIR] [--config FILE]
//
// Config file format (key = value, one per line):
//   parties = 3
//   listen = 0.0.0.0:50050
//   certs-dir = /path/to/certs
//
// Command-line flags override config file values.

#include "dealer/dealer_service.h"
#include "core/transport/party_server.h"
#include "core/config.h"

#include <grpcpp/grpcpp.h>
#include <iostream>
#include <string>
#include <csignal>

static std::unique_ptr<grpc::Server> g_server;

static void signalHandler(int) {
    if (g_server) g_server->Shutdown();
}

static void printUsage() {
    std::cerr << "Usage: psi_dealer --parties N --listen ADDR\n"
              << "                  [--cert FILE --key FILE --ca FILE]\n"
              << "                  [--certs-dir DIR] [--config FILE]\n";
}

int main(int argc, char** argv) {
    uint64_t numParties = 0;
    std::string listenAddr;
    std::string certsDir;
    std::string certFile, keyFile, caFile;
    std::string configFile;

    // First pass: find --config
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc)
            configFile = argv[++i];
    }

    // Load config file defaults
    if (!configFile.empty()) {
        auto kv = mpsi::parseConfigFile(configFile);
        if (kv.count("parties"))   numParties = std::stoull(kv["parties"]);
        if (kv.count("listen"))    listenAddr = kv["listen"];
        if (kv.count("cert"))      certFile = kv["cert"];
        if (kv.count("key"))       keyFile = kv["key"];
        if (kv.count("ca"))        caFile = kv["ca"];
        if (kv.count("certs-dir")) certsDir = kv["certs-dir"];
    }

    // Second pass: command-line flags override config file
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--parties" && i + 1 < argc)
            numParties = std::stoull(argv[++i]);
        else if (arg == "--listen" && i + 1 < argc)
            listenAddr = argv[++i];
        else if (arg == "--cert" && i + 1 < argc)
            certFile = argv[++i];
        else if (arg == "--key" && i + 1 < argc)
            keyFile = argv[++i];
        else if (arg == "--ca" && i + 1 < argc)
            caFile = argv[++i];
        else if (arg == "--certs-dir" && i + 1 < argc)
            certsDir = argv[++i];
        else if (arg == "--config" && i + 1 < argc)
            ++i; // already handled
        else if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else {
            printUsage();
            return 1;
        }
    }

    if (numParties < 2 || listenAddr.empty()) {
        printUsage();
        return 1;
    }

    mpsi::KeyDealerImpl dealer(numParties);

    grpc::ServerBuilder builder;

    // TLS setup: explicit flags take precedence over --certs-dir
    mpsi::TlsConfig tls;
    if (!certFile.empty() && !keyFile.empty() && !caFile.empty()) {
        tls.server_cert = mpsi::readFile(certFile);
        tls.server_key = mpsi::readFile(keyFile);
        tls.ca_cert = mpsi::readFile(caFile);
        tls.enable_mtls = true;
    } else if (!certsDir.empty()) {
        tls.server_cert = mpsi::readFile(certsDir + "/dealer.pem");
        tls.server_key = mpsi::readFile(certsDir + "/dealer-key.pem");
        tls.ca_cert = mpsi::readFile(certsDir + "/ca.pem");
        tls.enable_mtls = true;
    }

    if (tls.enable_mtls) {
        auto creds = mpsi::makeServerCredentials(tls);
        builder.AddListeningPort(listenAddr, creds);
        std::cerr << "[Dealer] Listening on " << listenAddr << " (mTLS)"
                  << std::endl;
    } else {
        builder.AddListeningPort(listenAddr,
                                  grpc::InsecureServerCredentials());
        std::cerr << "[Dealer] Listening on " << listenAddr << " (insecure)"
                  << std::endl;
    }

    builder.RegisterService(&dealer);
    g_server = builder.BuildAndStart();

    if (!g_server) {
        std::cerr << "[Dealer] Failed to start server" << std::endl;
        return 1;
    }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::cerr << "[Dealer] Waiting for " << numParties
              << " parties to collect their key shares..." << std::endl;

    // Wait until all parties have collected, then shut down
    dealer.waitUntilDone();

    std::cerr << "[Dealer] All shares distributed. Shutting down."
              << std::endl;
    g_server->Shutdown();

    return 0;
}
