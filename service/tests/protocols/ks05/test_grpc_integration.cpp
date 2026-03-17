#include <iostream>
#include <vector>
#include <thread>
#include <set>
#include <fstream>
#include <chrono>
#include <atomic>
#include <mutex>
#include <condition_variable>

#include "core/transport/grpc_channel.h"
#include "core/transport/party_server.h"
#include "protocols/ks05/protocol/t_mpsi.h"
#include "protocols/ks05/crypto/paillier.h"
#include "protocols/ks05/protocol/logger.h"

using namespace mpsi::ks05;

static std::string readFileStr(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) throw std::runtime_error("Cannot open: " + path);
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    std::cout << "=== KS05 T-MPSI gRPC Integration Test ===" << std::endl;

    bool use_tls = false;
    std::string certsDir;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--tls")
            use_tls = true;
        else if (arg == "--certs-dir" && i + 1 < argc)
            certsDir = argv[++i];
    }
    std::cout << "TLS: " << (use_tls ? "enabled" : "disabled") << std::endl;

    const uint64_t numParties = 3;
    const uint64_t threshold = 3;
    const uint64_t senderSize = 4;
    const uint64_t recverSize = 4;

    Logger::getInstance().setEnabled(true);

    // Generate keys via trusted dealer model
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    // Party addresses
    // Use different port ranges for insecure vs TLS to allow parallel ctest
    int base_port = use_tls ? 50080 : 50070;
    std::string addr[3] = {
        "127.0.0.1:" + std::to_string(base_port),
        "127.0.0.1:" + std::to_string(base_port + 1),
        "127.0.0.1:" + std::to_string(base_port + 2),
    };

    // TLS config (optional)
    mpsi::TlsConfig tls[3];
    if (use_tls) {
        if (certsDir.empty()) {
            std::cerr << "TLS mode requires --certs-dir <path>" << std::endl;
            return 1;
        }
        std::string caCert = readFileStr(certsDir + "/ca.pem");
        for (int i = 0; i < 3; i++) {
            tls[i].server_cert = readFileStr(certsDir + "/party" + std::to_string(i) + ".pem");
            tls[i].server_key = readFileStr(certsDir + "/party" + std::to_string(i) + "-key.pem");
            tls[i].ca_cert = caCert;
            tls[i].enable_mtls = true;
        }
    }

    // Inputs (intersection of all 3 = {3, 4})
    std::vector<ZZ> inputs[3] = {
        {NTL::to_ZZ(1), NTL::to_ZZ(2), NTL::to_ZZ(3), NTL::to_ZZ(4)},
        {NTL::to_ZZ(2), NTL::to_ZZ(3), NTL::to_ZZ(4), NTL::to_ZZ(5)},
        {NTL::to_ZZ(3), NTL::to_ZZ(4), NTL::to_ZZ(5), NTL::to_ZZ(6)},
    };

    // Create servers
    mpsi::PartyServer server[3] = {
        {addr[0], tls[0]},
        {addr[1], tls[1]},
        {addr[2], tls[2]},
    };

    // Results
    std::vector<ZZ> intersection_result;
    std::atomic<bool> p0_done{false};
    std::atomic<bool> p1_done{false};
    std::mutex p0_mu, p1_mu;
    std::condition_variable p0_cv, p1_cv;

    // P1 needs 2 connections. Collect them with identification.
    mpsi::GrpcServerChannel* p1_ch_leader = nullptr;
    mpsi::GrpcServerChannel* p1_ch_p0 = nullptr;
    std::atomic<int> p1_connections{0};

    // P0's server: expects leader (party 2) to connect
    server[0].service().expectParty(2, [&](mpsi::GrpcServerChannel* ch_from_leader) {
        std::cout << "[P0] Leader connected, starting member protocol" << std::endl;

        // P0 connects to P1 as client
        auto creds = mpsi::makeClientCredentials(tls[0]);
        mpsi::GrpcIdentifiedClientChannel ch_to_p1(addr[1], creds, 0);

        // channels[0]=leader, channels[1]=nullptr(no prev for first member), channels[2]=next(P1)
        std::vector<mpsi::Channel*> chls = {ch_from_leader, nullptr, &ch_to_p1};

        TMpsiMember member;
        member.init(numParties, threshold, 0, senderSize, recverSize, true);
        member.setKeys(pk, sks[0]);
        member.run(inputs[0], chls);

        ch_to_p1.close();
        p0_done = true;
        p0_cv.notify_all();
        std::cout << "[P0] Done" << std::endl;
    });

    // P1's server: expects leader (party 2) and P0 (party 0)
    server[1].service().expectParty(2, [&](mpsi::GrpcServerChannel* ch) {
        std::cout << "[P1] Leader connected" << std::endl;
        p1_ch_leader = ch;
        p1_connections++;
        p1_cv.notify_all();
        // Keep stream alive until protocol finishes
        std::unique_lock<std::mutex> lk(p1_mu);
        p1_cv.wait(lk, [&] { return p1_done.load(); });
    });

    server[1].service().expectParty(0, [&](mpsi::GrpcServerChannel* ch) {
        std::cout << "[P1] P0 connected" << std::endl;
        p1_ch_p0 = ch;
        p1_connections++;
        p1_cv.notify_all();
        // Keep stream alive
        std::unique_lock<std::mutex> lk(p1_mu);
        p1_cv.wait(lk, [&] { return p1_done.load(); });
    });

    // Start servers
    std::atomic<int> servers_ready{0};
    std::mutex srv_mu;
    std::condition_variable srv_cv;

    std::thread server_threads[3];
    for (int i = 0; i < 3; i++) {
        server_threads[i] = std::thread([&, i]() {
            server[i].start();
            servers_ready++;
            srv_cv.notify_all();
            server[i].wait();
        });
    }

    {
        std::unique_lock<std::mutex> lk(srv_mu);
        srv_cv.wait(lk, [&] { return servers_ready.load() >= 3; });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::cout << "All servers started" << std::endl;

    // P1 protocol thread
    std::thread p1_thread([&]() {
        {
            std::unique_lock<std::mutex> lk(p1_mu);
            p1_cv.wait(lk, [&] { return p1_connections.load() >= 2; });
        }
        std::cout << "[P1] Both connections received, starting member protocol" << std::endl;

        // channels[0]=leader, channels[1]=prev(P0), channels[2]=nullptr(last member)
        std::vector<mpsi::Channel*> chls = {p1_ch_leader, p1_ch_p0, nullptr};

        TMpsiMember member;
        member.init(numParties, threshold, 1, senderSize, recverSize, true);
        member.setKeys(pk, sks[1]);
        member.run(inputs[1], chls);

        std::cout << "[P1] Done" << std::endl;
        p1_done = true;
        p1_cv.notify_all();
    });

    // Leader thread
    std::thread leader_thread([&]() {
        std::cout << "[Leader] Connecting to P0 and P1" << std::endl;

        auto creds = mpsi::makeClientCredentials(tls[2]);
        mpsi::GrpcIdentifiedClientChannel ch_to_p0(addr[0], creds, 2);
        std::cout << "[Leader] Connected to P0" << std::endl;

        mpsi::GrpcIdentifiedClientChannel ch_to_p1(addr[1], creds, 2);
        std::cout << "[Leader] Connected to P1" << std::endl;

        std::vector<mpsi::Channel*> chls = {&ch_to_p0, &ch_to_p1};

        TMpsiLeader leader;
        leader.init(numParties, threshold, 2, senderSize, recverSize, true);
        leader.setKeys(pk, sks[2]);
        intersection_result = leader.run(inputs[2], chls);

        ch_to_p0.close();
        ch_to_p1.close();
    });

    leader_thread.join();
    std::cout << "[Main] Leader done" << std::endl;

    {
        std::unique_lock<std::mutex> lk(p0_mu);
        p0_cv.wait(lk, [&] { return p0_done.load(); });
    }
    std::cout << "[Main] P0 done" << std::endl;

    p1_thread.join();
    std::cout << "[Main] P1 done" << std::endl;

    for (int i = 0; i < 3; i++) server[i].shutdown();
    for (int i = 0; i < 3; i++) server_threads[i].join();

    // Verify
    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "Intersection size: " << intersection_result.size() << std::endl;

    std::set<long> result_set;
    for (const auto& v : intersection_result) {
        long val = NTL::to_long(v);
        result_set.insert(val);
        std::cout << "  Element: " << val << std::endl;
    }

    std::set<long> expected = {3, 4};

    if (result_set == expected) {
        std::cout << "\nTEST PASSED: gRPC intersection matches expected {3, 4}" << std::endl;
        return 0;
    } else {
        std::cerr << "\nTEST FAILED: Expected {3, 4}, got {";
        for (auto v : result_set) std::cerr << v << ", ";
        std::cerr << "}" << std::endl;
        return 1;
    }
}
