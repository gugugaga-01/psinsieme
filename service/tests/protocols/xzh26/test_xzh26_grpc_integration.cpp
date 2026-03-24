#include <iostream>
#include <vector>
#include <thread>
#include <set>
#include <fstream>
#include <chrono>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <cstring>

#include "core/transport/grpc_channel.h"
#include "core/transport/party_server.h"
#include "protocols/xzh26/protocol/ec_mpsi.h"

using namespace mpsi::xzh26;

static std::string readFileStr(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) throw std::runtime_error("Cannot open: " + path);
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    std::cout << "=== XZH26 EC-MPSI gRPC Integration Test ===" << std::endl;

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
    const uint64_t setSize = 32;

    int base_port = use_tls ? 50200 : 50190;
    std::string addr[3] = {
        "127.0.0.1:" + std::to_string(base_port),
        "127.0.0.1:" + std::to_string(base_port + 1),
        "127.0.0.1:" + std::to_string(base_port + 2),
    };

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
        }
    }

    // Build input sets: first 16 elements shared, rest unique
    std::vector<std::vector<Element>> inputs(numParties);
    for (uint64_t p = 0; p < numParties; p++) {
        for (uint32_t i = 0; i < setSize; i++) {
            if (i < 16)
                inputs[p].push_back(100 + i);
            else
                inputs[p].push_back(1000 * (p + 1) + i);
        }
    }

    const uint64_t leaderIdx = numParties - 1;

    // Create servers
    mpsi::PartyServer server[3] = {
        {addr[0], tls[0]},
        {addr[1], tls[1]},
        {addr[2], tls[2]},
    };

    std::vector<Element> intersection_result;
    std::atomic<bool> p0_done{false}, p1_done{false};
    std::mutex p0_mu, p1_mu;
    std::condition_variable p0_cv, p1_cv;

    // P0: expects leader to connect (star topology)
    server[0].service().expectParty(2, [&](mpsi::GrpcServerChannel* ch_from_leader) {
        std::vector<mpsi::Channel*> chls = {ch_from_leader};
        EcMpsiMember member;
        member.init(numParties, threshold, 0, setSize, true);
        member.run(inputs[0], chls);
        p0_done = true;
        p0_cv.notify_all();
    });

    // P1: expects leader to connect (star topology)
    server[1].service().expectParty(2, [&](mpsi::GrpcServerChannel* ch_from_leader) {
        std::vector<mpsi::Channel*> chls = {ch_from_leader};
        EcMpsiMember member;
        member.init(numParties, threshold, 1, setSize, true);
        member.run(inputs[1], chls);
        p1_done = true;
        p1_cv.notify_all();
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

    // Leader thread: connect to P0 and P1
    std::thread leader_thread([&]() {
        auto creds = mpsi::makeClientCredentials(tls[2]);
        mpsi::GrpcIdentifiedClientChannel ch_to_p0(addr[0], creds, 2);
        mpsi::GrpcIdentifiedClientChannel ch_to_p1(addr[1], creds, 2);

        std::vector<mpsi::Channel*> chls = {&ch_to_p0, &ch_to_p1};

        EcMpsiLeader leader;
        leader.init(numParties, threshold, leaderIdx, setSize, true);
        intersection_result = leader.run(inputs[leaderIdx], chls);

        ch_to_p0.close();
        ch_to_p1.close();
    });

    leader_thread.join();
    std::cout << "[Main] Leader done" << std::endl;

    {
        std::unique_lock<std::mutex> lk(p0_mu);
        p0_cv.wait(lk, [&] { return p0_done.load(); });
    }
    {
        std::unique_lock<std::mutex> lk(p1_mu);
        p1_cv.wait(lk, [&] { return p1_done.load(); });
    }

    for (int i = 0; i < 3; i++) server[i].shutdown();
    for (int i = 0; i < 3; i++) server_threads[i].join();

    // Verify
    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "Intersection size: " << intersection_result.size() << std::endl;

    std::set<uint32_t> result_set(intersection_result.begin(), intersection_result.end());
    std::set<uint32_t> expected;
    for (uint32_t i = 0; i < 16; i++) expected.insert(100 + i);

    if (result_set == expected) {
        std::cout << "\nTEST PASSED: gRPC intersection matches expected ("
                  << expected.size() << " elements)" << std::endl;
        return 0;
    } else {
        std::cerr << "\nTEST FAILED: Expected " << expected.size()
                  << " elements, got " << result_set.size() << std::endl;
        return 1;
    }
}
