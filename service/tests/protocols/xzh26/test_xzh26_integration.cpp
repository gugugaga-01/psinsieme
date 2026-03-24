#include <iostream>
#include <vector>
#include <thread>
#include <set>
#include <cstring>

#include "core/transport/in_process_channel.h"
#include "protocols/xzh26/protocol/ec_mpsi.h"

using namespace mpsi::xzh26;

// Run XZH26 protocol and return the leader's intersection result.
static std::set<uint32_t> runProtocol(
    uint64_t numParties, uint64_t threshold,
    const std::vector<std::vector<Element>>& allInputs)
{
    uint64_t leaderIdx = numParties - 1;
    uint64_t numMembers = numParties - 1;

    // Create star channels: leader <-> each member
    std::vector<std::unique_ptr<mpsi::InProcessChannel>> member_to_leader;
    std::vector<std::unique_ptr<mpsi::InProcessChannel>> leader_to_member;
    for (uint64_t i = 0; i < numMembers; i++) {
        auto [a, b] = mpsi::InProcessChannel::createPair();
        member_to_leader.push_back(std::move(a));
        leader_to_member.push_back(std::move(b));
    }

    std::vector<Element> intersection_result;

    // Leader thread
    std::thread leader_thread([&]() {
        EcMpsiLeader leader;
        leader.init(numParties, threshold, leaderIdx,
                    allInputs[leaderIdx].size(), true);

        std::vector<mpsi::Channel*> chls;
        for (uint64_t i = 0; i < numMembers; i++)
            chls.push_back(leader_to_member[i].get());

        intersection_result = leader.run(allInputs[leaderIdx], chls);
    });

    // Member threads
    std::vector<std::thread> member_threads;
    for (uint64_t m = 0; m < numMembers; m++) {
        member_threads.emplace_back([&, m]() {
            EcMpsiMember member;
            member.init(numParties, threshold, m,
                        allInputs[m].size(), true);

            std::vector<mpsi::Channel*> chls = {member_to_leader[m].get()};
            member.run(allInputs[m], chls);
        });
    }

    leader_thread.join();
    for (auto& t : member_threads) t.join();

    std::set<uint32_t> result(intersection_result.begin(), intersection_result.end());
    return result;
}

// Test 1: 3 parties, larger sets (OPPRF hashing needs reasonable set sizes)
static bool testEqualSizes() {
    std::cout << "\n=== Test 1: 3 parties, 32-element sets, threshold=3 ===" << std::endl;

    const uint64_t numParties = 3;
    const uint64_t setSize = 32;

    // Build input sets: first 16 elements shared, rest unique per party
    std::vector<std::vector<Element>> inputs(numParties);
    for (uint64_t p = 0; p < numParties; p++) {
        for (uint32_t i = 0; i < setSize; i++) {
            if (i < 16)
                inputs[p].push_back(100 + i);  // shared: 100..115
            else
                inputs[p].push_back(1000 * (p + 1) + i);  // unique per party
        }
    }

    auto result = runProtocol(numParties, 3, inputs);

    // Expected: all shared elements (100..115)
    std::set<uint32_t> expected;
    for (uint32_t i = 0; i < 16; i++) expected.insert(100 + i);

    std::cout << "Intersection size: " << result.size()
              << " (expected " << expected.size() << ")" << std::endl;

    if (result == expected) {
        std::cout << "TEST 1 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 1 FAILED: got {";
    for (auto v : result) std::cerr << v << ", ";
    std::cerr << "}" << std::endl;
    return false;
}

// Test 2: 3 parties, no common elements
static bool testEmptyIntersection() {
    std::cout << "\n=== Test 2: Empty intersection ===" << std::endl;

    const uint64_t numParties = 3;
    const uint64_t setSize = 32;

    // No overlap between parties
    std::vector<std::vector<Element>> inputs(numParties);
    for (uint64_t p = 0; p < numParties; p++) {
        for (uint32_t i = 0; i < setSize; i++)
            inputs[p].push_back(1000 * (p + 1) + i);
    }

    auto result = runProtocol(numParties, 3, inputs);
    std::set<uint32_t> expected = {};

    std::cout << "Intersection size: " << result.size()
              << " (expected 0)" << std::endl;

    if (result == expected) {
        std::cout << "TEST 2 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 2 FAILED" << std::endl;
    return false;
}

int main() {
    std::cout << "=== XZH26 EC-MPSI In-Process Integration Tests ===" << std::endl;

    bool allPassed = true;
    allPassed &= testEqualSizes();
    allPassed &= testEmptyIntersection();

    std::cout << "\n=== Summary ===" << std::endl;
    if (allPassed) {
        std::cout << "ALL TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << "SOME TESTS FAILED" << std::endl;
        return 1;
    }
}
