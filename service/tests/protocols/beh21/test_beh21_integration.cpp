#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <set>
#include <cstring>

#include "core/transport/in_process_channel.h"
#include "protocols/beh21/protocol/ot_mpsi.h"
#include "protocols/beh21/crypto/bloom_filter.h"
#include "protocols/ks05/crypto/paillier.h"
#include "protocols/ks05/protocol/t_mpsi.h"
#include "protocols/ks05/protocol/logger.h"

using namespace mpsi::ks05;
using namespace mpsi::beh21;

// Helper: create an Element from a uint64_t (zero-padded to 16 bytes)
static Element makeElement(uint64_t val) {
    Element e{};
    std::memcpy(e.data(), &val, sizeof(val));
    return e;
}

// Run BEH21 protocol and return the leader's intersection result.
static std::set<uint64_t> runProtocol(
    uint64_t numParties, uint64_t threshold,
    const std::vector<std::vector<Element>>& allInputs,
    const PubKey& pk, const std::vector<PrivKey>& sks)
{
    uint64_t leaderIdx = numParties - 1;
    uint64_t numMembers = numParties - 1;

    // Create channels: leader <-> each member (star), member[i] -> member[i+1] (ring)
    // Star channels
    std::vector<std::unique_ptr<mpsi::InProcessChannel>> member_to_leader;
    std::vector<std::unique_ptr<mpsi::InProcessChannel>> leader_to_member;
    for (uint64_t i = 0; i < numMembers; i++) {
        auto [a, b] = mpsi::InProcessChannel::createPair();
        member_to_leader.push_back(std::move(a));
        leader_to_member.push_back(std::move(b));
    }
    // Ring channels: member[i] -> member[i+1]
    std::vector<std::unique_ptr<mpsi::InProcessChannel>> ring_send;
    std::vector<std::unique_ptr<mpsi::InProcessChannel>> ring_recv;
    for (uint64_t i = 0; i + 1 < numMembers; i++) {
        auto [a, b] = mpsi::InProcessChannel::createPair();
        ring_send.push_back(std::move(a));
        ring_recv.push_back(std::move(b));
    }

    std::vector<Element> intersection_result;

    // Leader thread
    std::thread leader_thread([&]() {
        OtMpsiLeader leader;
        leader.init(numParties, threshold, leaderIdx,
                    allInputs[leaderIdx].size(), allInputs[leaderIdx].size(), true);
        leader.setKeys(pk, sks[leaderIdx]);

        std::vector<mpsi::Channel*> chls;
        for (uint64_t i = 0; i < numMembers; i++)
            chls.push_back(leader_to_member[i].get());

        intersection_result = leader.run(allInputs[leaderIdx], chls);
    });

    // Member threads
    std::vector<std::thread> member_threads;
    for (uint64_t m = 0; m < numMembers; m++) {
        member_threads.emplace_back([&, m]() {
            OtMpsiMember member;
            member.init(numParties, threshold, m,
                        allInputs[m].size(), allInputs[leaderIdx].size(), true);
            member.setKeys(pk, sks[m]);

            mpsi::Channel* ch_prev = (m > 0) ? ring_recv[m - 1].get() : nullptr;
            mpsi::Channel* ch_next = (m + 1 < numMembers) ? ring_send[m].get() : nullptr;
            std::vector<mpsi::Channel*> chls = {member_to_leader[m].get(), ch_prev, ch_next};
            member.run(allInputs[m], chls);
        });
    }

    leader_thread.join();
    for (auto& t : member_threads)
        t.join();

    std::set<uint64_t> result;
    for (const auto& elem : intersection_result) {
        uint64_t val = 0;
        std::memcpy(&val, elem.data(), sizeof(val));
        result.insert(val);
    }
    return result;
}

// Test 1: Equal set sizes, full threshold
// Party 0: {1, 2, 3, 4}  Party 1: {2, 3, 4, 5}  Party 2: {3, 4, 5, 6}
// Threshold=3 => intersection = {3, 4}
static bool testEqualSizes() {
    std::cout << "\n=== Test 1: Equal set sizes, threshold=3 ===" << std::endl;

    const uint64_t numParties = 3;
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    std::vector<std::vector<Element>> inputs = {
        {makeElement(1), makeElement(2), makeElement(3), makeElement(4)},
        {makeElement(2), makeElement(3), makeElement(4), makeElement(5)},
        {makeElement(3), makeElement(4), makeElement(5), makeElement(6)},
    };

    auto result = runProtocol(numParties, 3, inputs, pk, sks);
    std::set<uint64_t> expected = {3, 4};

    std::cout << "Intersection: {";
    for (auto v : result) std::cout << v << ", ";
    std::cout << "}" << std::endl;

    if (result == expected) {
        std::cout << "TEST 1 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 1 FAILED" << std::endl;
    return false;
}

// Test 2: Variable set sizes (tests set size negotiation)
// Party 0: {1, 2, 3}        (3 elements)
// Party 1: {2, 3, 4, 5, 6}  (5 elements)
// Party 2: {3, 4, 5, 6}     (4 elements, leader)
// Threshold=3 => intersection = {3} (only 3 is in all 3 parties)
static bool testVariableSizes() {
    std::cout << "\n=== Test 2: Variable set sizes, threshold=3 ===" << std::endl;

    const uint64_t numParties = 3;
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    std::vector<std::vector<Element>> inputs = {
        {makeElement(1), makeElement(2), makeElement(3)},
        {makeElement(2), makeElement(3), makeElement(4), makeElement(5), makeElement(6)},
        {makeElement(3), makeElement(4), makeElement(5), makeElement(6)},
    };

    auto result = runProtocol(numParties, 3, inputs, pk, sks);
    std::set<uint64_t> expected = {3};

    std::cout << "Intersection: {";
    for (auto v : result) std::cout << v << ", ";
    std::cout << "}" << std::endl;

    if (result == expected) {
        std::cout << "TEST 2 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 2 FAILED" << std::endl;
    return false;
}

// Test 3: Threshold < numParties (t=2, n=3)
// Party 0: {1, 2, 3, 4}  Party 1: {2, 3, 4, 5}  Party 2: {3, 4, 5, 6}
// Threshold=2 => elements in >=2 parties that are in leader's set = {3, 4, 5}
static bool testThresholdLessThanN() {
    std::cout << "\n=== Test 3: Threshold=2, n=3 ===" << std::endl;

    const uint64_t numParties = 3;
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    std::vector<std::vector<Element>> inputs = {
        {makeElement(1), makeElement(2), makeElement(3), makeElement(4)},
        {makeElement(2), makeElement(3), makeElement(4), makeElement(5)},
        {makeElement(3), makeElement(4), makeElement(5), makeElement(6)},
    };

    auto result = runProtocol(numParties, 2, inputs, pk, sks);
    // threshold-1 = 1 members needed (besides leader). Elements 3,4 are in all 3.
    // Element 5 is in party 1 and leader (2 parties). Element 6 is only in leader.
    // Element 2 is in party 0 and 1 but NOT leader, so not in result.
    // With threshold=2: leader needs element to be in >= 1 other party.
    // 3: in p0, p1 => >=1 member => YES
    // 4: in p0, p1 => >=1 member => YES
    // 5: in p1 => >=1 member => YES
    // 6: in nobody else => NO
    std::set<uint64_t> expected = {3, 4, 5};

    std::cout << "Intersection: {";
    for (auto v : result) std::cout << v << ", ";
    std::cout << "}" << std::endl;

    if (result == expected) {
        std::cout << "TEST 3 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 3 FAILED" << std::endl;
    return false;
}

// Test 4: Empty intersection (no element meets the threshold)
// Party 0: {1, 2}  Party 1: {3, 4}  Party 2: {5, 6}
// Threshold=3 => no element in all 3 => intersection = {}
static bool testEmptyIntersection() {
    std::cout << "\n=== Test 4: Empty intersection, threshold=3 ===" << std::endl;

    const uint64_t numParties = 3;
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    std::vector<std::vector<Element>> inputs = {
        {makeElement(1), makeElement(2)},
        {makeElement(3), makeElement(4)},
        {makeElement(5), makeElement(6)},
    };

    auto result = runProtocol(numParties, 3, inputs, pk, sks);
    std::set<uint64_t> expected = {};

    std::cout << "Intersection: {";
    for (auto v : result) std::cout << v << ", ";
    std::cout << "}" << std::endl;

    if (result == expected) {
        std::cout << "TEST 4 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 4 FAILED" << std::endl;
    return false;
}

// Test 5: Four parties, full threshold
// Party 0: {1, 2, 3, 5}  Party 1: {2, 3, 4, 5}  Party 2: {3, 5, 6, 7}  Party 3: {3, 5, 8, 9}
// Threshold=4 => elements in all 4 = {3, 5}
static bool testFourParties() {
    std::cout << "\n=== Test 5: Four parties, threshold=4 ===" << std::endl;

    const uint64_t numParties = 4;
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    std::vector<std::vector<Element>> inputs = {
        {makeElement(1), makeElement(2), makeElement(3), makeElement(5)},
        {makeElement(2), makeElement(3), makeElement(4), makeElement(5)},
        {makeElement(3), makeElement(5), makeElement(6), makeElement(7)},
        {makeElement(3), makeElement(5), makeElement(8), makeElement(9)},
    };

    auto result = runProtocol(numParties, 4, inputs, pk, sks);
    std::set<uint64_t> expected = {3, 5};

    std::cout << "Intersection: {";
    for (auto v : result) std::cout << v << ", ";
    std::cout << "}" << std::endl;

    if (result == expected) {
        std::cout << "TEST 5 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 5 FAILED" << std::endl;
    return false;
}

// Test 6: Single element sets, all share same element
// Party 0: {42}  Party 1: {42}  Party 2: {42}
// Threshold=3 => intersection = {42}
static bool testSingleElementSets() {
    std::cout << "\n=== Test 6: Single element sets ===" << std::endl;

    const uint64_t numParties = 3;
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    std::vector<std::vector<Element>> inputs = {
        {makeElement(42)},
        {makeElement(42)},
        {makeElement(42)},
    };

    auto result = runProtocol(numParties, 3, inputs, pk, sks);
    std::set<uint64_t> expected = {42};

    std::cout << "Intersection: {";
    for (auto v : result) std::cout << v << ", ";
    std::cout << "}" << std::endl;

    if (result == expected) {
        std::cout << "TEST 6 PASSED" << std::endl;
        return true;
    }
    std::cerr << "TEST 6 FAILED" << std::endl;
    return false;
}

int main() {
    std::cout << "=== BEH21 OT-MPSI In-Process Integration Tests ===" << std::endl;
    Logger::getInstance().setEnabled(true);

    bool allPassed = true;
    allPassed &= testEqualSizes();
    allPassed &= testVariableSizes();
    allPassed &= testThresholdLessThanN();
    allPassed &= testEmptyIntersection();
    allPassed &= testFourParties();
    allPassed &= testSingleElementSets();

    std::cout << "\n=== Summary ===" << std::endl;
    if (allPassed) {
        std::cout << "ALL TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << "SOME TESTS FAILED" << std::endl;
        return 1;
    }
}
