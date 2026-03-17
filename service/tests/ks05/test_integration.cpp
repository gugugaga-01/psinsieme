#include <iostream>
#include <vector>
#include <thread>
#include <cassert>
#include <set>

#include "core/transport/in_process_channel.h"
#include "protocols/ks05/protocol/t_mpsi.h"
#include "protocols/ks05/crypto/paillier.h"
#include "protocols/ks05/protocol/logger.h"

using namespace mpsi::ks05;

// Run a 3-party T-MPSI test with small sets.
// Party 0 (member): {1, 2, 3, 4}
// Party 1 (member): {2, 3, 4, 5}
// Party 2 (leader): {3, 4, 5, 6}
// Threshold = 2: elements in >= 2 parties = {2, 3, 4, 5}
// Threshold = 3: elements in all 3 parties = {3, 4}
// We test with threshold=3 (full intersection) for simplicity.
int main() {
    std::cout << "=== KS05 T-MPSI In-Process Integration Test ===" << std::endl;

    const u64 numParties = 3;
    const u64 threshold = 3;
    const u64 senderSize = 4; // member set size
    const u64 recverSize = 4; // leader set size

    // Enable debug logging
    Logger::getInstance().setEnabled(true);

    // Generate keys via trusted dealer model
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    // Create channel pairs:
    // Member 0 <-> Leader (channels[0] for member0, channels[0] for leader)
    // Member 1 <-> Leader (channels[0] for member1, channels[1] for leader)
    // Member 0 -> Member 1 (channels[2] for member0, channels[1] for member1)

    auto [m0_leader_ch, leader_m0_ch] = mpsi::InProcessChannel::createPair();
    auto [m1_leader_ch, leader_m1_ch] = mpsi::InProcessChannel::createPair();
    auto [m0_to_m1_ch, m1_from_m0_ch] = mpsi::InProcessChannel::createPair();

    // Prepare inputs as ZZ values
    // Party 0 (member): {1, 2, 3, 4}
    std::vector<ZZ> inputs_p0 = {NTL::to_ZZ(1), NTL::to_ZZ(2), NTL::to_ZZ(3), NTL::to_ZZ(4)};
    // Party 1 (member): {2, 3, 4, 5}
    std::vector<ZZ> inputs_p1 = {NTL::to_ZZ(2), NTL::to_ZZ(3), NTL::to_ZZ(4), NTL::to_ZZ(5)};
    // Party 2 (leader): {3, 4, 5, 6}
    std::vector<ZZ> inputs_p2 = {NTL::to_ZZ(3), NTL::to_ZZ(4), NTL::to_ZZ(5), NTL::to_ZZ(6)};

    std::vector<ZZ> intersection_result;

    // Run all 3 parties in separate threads
    std::thread leader_thread([&]() {
        TMpsiLeader leader;
        leader.init(numParties, threshold, 2, senderSize, recverSize, true);
        leader.setKeys(pk, sks[2]);

        // Leader channels: [0]=member0, [1]=member1
        std::vector<mpsi::Channel*> chls = {leader_m0_ch.get(), leader_m1_ch.get()};
        intersection_result = leader.run(inputs_p2, chls);
    });

    std::thread member0_thread([&]() {
        TMpsiMember member0;
        member0.init(numParties, threshold, 0, senderSize, recverSize, true);
        member0.setKeys(pk, sks[0]);

        // Member 0 channels: [0]=leader, [2]=next(member1)
        // Member 0 is first in ring: receives from leader (chl[0]), sends to member1 (chl[2])
        // No prev member for P0, so channels[1] is unused
        std::vector<mpsi::Channel*> chls = {m0_leader_ch.get(), nullptr, m0_to_m1_ch.get()};
        member0.run(inputs_p0, chls);
    });

    std::thread member1_thread([&]() {
        TMpsiMember member1;
        member1.init(numParties, threshold, 1, senderSize, recverSize, true);
        member1.setKeys(pk, sks[1]);

        // Member 1 channels: [0]=leader, [1]=prev(member0)
        // Member 1 is last in ring: receives from member0 (chl[1]), sends to leader (chl[0])
        // No next member for Pn-2, so channels[2] is unused
        std::vector<mpsi::Channel*> chls = {m1_leader_ch.get(), m1_from_m0_ch.get(), nullptr};
        member1.run(inputs_p1, chls);
    });

    leader_thread.join();
    member0_thread.join();
    member1_thread.join();

    // Verify results
    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "Intersection size: " << intersection_result.size() << std::endl;

    std::set<long> result_set;
    for (const auto& v : intersection_result) {
        long val = NTL::to_long(v);
        result_set.insert(val);
        std::cout << "  Element: " << val << std::endl;
    }

    // Expected intersection with threshold=3: {3, 4}
    std::set<long> expected = {3, 4};

    if (result_set == expected) {
        std::cout << "\nTEST PASSED: Intersection matches expected {3, 4}" << std::endl;
        return 0;
    } else {
        std::cerr << "\nTEST FAILED: Expected {3, 4}, got {";
        for (auto v : result_set) std::cerr << v << ", ";
        std::cerr << "}" << std::endl;
        return 1;
    }
}
