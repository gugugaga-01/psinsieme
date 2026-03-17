#include <iostream>
#include <vector>
#include <thread>
#include <set>

#include "core/transport/in_process_channel.h"
#include "protocols/ks05/protocol/t_mpsi.h"
#include "protocols/ks05/crypto/paillier.h"
#include "protocols/ks05/protocol/logger.h"

using namespace mpsi::ks05;

// Test threshold MPSI with t < n.
//
// 3 parties, threshold = 2:
//   Party 0 (member): {1, 2, 3, 4}
//   Party 1 (member): {2, 3, 4, 5}
//   Party 2 (leader): {3, 4, 5, 6}
//
// Elements appearing in >= 2 parties:
//   2: P0, P1          (2 parties) yes
//   3: P0, P1, P2      (3 parties) yes
//   4: P0, P1, P2      (3 parties) yes
//   5: P1, P2           (2 parties) yes
//
// But the leader only checks their own elements {3, 4, 5, 6}.
// Elements in leader's set that appear in >= 2 parties: {3, 4, 5}
// (6 appears only in P2, so it's excluded)

int main() {
    std::cout << "=== KS05 Threshold MPSI Test (t=2, n=3) ===" << std::endl;

    const u64 numParties = 3;
    const u64 threshold = 2;
    const u64 setSize = 4;

    Logger::getInstance().setEnabled(true);

    // Generate keys via trusted dealer model
    NTL::SetSeed(NTL::to_ZZ(42UL));
    PubKey pk;
    std::vector<PrivKey> sks;
    distributedKeyGen(PAILLIER_KEY_BITS, numParties, pk, sks);

    auto [m0_leader_ch, leader_m0_ch] = mpsi::InProcessChannel::createPair();
    auto [m1_leader_ch, leader_m1_ch] = mpsi::InProcessChannel::createPair();
    auto [m0_to_m1_ch, m1_from_m0_ch] = mpsi::InProcessChannel::createPair();

    std::vector<ZZ> inputs_p0 = {NTL::to_ZZ(1), NTL::to_ZZ(2), NTL::to_ZZ(3), NTL::to_ZZ(4)};
    std::vector<ZZ> inputs_p1 = {NTL::to_ZZ(2), NTL::to_ZZ(3), NTL::to_ZZ(4), NTL::to_ZZ(5)};
    std::vector<ZZ> inputs_p2 = {NTL::to_ZZ(3), NTL::to_ZZ(4), NTL::to_ZZ(5), NTL::to_ZZ(6)};

    std::vector<ZZ> intersection_result;

    std::thread leader_thread([&]() {
        TMpsiLeader leader;
        leader.init(numParties, threshold, 2, setSize, setSize, true);
        leader.setKeys(pk, sks[2]);
        std::vector<mpsi::Channel*> chls = {leader_m0_ch.get(), leader_m1_ch.get()};
        intersection_result = leader.run(inputs_p2, chls);
    });

    std::thread member0_thread([&]() {
        TMpsiMember member0;
        member0.init(numParties, threshold, 0, setSize, setSize, true);
        member0.setKeys(pk, sks[0]);
        std::vector<mpsi::Channel*> chls = {m0_leader_ch.get(), nullptr, m0_to_m1_ch.get()};
        member0.run(inputs_p0, chls);
    });

    std::thread member1_thread([&]() {
        TMpsiMember member1;
        member1.init(numParties, threshold, 1, setSize, setSize, true);
        member1.setKeys(pk, sks[1]);
        std::vector<mpsi::Channel*> chls = {m1_leader_ch.get(), m1_from_m0_ch.get(), nullptr};
        member1.run(inputs_p1, chls);
    });

    leader_thread.join();
    member0_thread.join();
    member1_thread.join();

    std::cout << "\n=== Results ===" << std::endl;
    std::cout << "Intersection size: " << intersection_result.size() << std::endl;

    std::set<long> result_set;
    for (const auto& v : intersection_result) {
        long val = NTL::to_long(v);
        result_set.insert(val);
        std::cout << "  Element: " << val << std::endl;
    }

    // Leader's elements {3,4,5,6} that appear in >= 2 parties = {3,4,5}
    std::set<long> expected = {3, 4, 5};

    if (result_set == expected) {
        std::cout << "\nTEST PASSED: Threshold-2 intersection = {3, 4, 5}" << std::endl;
        return 0;
    } else {
        std::cerr << "\nTEST FAILED: Expected {3, 4, 5}, got {";
        for (auto v : result_set) std::cerr << v << ", ";
        std::cerr << "}" << std::endl;
        return 1;
    }
}
