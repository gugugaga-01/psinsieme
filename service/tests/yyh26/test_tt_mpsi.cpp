#include <gtest/gtest.h>
#include "yyh26_tt_mpsi/protocol/tt_mpsi.h"
#include "yyh26_tt_mpsi/protocol/shamir_ss.h"
#include "yyh26_tt_mpsi/protocol/crt_utils.h"

#include <string>
#include <vector>

using namespace mpsi::yyh26;

// ============================================================
// Unit tests for TTMpsiConfig
// ============================================================

TEST(TTMpsiConfigTest, DefaultValues) {
    TTMpsiConfig config;
    EXPECT_EQ(config.tcpBasePort, 1100u);
    EXPECT_TRUE(config.partyHostnames.empty());
}

TEST(TTMpsiConfigTest, GetHostnameDefault) {
    TTMpsiConfig config;
    EXPECT_EQ(config.getHostname(0), "localhost");
    EXPECT_EQ(config.getHostname(99), "localhost");
}

TEST(TTMpsiConfigTest, GetHostnameConfigured) {
    TTMpsiConfig config;
    config.partyHostnames[0] = "10.0.0.1";
    config.partyHostnames[1] = "10.0.0.2";

    EXPECT_EQ(config.getHostname(0), "10.0.0.1");
    EXPECT_EQ(config.getHostname(1), "10.0.0.2");
    EXPECT_EQ(config.getHostname(2), "localhost"); // not configured -> default
}

// ============================================================
// Unit tests for TTMpsiLeader/TTMpsiMember init
// ============================================================

TEST(TTMpsiLeaderTest, InitSetsConfig) {
    TTMpsiConfig config;
    config.numParties = 5;
    config.threshold = 3;
    config.partyID = 4;
    config.tcpBasePort = 12000;

    TTMpsiLeader leader;
    EXPECT_NO_THROW(leader.init(config));
}

TEST(TTMpsiMemberTest, InitSetsConfig) {
    TTMpsiConfig config;
    config.numParties = 5;
    config.threshold = 3;
    config.partyID = 1;

    TTMpsiMember member;
    EXPECT_NO_THROW(member.init(config));
}

// ============================================================
// Unit tests for CRT utilities
// ============================================================

TEST(CrtUtilsTest, PackUnpack) {
    std::array<uint32_t, 4> residues = {100, 200, 300, 400};
    __uint128_t packed = crtPack(residues[0], residues[1], residues[2], residues[3]);

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(crtExtract(packed, i), residues[i]);
    }
}

TEST(CrtUtilsTest, PackZero) {
    __uint128_t packed = crtPack(0, 0, 0, 0);
    EXPECT_EQ(packed, static_cast<__uint128_t>(0));
}

TEST(CrtUtilsTest, CrtAddMod) {
    // Add within each CRT modulus
    __uint128_t a = crtPack(10, 20, 30, 40);
    __uint128_t b = crtPack(5, 15, 25, 35);
    __uint128_t sum = crtAdd(a, b);

    EXPECT_EQ(crtExtract(sum, 0), 15u);
    EXPECT_EQ(crtExtract(sum, 1), 35u);
    EXPECT_EQ(crtExtract(sum, 2), 55u);
    EXPECT_EQ(crtExtract(sum, 3), 75u);
}

TEST(CrtUtilsTest, CrtAddModWraparound) {
    // Test wraparound: CRT_MODULI[3] = 4294475777
    uint32_t m3 = CRT_MODULI[3];
    __uint128_t a = crtPack(0, 0, 0, m3 - 1);
    __uint128_t b = crtPack(0, 0, 0, 2);
    __uint128_t sum = crtAdd(a, b);

    // (m3-1 + 2) mod m3 = 1
    EXPECT_EQ(crtExtract(sum, 3), 1u);
}

// ============================================================
// Unit tests for Shamir Secret Sharing
// ============================================================

TEST(ShamirSSTest, ShareAndReconstruct) {
    NTL::ZZ modulus = NTL::ZZ(4293230593UL); // CRT_MODULI[0]
    NTL::ZZ_p::init(modulus);

    NTL::ZZ_p secret = NTL::to_ZZ_p(42);
    uint64_t numShares = 5;
    uint64_t threshold = 3;

    auto shares = shamirShare(secret, numShares, threshold, modulus);
    EXPECT_EQ(shares.size(), numShares);

    // Reconstruct from first `threshold` shares
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> selected;
    for (uint64_t i = 0; i < threshold; i++) {
        selected.push_back({NTL::ZZ(i + 1), NTL::rep(shares[i])});
    }

    NTL::ZZ reconstructed = lagrangeInterpolateAtZero(selected, modulus);
    EXPECT_EQ(reconstructed, NTL::ZZ(42));
}

TEST(ShamirSSTest, ZeroSharing) {
    NTL::ZZ modulus = NTL::ZZ(4293836801UL); // CRT_MODULI[1]
    NTL::ZZ_p::init(modulus);

    uint64_t numShares = 4;
    uint64_t threshold = 3;

    auto values = generateUpdateValues(numShares, threshold, modulus);
    EXPECT_EQ(values.size(), numShares);

    // Reconstruct from any `threshold` shares should give 0
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> selected;
    for (uint64_t i = 0; i < threshold; i++) {
        selected.push_back({NTL::ZZ(i + 1), NTL::rep(values[i])});
    }

    NTL::ZZ reconstructed = lagrangeInterpolateAtZero(selected, modulus);
    EXPECT_EQ(reconstructed, NTL::ZZ(0));
}

TEST(ShamirSSTest, DifferentSubsetsReconstruct) {
    NTL::ZZ modulus = NTL::ZZ(4293918721UL); // CRT_MODULI[2]
    NTL::ZZ_p::init(modulus);

    NTL::ZZ_p secret = NTL::to_ZZ_p(12345);
    uint64_t numShares = 5;
    uint64_t threshold = 3;

    auto shares = shamirShare(secret, numShares, threshold, modulus);

    // Try all C(5,3) = 10 subsets
    auto combos = getCombinations(5, 3);
    EXPECT_EQ(combos.size(), 10u);

    for (const auto& combo : combos) {
        std::vector<std::pair<NTL::ZZ, NTL::ZZ>> selected;
        for (int idx : combo) {
            selected.push_back({NTL::ZZ(idx + 1), NTL::rep(shares[idx])});
        }
        NTL::ZZ reconstructed = lagrangeInterpolateAtZero(selected, modulus);
        EXPECT_EQ(reconstructed, NTL::ZZ(12345));
    }
}

// ============================================================
// getCombinations tests
// ============================================================

TEST(CombinationsTest, BasicCombinations) {
    auto combos = getCombinations(4, 2);
    EXPECT_EQ(combos.size(), 6u); // C(4,2) = 6
}

TEST(CombinationsTest, ChooseAll) {
    auto combos = getCombinations(3, 3);
    EXPECT_EQ(combos.size(), 1u); // C(3,3) = 1
    EXPECT_EQ(combos[0], (std::vector<int>{0, 1, 2}));
}

TEST(CombinationsTest, ChooseOne) {
    auto combos = getCombinations(4, 1);
    EXPECT_EQ(combos.size(), 4u); // C(4,1) = 4
}

// ============================================================
// Service dispatch test (compile-time only)
// ============================================================

TEST(TTMpsiDispatchTest, ProtocolNameMatches) {
    std::string expected = "yyh26_tt_mpsi";
    EXPECT_EQ(expected, "yyh26_tt_mpsi");
}
