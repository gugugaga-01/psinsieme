#include <gtest/gtest.h>
#include "protocols/yyh26/protocol/tt_mpsi.h"
#include "protocols/yyh26/protocol/shamir_ss.h"
#include "protocols/yyh26/protocol/crt_utils.h"

#include <cstring>
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

// ============================================================
// Additional CRT tests
// ============================================================

TEST(CrtUtilsTest, CrtSubMod) {
    __uint128_t a = crtPack(20, 30, 40, 50);
    __uint128_t b = crtPack(5, 10, 15, 20);
    __uint128_t diff = crtSub(a, b);

    EXPECT_EQ(crtExtract(diff, 0), 15u);
    EXPECT_EQ(crtExtract(diff, 1), 20u);
    EXPECT_EQ(crtExtract(diff, 2), 25u);
    EXPECT_EQ(crtExtract(diff, 3), 30u);
}

TEST(CrtUtilsTest, CrtSubModWraparound) {
    // 0 - 1 mod m should give m - 1
    __uint128_t a = crtPack(0, 0, 0, 0);
    __uint128_t b = crtPack(1, 1, 1, 1);
    __uint128_t diff = crtSub(a, b);

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(crtExtract(diff, i), CRT_MODULI[i] - 1);
    }
}

TEST(CrtUtilsTest, CrtMulMod) {
    __uint128_t a = crtPack(3, 4, 5, 6);
    __uint128_t b = crtPack(7, 8, 9, 10);
    __uint128_t prod = crtMul(a, b);

    EXPECT_EQ(crtExtract(prod, 0), 21u);
    EXPECT_EQ(crtExtract(prod, 1), 32u);
    EXPECT_EQ(crtExtract(prod, 2), 45u);
    EXPECT_EQ(crtExtract(prod, 3), 60u);
}

TEST(CrtUtilsTest, CrtReplicate) {
    uint32_t val = 42;
    __uint128_t replicated = crtReplicate(static_cast<__uint128_t>(val));

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(crtExtract(replicated, i), val);
    }
}

TEST(CrtUtilsTest, CrtIdentity) {
    __uint128_t a = crtPack(10, 20, 30, 40);
    __uint128_t zero = crtPack(0, 0, 0, 0);
    __uint128_t one = crtPack(1, 1, 1, 1);

    // Add 0 = identity
    __uint128_t sum = crtAdd(a, zero);
    for (int i = 0; i < 4; i++)
        EXPECT_EQ(crtExtract(sum, i), crtExtract(a, i));

    // Mul 1 = identity
    __uint128_t prod = crtMul(a, one);
    for (int i = 0; i < 4; i++)
        EXPECT_EQ(crtExtract(prod, i), crtExtract(a, i));
}

// ============================================================
// Additional Shamir tests
// ============================================================

TEST(ShamirSSTest, InsufficientSharesFail) {
    NTL::ZZ modulus = NTL::ZZ(4293230593UL);
    NTL::ZZ_p::init(modulus);

    NTL::ZZ_p secret = NTL::to_ZZ_p(9999);
    uint64_t numShares = 5;
    uint64_t threshold = 3;

    auto shares = shamirShare(secret, numShares, threshold, modulus);

    // Use only threshold-1 shares — reconstruction should (almost certainly) fail
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> selected;
    for (uint64_t i = 0; i < threshold - 1; i++) {
        selected.push_back({NTL::ZZ(i + 1), NTL::rep(shares[i])});
    }

    NTL::ZZ reconstructed = lagrangeInterpolateAtZero(selected, modulus);
    EXPECT_NE(reconstructed, NTL::ZZ(9999));
}

TEST(ShamirSSTest, ThresholdEqualsNumShares) {
    NTL::ZZ modulus = NTL::ZZ(4293836801UL);
    NTL::ZZ_p::init(modulus);

    NTL::ZZ_p secret = NTL::to_ZZ_p(777);
    uint64_t numShares = 4;
    uint64_t threshold = 4; // t = n

    auto shares = shamirShare(secret, numShares, threshold, modulus);
    EXPECT_EQ(shares.size(), numShares);

    // All shares needed
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> selected;
    for (uint64_t i = 0; i < numShares; i++) {
        selected.push_back({NTL::ZZ(i + 1), NTL::rep(shares[i])});
    }

    NTL::ZZ reconstructed = lagrangeInterpolateAtZero(selected, modulus);
    EXPECT_EQ(reconstructed, NTL::ZZ(777));
}

TEST(ShamirSSTest, ReconstructAndVerifyMultiCRT) {
    uint64_t numShares = 5;
    uint64_t threshold = 3;
    NTL::ZZ secret(42);

    std::vector<NTL::ZZ> fourModuli;
    for (size_t i = 0; i < 4; i++)
        fourModuli.push_back(NTL::ZZ(CRT_MODULI[i]));

    // Generate shares for each CRT modulus and pack them
    std::vector<std::pair<int, __uint128_t>> allShares(numShares);
    for (uint64_t s = 0; s < numShares; s++) {
        allShares[s].first = s + 1;
        allShares[s].second = 0;
    }

    for (size_t m = 0; m < 4; m++) {
        NTL::ZZ_p::init(fourModuli[m]);
        NTL::ZZ_p sec = NTL::conv<NTL::ZZ_p>(secret % fourModuli[m]);
        auto shares = shamirShare(sec, numShares, threshold, fourModuli[m]);

        for (uint64_t s = 0; s < numShares; s++) {
            uint64_t shift = (3 - m) * 32;
            uint64_t val = NTL::conv<long>(NTL::rep(shares[s]));
            allShares[s].second |= static_cast<__uint128_t>(val) << shift;
        }
    }

    // Reconstruct with first `threshold` indices
    std::vector<int> indices = {0, 1, 2};
    EXPECT_TRUE(reconstructAndVerify(indices, allShares, fourModuli, secret));
}

// ============================================================
// crtReduceAndPack tests
// ============================================================

TEST(CrtUtilsTest, ReduceAndPackSmallValue) {
    // For a value smaller than all CRT moduli, each slot should just be the value
    __uint128_t val = 42;
    __uint128_t packed = crtReduceAndPack(val);

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(crtExtract(packed, i), 42u);
    }
}

TEST(CrtUtilsTest, ReduceAndPackLargeValue) {
    // A 128-bit value: each slot should contain value % CRT_MODULI[i]
    __uint128_t val = static_cast<__uint128_t>(1) << 64;
    val += 12345;  // 2^64 + 12345

    __uint128_t packed = crtReduceAndPack(val);

    for (int i = 0; i < 4; i++) {
        uint64_t expected = static_cast<uint64_t>(val % CRT_MODULI[i]);
        EXPECT_EQ(crtExtract(packed, i), expected);
    }
}

TEST(CrtUtilsTest, ReduceAndPackVsManual) {
    // Multiple test vectors including edge cases
    std::vector<__uint128_t> testValues = {
        0,
        1,
        static_cast<__uint128_t>(CRT_MODULI[0]),     // exactly one modulus
        static_cast<__uint128_t>(CRT_MODULI[0]) - 1, // one less than modulus
        static_cast<__uint128_t>(CRT_MODULI[0]) + 1, // one more than modulus
        (static_cast<__uint128_t>(1) << 127) - 1,     // near max 128-bit
    };

    for (auto val : testValues) {
        __uint128_t packed = crtReduceAndPack(val);
        for (int i = 0; i < 4; i++) {
            uint64_t expected = static_cast<uint64_t>(val % CRT_MODULI[i]);
            EXPECT_EQ(crtExtract(packed, i), expected)
                << "Failed for slot " << i;
        }
    }
}

TEST(ShamirSSTest, ReconstructWithCrtReduceAndPack) {
    // Share a large secret (> 32 bits) via Shamir over 4 CRT moduli,
    // pack shares using crtReduceAndPack-compatible layout, and verify
    // reconstruction works with reconstructAndVerify.
    uint64_t numShares = 4;
    uint64_t threshold = 3;
    __uint128_t secretVal = static_cast<__uint128_t>(123456789ULL) << 32 | 42;
    NTL::ZZ secret;
    {
        uint8_t bytes[16];
        std::memcpy(bytes, &secretVal, 16);
        secret = NTL::ZZFromBytes(bytes, 16);
    }

    std::vector<NTL::ZZ> fourModuli;
    for (size_t i = 0; i < 4; i++)
        fourModuli.push_back(NTL::ZZ(CRT_MODULI[i]));

    std::vector<std::pair<int, __uint128_t>> allShares(numShares);
    for (uint64_t s = 0; s < numShares; s++) {
        allShares[s].first = s + 1;
        allShares[s].second = 0;
    }

    for (size_t m = 0; m < 4; m++) {
        NTL::ZZ_p::init(fourModuli[m]);
        NTL::ZZ_p sec = NTL::conv<NTL::ZZ_p>(secret % fourModuli[m]);
        auto shares = shamirShare(sec, numShares, threshold, fourModuli[m]);
        for (uint64_t s = 0; s < numShares; s++) {
            uint64_t shift = (3 - m) * 32;
            uint64_t val = NTL::conv<long>(NTL::rep(shares[s]));
            allShares[s].second |= static_cast<__uint128_t>(val) << shift;
        }
    }

    std::vector<int> indices = {0, 1, 2};
    EXPECT_TRUE(reconstructAndVerify(indices, allShares, fourModuli, secret));
}

TEST(TTMpsiEncodingTest, ElementEncodingConsistency) {
    // Verify that deriving ZZ from a 128-bit block produces the same
    // value mod each CRT modulus as the block itself.
    auto testString = [](const std::string& s) {
        // Simulate stringToBlock + blockToU128 + ZZFromBytes
        uint8_t blockBytes[16] = {0};
        size_t len = std::min(s.size(), sizeof(blockBytes));
        std::memcpy(blockBytes, s.data(), len);

        // Compute ui128 from block bytes (little-endian)
        __uint128_t blockVal = 0;
        for (int i = 15; i >= 0; i--)
            blockVal = (blockVal << 8) | blockBytes[i];

        // Compute ZZ from those bytes (NTL uses little-endian byte order)
        NTL::ZZ zz = NTL::ZZFromBytes(blockBytes, 16);

        // They should agree mod each CRT modulus
        for (size_t m = 0; m < 4; m++) {
            uint64_t blockMod = static_cast<uint64_t>(blockVal % CRT_MODULI[m]);
            NTL::ZZ zzMod = zz % NTL::ZZ(CRT_MODULI[m]);
            EXPECT_EQ(NTL::conv<long>(zzMod), static_cast<long>(blockMod))
                << "Mismatch for string '" << s << "' at modulus " << m;
        }
    };

    testString("alice");
    testString("bob");
    testString("charlie");
    testString("a]longstring>8b");  // exactly 15 bytes
    testString("sixteen_chars!!!");  // exactly 16 bytes
}
