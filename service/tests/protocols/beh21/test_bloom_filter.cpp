#include <gtest/gtest.h>
#include <cstring>
#include "protocols/beh21/crypto/bloom_filter.h"

using namespace mpsi::beh21;

static Element makeElement(uint64_t val) {
    Element e{};
    std::memcpy(e.data(), &val, sizeof(val));
    return e;
}

TEST(BloomFilterTest, OptimalParams) {
    size_t numBits, numHash;
    BloomFilter::optimalParams(100, numBits, numHash);
    // For n=100, p=0.0009: m ~ 1437 bits, k ~ 10
    EXPECT_GT(numBits, 1000u);
    EXPECT_GT(numHash, 5u);
    EXPECT_LT(numHash, 20u);
}

TEST(BloomFilterTest, InsertAndContains) {
    size_t numBits, numHash;
    BloomFilter::optimalParams(10, numBits, numHash);

    std::vector<uint32_t> seeds(numHash);
    for (size_t i = 0; i < numHash; ++i)
        seeds[i] = static_cast<uint32_t>(i + 1);

    BloomFilter bf(numBits, seeds);

    Element e1 = makeElement(42);
    Element e2 = makeElement(99);
    Element e3 = makeElement(123);

    bf.add(e1);
    bf.add(e2);

    EXPECT_TRUE(bf.contains(e1));
    EXPECT_TRUE(bf.contains(e2));
    // e3 not inserted — may or may not be a false positive, but very unlikely
    // with a properly-sized filter for 10 elements and only 2 inserted
}

TEST(BloomFilterTest, EmptyFilterContainsNothing) {
    std::vector<uint32_t> seeds = {1, 2, 3};
    BloomFilter bf(1000, seeds);

    Element e = makeElement(42);
    EXPECT_FALSE(bf.contains(e));
}

TEST(BloomFilterTest, SetAndGetBit) {
    std::vector<uint32_t> seeds = {1};
    BloomFilter bf(128, seeds);

    EXPECT_FALSE(bf[0]);
    EXPECT_FALSE(bf[63]);
    EXPECT_FALSE(bf[64]);
    EXPECT_FALSE(bf[127]);

    bf.set(0);
    bf.set(63);
    bf.set(64);
    bf.set(127);

    EXPECT_TRUE(bf[0]);
    EXPECT_TRUE(bf[63]);
    EXPECT_TRUE(bf[64]);
    EXPECT_TRUE(bf[127]);
    EXPECT_FALSE(bf[1]);
}

TEST(BloomFilterTest, OutOfRangeThrows) {
    std::vector<uint32_t> seeds = {1};
    BloomFilter bf(64, seeds);

    EXPECT_THROW(bf.set(64), std::out_of_range);
    EXPECT_THROW(bf[64], std::out_of_range);
}

TEST(BloomFilterTest, InvalidConstructorThrows) {
    std::vector<uint32_t> seeds = {1};
    EXPECT_THROW(BloomFilter(0, seeds), std::invalid_argument);

    std::vector<uint32_t> empty_seeds;
    EXPECT_THROW(BloomFilter(100, empty_seeds), std::invalid_argument);
}

TEST(BloomFilterTest, MurmurHashDeterministic) {
    Element e = makeElement(42);
    uint64_t h1 = murmurHash(e, 1);
    uint64_t h2 = murmurHash(e, 1);
    EXPECT_EQ(h1, h2);

    // Different seeds should produce different hashes (with overwhelming probability)
    uint64_t h3 = murmurHash(e, 2);
    EXPECT_NE(h1, h3);
}

TEST(BloomFilterTest, MurmurHashDifferentElements) {
    Element e1 = makeElement(1);
    Element e2 = makeElement(2);
    uint64_t h1 = murmurHash(e1, 42);
    uint64_t h2 = murmurHash(e2, 42);
    EXPECT_NE(h1, h2);
}
