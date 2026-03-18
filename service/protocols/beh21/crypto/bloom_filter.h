#pragma once

#include <vector>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <stdexcept>
#include "../third_party/smhasher/MurmurHash3.h"

namespace mpsi::beh21 {

using Element = std::array<uint8_t, 16>;

constexpr double FALSE_POSITIVE_RATE = 0.0009; // < 2^(-10)

inline uint64_t murmurHash(const Element& element, uint32_t seed)
{
    uint64_t out[2] = {0, 0};
    MurmurHash3_x86_128(
        element.data(),
        16,
        seed,
        out);
    return out[0];
}

class BloomFilter
{
public:
    BloomFilter(size_t numBits, const std::vector<uint32_t>& seeds) : mSize(numBits),
                                                                       mSeeds(seeds)
    {
        if (numBits == 0 || mSeeds.empty())
            throw std::invalid_argument("BloomFilter: numBits > 0 and seeds non-empty");
        size_t numWords = (mSize + BitsPerWord - 1) / BitsPerWord;
        mData.resize(numWords, 0);
    }

    static void optimalParams(size_t inputSize, size_t& numBits, size_t& numHash)
    {
        double n = static_cast<double>(inputSize);
        double p = FALSE_POSITIVE_RATE;
        double m = -(n * std::log(p)) / (std::log(2) * std::log(2));
        numBits = static_cast<size_t>(std::ceil(m));
        double k = (m / n) * std::log(2);
        numHash = static_cast<size_t>(std::ceil(k));
        if (numHash == 0)
            numHash = 1;
    }

    void add(const Element& element)
    {
        for (uint32_t seed : mSeeds)
        {
            uint64_t h = murmurHash(element, seed);
            size_t idx = static_cast<size_t>(h % mSize);
            set(idx);
        }
    }

    bool contains(const Element& element) const
    {
        for (uint32_t seed : mSeeds)
        {
            uint64_t h = murmurHash(element, seed);
            size_t idx = static_cast<size_t>(h % mSize);
            if (!(*this)[idx])
                return false;
        }
        return true;
    }

    const std::vector<uint32_t>& seeds() const { return mSeeds; }
    size_t size() const { return mSize; }
    const std::vector<uint64_t>& data() const { return mData; }
    std::vector<uint64_t>& data() { return mData; }

    void set(size_t idx)
    {
        if (idx >= mSize)
            throw std::out_of_range("BloomFilter::set index out of range");
        size_t wordIdx = idx / BitsPerWord;
        size_t bitIdx = idx % BitsPerWord;
        mData[wordIdx] |= (1ULL << bitIdx);
    }

    bool operator[](size_t idx) const
    {
        if (idx >= mSize)
            throw std::out_of_range("BloomFilter::operator[] index out of range");
        size_t wordIdx = idx / BitsPerWord;
        size_t bitIdx = idx % BitsPerWord;
        return (mData[wordIdx] & (1ULL << bitIdx)) != 0;
    }

private:
    size_t mSize;
    std::vector<uint32_t> mSeeds;
    std::vector<uint64_t> mData;
    static constexpr size_t BitsPerWord = 64;
};

} // namespace mpsi::beh21
