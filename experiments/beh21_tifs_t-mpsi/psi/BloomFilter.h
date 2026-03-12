#pragma once

#include <vector>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include "MurmurHash3.h"
#include "Defines.h"

/// Compute a 64-bit MurmurHash3 of a 16-byte block using the given seed.
inline u64 murmurHash(const block &element, u32 seed)
{
    u64 out[2] = {0, 0};
    MurmurHash3_x86_128(
        element.data(), // raw bytes (16 bytes)
        16,
        seed,
        out);
    return out[0];
}

class BloomFilter
{
public:
    // numBits = total bits; seeds = hash seeds
    BloomFilter(size_t numBits, const std::vector<u32> &seeds) : mSize(numBits),
                                                                 mSeeds(seeds)
    {
        if (numBits == 0 || mSeeds.empty())
            throw std::invalid_argument("BloomFilter: numBits > 0 and seeds non-empty");
        // Calculate number of 64-bit words needed
        size_t numWords = (mSize + BitsPerWord - 1) / BitsPerWord;
        mData.resize(numWords, 0);
    }

    // Compute optimal m (bits) and k (#hashes) from n and false-positive rate P
    static void optimalParams(size_t inputSize, size_t &numBits, size_t &numHash)
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

    void add(const block &element)
    {
        for (u32 seed : mSeeds)
        {
            u64 h = murmurHash(element, seed);
            size_t idx = static_cast<size_t>(h % mSize);
            set(idx);
        }
    }

    void remove(const block & /*element*/)
    {
        throw std::logic_error("BloomFilter::remove not supported");
    }

    bool contains(const block &element) const
    {
        for (u32 seed : mSeeds)
        {
            u64 h = murmurHash(element, seed);
            size_t idx = static_cast<size_t>(h % mSize);
            if (!(*this)[idx])
                return false;
        }
        return true;
    }

    const std::vector<u32> &seeds() const { return mSeeds; }

    // Get the size (number of bits) of the Bloom filter
    size_t size() const { return mSize; }

    // Get the raw data (for encryption/serialization)
    const std::vector<u64> &data() const { return mData; }
    std::vector<u64> &data() { return mData; }

    // Set a bit at the given index
    void set(size_t idx)
    {
        if (idx >= mSize)
            throw std::out_of_range("BloomFilter::set index out of range");
        size_t wordIdx = idx / BitsPerWord;
        size_t bitIdx = idx % BitsPerWord;
        mData[wordIdx] |= (1ULL << bitIdx);
    }

    // Get a bit at the given index
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
    std::vector<u32> mSeeds; // hashing seeds
    std::vector<u64> mData;
    static constexpr size_t BitsPerWord = 64;
};