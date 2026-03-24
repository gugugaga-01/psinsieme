#ifndef OTMPSI_UTILS_BLOOMFILTER_H_
#define OTMPSI_UTILS_BLOOMFILTER_H_

#include <boost/dynamic_bitset.hpp>
#include <vector>
#include <array>
#include <cstring>
#include <sodium.h>

#include "common.h"

using ECpoint = std::array<unsigned char, crypto_core_ristretto255_BYTES>;
using Ciphertext = std::pair<ECpoint, ECpoint>;

class BloomFilter {
 public:
  BloomFilter() = delete;
  ~BloomFilter() = default;
  BloomFilter(const ContainerSizeType &size, const std::vector<uint32> &murmurhash_seeds)
      : size_(size), bit_array_(boost::dynamic_bitset<>(size)), murmurhash_seeds_(murmurhash_seeds){};

  [[nodiscard]] inline ContainerSizeType size() const;

  inline void Invert();
  inline void Clear();
  inline bool CheckPosition(const ContainerSizeType &pos);

  void Insert(const ElementType &e);
  bool CheckElement(const ElementType &e);
  std::vector<uint32> GetPositions(const ElementType &e);

 private:
  ContainerSizeType size_;                // size of the bloom filter
  boost::dynamic_bitset<> bit_array_;     // underlying bit array
  std::vector<uint32> murmurhash_seeds_;  // murmurhash seeds for hash functions
};

ContainerSizeType BloomFilter::size() const { return size_; }

bool BloomFilter::CheckPosition(const ContainerSizeType &pos) { return bit_array_[pos] == 1; }

void BloomFilter::Invert() { bit_array_.flip(0, size_); }

void BloomFilter::Clear() { bit_array_.reset(); }

#endif  // OTMPSI_UTILS_BLOOMFILTER_H_