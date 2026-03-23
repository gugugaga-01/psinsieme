#include "bloom_filter.h"

#include "third_party/smhasher/MurmurHash3.h"

void BloomFilter::Insert(const ElementType &e) {
  uint64 hash[2];
  for (auto &seed : murmurhash_seeds_) {
    MurmurHash3_x86_128(&e, elementTypeWords, seed, hash);
    uint32 pos = hash[0] % size_;
    bit_array_[pos] = 1;
  }
}

bool BloomFilter::CheckElement(const ElementType &e) {
  for (auto &pos : GetPositions(e)) {
    if (bit_array_[pos] == 0) {
      return false;
    }
  }
  return true;
}

std::vector<uint32> BloomFilter::GetPositions(const ElementType &e) {
  std::vector<uint32> positions;
  uint64 hash[2];

  positions.reserve(murmurhash_seeds_.size());
  for (auto &seed : murmurhash_seeds_) {
    MurmurHash3_x86_128(&e, elementTypeWords, seed, &hash);
    uint32 pos = hash[0] % size_;
    positions.push_back(pos);
  }
  return positions;
}
