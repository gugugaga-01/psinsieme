#include "protocols/xzh26/protocol/ec_mpsi.h"
#include "protocols/xzh26/crypto/point.h"
#include "protocols/xzh26/crypto/bloom_filter.h"
#include "protocols/xzh26/crypto/common.h"
#include "protocols/xzh26/protocol/channel_adapter.h"
#include "protocols/xzh26/protocol/OPPRFSender.h"
#include "protocols/xzh26/protocol/OPPRFReceiver.h"
#include "protocols/xzh26/protocol/binSet.h"

#include "Common/Defines.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"

#include <sodium.h>
#include <cmath>
#include <cstring>
#include <thread>
#include <iostream>
#include <vector>

using namespace osuCrypto;

namespace mpsi::xzh26 {

// Helper: send raw bytes over mpsi::Channel
static void sendPoint(mpsi::Channel* ch, const ECpoint& pt) {
    ch->sendBytes(std::string(reinterpret_cast<const char*>(pt.data()),
                               crypto_core_ristretto255_BYTES));
}

static void recvPoint(mpsi::Channel* ch, ECpoint& pt) {
    std::string data = ch->recvBytes();
    std::memcpy(pt.data(), data.data(), crypto_core_ristretto255_BYTES);
}

static ECpoint block_to_point(const block& input) {
    unsigned char block_bytes[16];
    std::memcpy(block_bytes, &input, 16);
    unsigned char hash_64bytes[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash_64bytes, block_bytes, 16);
    ECpoint result_point;
    crypto_core_ristretto255_from_hash(result_point.data(), hash_64bytes);
    return result_point;
}

static std::vector<ECpoint> setblock_to_points(const std::vector<block>& setBlock) {
    std::vector<ECpoint> points(setBlock.size());
    for (size_t i = 0; i < setBlock.size(); ++i)
        points[i] = block_to_point(setBlock[i]);
    return points;
}

static void Encrypt(Ciphertext& cipher, const ECpoint& plaintext, const ECpoint& B) {
    ECscalar r = scalar_random();
    cipher.first = scalar_mul_base(r);
    ECpoint temp = scalar_mul(r, B);
    cipher.second = point_add(temp, plaintext);
}

static void Homo_Add(Ciphertext& dest, const Ciphertext& src1, const Ciphertext& src2) {
    dest.first = point_add(src1.first, src2.first);
    dest.second = point_add(src1.second, src2.second);
}

static void PartialDecrypt(ECpoint& share, const ECpoint& c1, const ECscalar& a) {
    share = scalar_mul(scalar_negate(a), c1);
}

static void FullyDecrypt(ECpoint& plaintext, const std::vector<ECpoint>& shares, const ECpoint& c2) {
    plaintext = c2;
    for (const auto& share : shares)
        plaintext = point_add(plaintext, share);
}

static const std::vector<uint32_t> MURMURHASH_SEEDS = {
    1805253736, 397701183, 1495055303, 1012881222, 1442197113,
    899180298, 1148210001, 1954046069, 1587823014, 121110290
};

void EcMpsiBase::init(uint64_t numberOfParties, uint64_t threshold,
                       uint64_t partyID, uint64_t setSize, bool debug) {
    mNumberOfParties = numberOfParties;
    mThreshold = threshold;
    mPartyID = partyID;
    mSetSize = setSize;
    mDebug = debug;
}

// ======================= LEADER =======================

std::vector<Element> EcMpsiLeader::run(
    const std::vector<Element>& inputs,
    std::vector<mpsi::Channel*>& channels)
{
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");

    const uint64_t nParties = mNumberOfParties;
    const uint64_t setSize = inputs.size();
    const uint64_t leaderIdx = nParties - 1;
    const uint64_t psiSecParam = 40;
    const uint64_t opprfNum = 2;

    PRNG prng(_mm_set_epi32(4253465, 3434565, (int)mPartyID, (int)mPartyID));

    // === DKG ===
    ECscalar a = scalar_random();
    ECpoint betaPart = scalar_mul_base(a);
    ECpoint beta = betaPart;

    for (uint64_t pIdx = 0; pIdx < nParties - 1; pIdx++) {
        ECpoint other_share;
        recvPoint(channels[pIdx], other_share);
        beta = point_add(beta, other_share);
    }
    for (uint64_t pIdx = 0; pIdx < nParties - 1; pIdx++) {
        sendPoint(channels[pIdx], beta);
    }

    if (mDebug) std::cerr << "[Leader] DKG done" << std::endl;

    // === Bloom filter construction ===
    double false_positive_rate = 0.001;
    double m = -(setSize * std::log(false_positive_rate)) / (std::log(2) * std::log(2));
    uint32_t bf_size = std::ceil(m);

    BloomFilter bf(bf_size, MURMURHASH_SEEDS);
    bf.Clear();
    for (const auto& e : inputs) bf.Insert(e);

    std::vector<Ciphertext> encrypted_bloom_filter(bf.size());
    for (size_t i = 0; i < bf.size(); ++i) {
        if (!bf.CheckPosition(i))
            encrypted_bloom_filter[i] = std::make_pair(point_random(), point_random());
        else
            Encrypt(encrypted_bloom_filter[i], ZERO_POINT, beta);
    }

    if (mDebug) std::cerr << "[Leader] EBF built" << std::endl;

    // === Send EBF to all members ===
    for (uint64_t pIdx = 0; pIdx < nParties - 1; ++pIdx) {
        for (size_t i = 0; i < bf.size(); ++i) {
            sendPoint(channels[pIdx], encrypted_bloom_filter[i].first);
            sendPoint(channels[pIdx], encrypted_bloom_filter[i].second);
        }
    }

    if (mDebug) std::cerr << "[Leader] EBF sent" << std::endl;

    // === DH-OPRF ===
    std::vector<block> setBlock(setSize);
    for (size_t i = 0; i < setSize; i++) setBlock[i] = toBlock(inputs[i]);

    std::vector<ECpoint> hashedPoints = setblock_to_points(setBlock);

    // Generate blind factors and send blinded points
    std::vector<std::vector<ECscalar>> blindFactors(nParties - 1);
    for (uint64_t pIdx = 0; pIdx < nParties - 1; ++pIdx) {
        blindFactors[pIdx].resize(setSize);
        for (size_t i = 0; i < setSize; ++i) {
            blindFactors[pIdx][i] = scalar_random();
            ECpoint blinded = scalar_mul(blindFactors[pIdx][i], hashedPoints[i]);
            sendPoint(channels[pIdx], blinded);
        }
    }

    // Receive processed points from clients
    std::vector<std::vector<ECpoint>> processedPoints(nParties - 1);
    for (uint64_t pIdx = 0; pIdx < nParties - 1; ++pIdx) {
        processedPoints[pIdx].resize(setSize);
        for (size_t i = 0; i < setSize; ++i) {
            recvPoint(channels[pIdx], processedPoints[pIdx][i]);
        }
    }

    if (mDebug) std::cerr << "[Leader] DH-OPRF done" << std::endl;

    // === OPPRF setup ===
    binSet bins;
    bins.init(leaderIdx, nParties, setSize, psiSecParam);
    bins.hashing2Bins(setBlock, 1);

    std::vector<binSet> binSets;
    for (uint64_t i = 0; i < opprfNum; i++) binSets.push_back(bins);

    std::vector<OPPRFReceiver> recv(nParties * opprfNum);
    for (uint64_t pIdx = 0; pIdx < nParties - 1; pIdx++) {
        for (uint64_t opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++) {
            uint64_t index = pIdx * opprfNum + opprfIdx;
            // Create adapter channels for OPPRF
            std::vector<osuCrypto::Channel*> adaptedChls = { nullptr };
            recv[index].init(nParties, setSize, psiSecParam, adaptedChls, ZeroBlock);
        }
    }

    // Compute OPRF values and fill OPPRF tables
    for (uint64_t pIdx = 0; pIdx < nParties - 1; ++pIdx) {
        std::vector<ECpoint> myOPRFValues(setSize);
        for (size_t i = 0; i < setSize; ++i) {
            ECscalar inv_blind = scalar_invert(blindFactors[pIdx][i]);
            myOPRFValues[i] = scalar_mul(inv_blind, processedPoints[pIdx][i]);
        }
        uint64_t index = pIdx * opprfNum;
        recv[index].getOPRFkeysSeperatedandTable(pIdx, binSets[0], myOPRFValues);
        recv[index + 1].getOPRFkeysSeperatedandTable(pIdx, binSets[1], myOPRFValues);
    }

    if (mDebug) std::cerr << "[Leader] OPPRF keys done" << std::endl;

    // === OPPRF online: receive from members ===
    std::vector<std::vector<std::vector<ECpoint>>> totalData(nParties - 1);
    for (uint64_t pIdx = 0; pIdx < nParties - 1; pIdx++) {
        std::vector<std::vector<ECpoint>> recvTemp;
        for (uint64_t opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++) {
            uint64_t index = pIdx * opprfNum + opprfIdx;
            std::vector<ECpoint> recvPoint_vec(setSize);
            // Create adapter for OPPRF channel communication
            ChannelAdapter adapter(channels[pIdx]);
            std::vector<osuCrypto::Channel*> adaptedChls = { &adapter };
            recv[index].recvSSTableBased(pIdx, binSets[opprfIdx], recvPoint_vec, adaptedChls);
            recvTemp.push_back(recvPoint_vec);
        }
        totalData[pIdx] = recvTemp;
    }

    if (mDebug) std::cerr << "[Leader] OPPRF recv done" << std::endl;

    // === Aggregate ciphertexts ===
    std::vector<Ciphertext> recvResult(setSize);
    for (size_t i = 0; i < setSize; i++) {
        recvResult[i].first = ZERO_POINT;
        recvResult[i].second = ZERO_POINT;
    }

    for (uint64_t pIdx = 0; pIdx < nParties - 1; pIdx++) {
        for (uint64_t eIdx = 0; eIdx < setSize; eIdx++) {
            recvResult[eIdx].first = point_add(recvResult[eIdx].first, totalData[pIdx][0][eIdx]);
            recvResult[eIdx].second = point_add(recvResult[eIdx].second, totalData[pIdx][1][eIdx]);
        }
    }

    // === Send C1 for decryption ===
    for (uint64_t pIdx = 0; pIdx < nParties - 1; ++pIdx) {
        for (size_t j = 0; j < setSize; ++j) {
            sendPoint(channels[pIdx], recvResult[j].first);
        }
    }

    // === Leader partial decrypt ===
    std::vector<ECpoint> local_partial_decryption(setSize);
    for (size_t j = 0; j < setSize; ++j)
        PartialDecrypt(local_partial_decryption[j], recvResult[j].first, a);

    // === Receive partial decryptions from members ===
    std::vector<std::vector<ECpoint>> partial_decryption(setSize, std::vector<ECpoint>(nParties));
    for (uint64_t pIdx = 0; pIdx < nParties - 1; ++pIdx) {
        for (size_t i = 0; i < setSize; ++i) {
            recvPoint(channels[pIdx], partial_decryption[i][pIdx]);
        }
    }

    // Add leader's own partial decryption
    for (size_t i = 0; i < setSize; i++)
        partial_decryption[i][nParties - 1] = local_partial_decryption[i];

    // === Full decryption and intersection ===
    std::vector<Element> result;
    for (size_t i = 0; i < setSize; i++) {
        ECpoint res;
        FullyDecrypt(res, partial_decryption[i], recvResult[i].second);
        if (is_identity(res))
            result.push_back(inputs[i]);
    }

    if (mDebug) std::cerr << "[Leader] Intersection size: " << result.size() << std::endl;

    return result;
}

// ======================= MEMBER =======================

void EcMpsiMember::run(
    const std::vector<Element>& inputs,
    std::vector<mpsi::Channel*>& channels)
{
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");

    const uint64_t nParties = mNumberOfParties;
    const uint64_t setSize = inputs.size();
    const uint64_t leaderIdx = nParties - 1;
    const uint64_t psiSecParam = 40;
    const uint64_t opprfNum = 2;

    mpsi::Channel* leaderChl = channels[0];

    PRNG prng(_mm_set_epi32(4253465, 3434565, (int)mPartyID, (int)mPartyID));

    // === DKG ===
    ECscalar a = scalar_random();
    ECpoint betaPart = scalar_mul_base(a);
    sendPoint(leaderChl, betaPart);

    ECpoint beta;
    recvPoint(leaderChl, beta);

    if (mDebug) std::cerr << "[Member " << mPartyID << "] DKG done" << std::endl;

    // === Receive EBF ===
    double false_positive_rate = 0.001;
    double m = -(setSize * std::log(false_positive_rate)) / (std::log(2) * std::log(2));
    uint32_t bf_size = std::ceil(m);

    BloomFilter bf(bf_size, MURMURHASH_SEEDS);
    std::vector<Ciphertext> encrypted_bloom_filter(bf.size());

    for (size_t i = 0; i < bf.size(); ++i) {
        recvPoint(leaderChl, encrypted_bloom_filter[i].first);
        recvPoint(leaderChl, encrypted_bloom_filter[i].second);
    }

    if (mDebug) std::cerr << "[Member " << mPartyID << "] EBF received" << std::endl;

    // === Client membership test ===
    std::vector<Ciphertext> encrypted_membership_test_results(setSize);
    for (uint64_t i = 0; i < setSize; i++) {
        auto positions = bf.GetPositions(inputs[i]);
        Ciphertext test_result = encrypted_bloom_filter[positions[0]];
        for (size_t j = 1; j < positions.size(); j++)
            Homo_Add(test_result, test_result, encrypted_bloom_filter[positions[j]]);
        encrypted_membership_test_results[i] = test_result;

        // Rerandomize
        Ciphertext zeros;
        Encrypt(zeros, ZERO_POINT, beta);
        Homo_Add(encrypted_membership_test_results[i],
                  encrypted_membership_test_results[i], zeros);
    }

    if (mDebug) std::cerr << "[Member " << mPartyID << "] Membership test done" << std::endl;

    // === DH-OPRF ===
    std::vector<block> setBlock(setSize);
    for (size_t i = 0; i < setSize; i++) setBlock[i] = toBlock(inputs[i]);

    ECscalar priv_key = scalar_random();
    std::vector<ECpoint> hashedPoints = setblock_to_points(setBlock);

    std::vector<ECpoint> myOPRFValues(setSize);
    for (size_t i = 0; i < setSize; ++i)
        myOPRFValues[i] = scalar_mul(priv_key, hashedPoints[i]);

    // Receive blinded points from leader
    std::vector<ECpoint> blindedPts(setSize);
    for (size_t i = 0; i < setSize; ++i)
        recvPoint(leaderChl, blindedPts[i]);

    // Process and send back
    for (size_t i = 0; i < setSize; ++i) {
        ECpoint processed = scalar_mul(priv_key, blindedPts[i]);
        sendPoint(leaderChl, processed);
    }

    if (mDebug) std::cerr << "[Member " << mPartyID << "] DH-OPRF done" << std::endl;

    // === OPPRF setup ===
    binSet bins;
    bins.init(mPartyID, nParties, setSize, psiSecParam);
    bins.hashing2Bins(setBlock, 1);

    std::vector<binSet> binSets;
    for (uint64_t i = 0; i < opprfNum; i++) binSets.push_back(bins);

    std::vector<OPPRFSender> send(opprfNum);
    for (uint64_t opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++) {
        std::vector<osuCrypto::Channel*> adaptedChls = { nullptr };
        send[opprfIdx].init(nParties, setSize, psiSecParam, adaptedChls, prng.get<block>());
    }

    send[0].getOPRFkeysSeperatedandTable(leaderIdx, binSets[0], myOPRFValues);
    send[1].getOPRFkeysSeperatedandTable(leaderIdx, binSets[1], myOPRFValues);

    if (mDebug) std::cerr << "[Member " << mPartyID << "] OPPRF keys done" << std::endl;

    // === OPPRF online: send to leader ===
    std::vector<ECpoint> firstPoint(setSize), secondPoint(setSize);
    for (size_t j = 0; j < setSize; j++) {
        firstPoint[j] = encrypted_membership_test_results[j].first;
        secondPoint[j] = encrypted_membership_test_results[j].second;
    }

    {
        ChannelAdapter adapter(leaderChl);
        std::vector<osuCrypto::Channel*> adaptedChls = { &adapter };
        send[0].sendSSTableBased(leaderIdx, binSets[0], firstPoint, adaptedChls);
        send[1].sendSSTableBased(leaderIdx, binSets[1], secondPoint, adaptedChls);
    }

    if (mDebug) std::cerr << "[Member " << mPartyID << "] OPPRF sent" << std::endl;

    // === Receive C1 for decryption ===
    std::vector<ECpoint> c1_values(setSize);
    for (size_t i = 0; i < setSize; ++i)
        recvPoint(leaderChl, c1_values[i]);

    // === Partial decrypt and send shares ===
    std::vector<ECpoint> local_partial_decryption(setSize);
    for (size_t j = 0; j < setSize; ++j)
        PartialDecrypt(local_partial_decryption[j], c1_values[j], a);

    for (size_t i = 0; i < setSize; ++i)
        sendPoint(leaderChl, local_partial_decryption[i]);

    if (mDebug) std::cerr << "[Member " << mPartyID << "] Done" << std::endl;
}

} // namespace mpsi::xzh26
