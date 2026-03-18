#include "ot_mpsi.h"
#include "../crypto/bloom_filter.h"
#include "protocols/ks05/protocol/logger.h"

#include <algorithm>
#include <random>
#include <thread>

namespace mpsi::beh21 {

using ks05::Ciphertext;
using ks05::Plaintext;
using ks05::PubKey;
using ks05::PrivKey;
using ks05::ZZ;

// Serialize a ZZ Ciphertext into a binary string
static void serializeCt(const Ciphertext& ct, std::string& out)
{
    long numBytes = NTL::NumBytes(ct);
    std::vector<unsigned char> buffer(numBytes);
    NTL::BytesFromZZ(buffer.data(), ct, numBytes);
    out.assign(reinterpret_cast<const char*>(buffer.data()), numBytes);
}

// Deserialize a ZZ Ciphertext from a binary string
static void deserializeCt(const std::string& in, Ciphertext& ct)
{
    ct = NTL::ZZFromBytes(reinterpret_cast<const unsigned char*>(in.data()), in.size());
}

// Generate deterministic BF hash seeds (must match across all parties)
static std::vector<uint32_t> generateHashSeeds(size_t numHash)
{
    // Use a fixed seed to generate deterministic hash seeds
    // Matches experiment: 0x123456789ABCDEF0, 0xFEDCBA9876543210
    std::mt19937_64 rng(0x123456789ABCDEF0ULL);
    std::vector<uint32_t> seeds(numHash);
    for (size_t i = 0; i < numHash; ++i)
    {
        seeds[i] = static_cast<uint32_t>(rng());
    }
    return seeds;
}

bool signedNonPositive(const NTL::ZZ& plaintext, const PubKey& pk)
{
    // In Paillier, plaintext space is Z_n. Values > n/2 represent negative numbers.
    // A value is "non-positive" if it is 0 or > n/2.
    if (IsZero(plaintext))
        return true;
    return plaintext > pk.n / 2;
}

void OtMpsiBase::init(uint64_t numberOfParties,
                       uint64_t threshold,
                       uint64_t partyID,
                       uint64_t senderSize,
                       uint64_t recverSize,
                       bool debug)
{
    mNumberOfParties = numberOfParties;
    mThreshold = threshold;
    mPartyID = partyID;
    mSenderSize = senderSize;
    mRecverSize = recverSize;
    mDebug = debug;
}

void OtMpsiBase::setKeys(const PubKey& pk, const PrivKey& sk)
{
    mPubKey = pk;
    mPrivKey = sk;
}

// ============================================================================
// Set size negotiation
// ============================================================================

void OtMpsiLeader::negotiateSetSize(std::vector<mpsi::Channel*>& channels)
{
    auto& logger = ks05::Logger::getInstance();
    uint64_t maxSize = mSenderSize;

    // Receive each member's set size
    for (auto* ch : channels) {
        uint64_t memberSize = ch->recvU64();
        if (memberSize > maxSize)
            maxSize = memberSize;
    }

    mNegotiatedSetSize = maxSize;

    // Broadcast negotiated size and leader's element count back to all members
    for (auto* ch : channels) {
        ch->sendU64(mNegotiatedSetSize);
        ch->sendU64(mSenderSize);  // leader's input count = recverSize for members
    }

    logger.log("BEH21 Leader: Negotiated set size = ", mNegotiatedSetSize,
               ", leader elements = ", mSenderSize);
}

void OtMpsiMember::negotiateSetSize(mpsi::Channel* leaderChannel)
{
    auto& logger = ks05::Logger::getInstance();

    // Send our set size to leader
    leaderChannel->sendU64(mSenderSize);

    // Receive negotiated max size and leader's element count
    mNegotiatedSetSize = leaderChannel->recvU64();
    mRecverSize = leaderChannel->recvU64();

    logger.log("BEH21 Member ", mPartyID, ": Negotiated set size = ", mNegotiatedSetSize,
               ", leader elements = ", mRecverSize);
}

// ============================================================================
// Member
// ============================================================================

void OtMpsiMember::run(const std::vector<Element>& inputs,
                        std::vector<mpsi::Channel*>& channels)
{
    auto& logger = ks05::Logger::getInstance();
    logger.log("BEH21 Member ", mPartyID, " begins");

    // Step 0: Negotiate set sizes with leader
    negotiateSetSize(channels[0]);

    // Step 1: Build Bloom filter using negotiated set size for consistent parameters
    size_t numBits, numHash;
    BloomFilter::optimalParams(mNegotiatedSetSize, numBits, numHash);
    auto seeds = generateHashSeeds(numHash);

    BloomFilter bloomFilter(numBits, seeds);
    for (const auto& input : inputs)
        bloomFilter.add(input);

    logger.log("BEH21 Member ", mPartyID, " inserted ", inputs.size(), " elements into Bloom filter (",
               numBits, " bits)");

    // Step 1.5: Pre-compute Enc(0) for re-randomization
    size_t numLeaderElements = mRecverSize;
    size_t numMembers = mNumberOfParties - 1;
    size_t totalRerands = (numLeaderElements * numMembers * 2) + (numLeaderElements * 2);

    std::vector<Ciphertext> encZeros(totalRerands);
    for (size_t i = 0; i < totalRerands; ++i)
        encZeros[i] = ks05::enc(NTL::to_ZZ(0), mPubKey);
    size_t encZeroIdx = 0;

    logger.log("BEH21 Member ", mPartyID, " pre-computed ", totalRerands, " encrypted zeros");

    // Step 2: Encrypt Bloom filter and send to leader
    size_t bfSize = bloomFilter.size();
    std::vector<Ciphertext> encryptedBF(bfSize);
    for (size_t i = 0; i < bfSize; ++i)
    {
        uint64_t bitValue = bloomFilter[i] ? 1 : 0;
        encryptedBF[i] = ks05::enc(NTL::to_ZZ(bitValue), mPubKey);
    }

    for (size_t i = 0; i < bfSize; ++i)
    {
        std::string ctStr;
        serializeCt(encryptedBF[i], ctStr);
        channels[0]->sendBytes(ctStr);
    }

    logger.log("BEH21 Member ", mPartyID, " sent encrypted Bloom filter to leader");

    // Step 3: First round SCP - Ring-based membership test
    size_t recvChannel = (mPartyID == 0) ? 0 : 1;
    size_t sendChannel = (mPartyID == numMembers - 1) ? 0 : 2;
    ZZ randomBound = NTL::ZZ(128);

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::array<Ciphertext, 3> scp;
            for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
            {
                std::string ctStr = channels[recvChannel]->recvBytes();
                deserializeCt(ctStr, scp[ctIdx]);
            }

            auto& [a_1, a_2, c_encrypted] = scp;
            bool b_i = (NTL::RandomBnd(NTL::to_ZZ(2)) == 1);

            if (b_i)
                std::swap(a_1, a_2);

            a_1 = ks05::add(a_1, encZeros[encZeroIdx++], mPubKey);
            a_2 = ks05::add(a_2, encZeros[encZeroIdx++], mPubKey);

            ZZ r = NTL::RandomBnd(randomBound - 1) + 1;
            ZZ r_prime = NTL::RandomBnd(r - 1) + 1;
            int64_t sign = (b_i ? -1 : 1);
            c_encrypted = ks05::mul(c_encrypted, NTL::to_ZZ(sign) * r, mPubKey);
            c_encrypted = ks05::add(c_encrypted, ks05::enc(NTL::to_ZZ(sign) * r_prime, mPubKey), mPubKey);

            for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
            {
                std::string ctStr;
                serializeCt(scp[ctIdx], ctStr);
                channels[sendChannel]->sendBytes(ctStr);
            }
        }
    }

    logger.log("BEH21 Member ", mPartyID, " completed pipelined SCP processing");

    // Step 3.5: Joint decryption of first round SCP
    std::vector<std::vector<Ciphertext>> firstRoundC(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundC[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::string ctStr = channels[0]->recvBytes();
            deserializeCt(ctStr, firstRoundC[elemIdx][memberIdx]);
        }
    }

    std::vector<std::vector<Ciphertext>> firstRoundPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundPartialDec[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            firstRoundPartialDec[elemIdx][memberIdx] = ks05::partialDec(firstRoundC[elemIdx][memberIdx], mPubKey, mPrivKey);
        }
    }

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::string ctStr;
            serializeCt(firstRoundPartialDec[elemIdx][memberIdx], ctStr);
            channels[0]->sendBytes(ctStr);
        }
    }

    logger.log("BEH21 Member ", mPartyID, " sent partial decryptions to leader");

    // Step 4: Second round SCP - Threshold check
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::array<Ciphertext, 3> scp;
        for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
        {
            std::string ctStr = channels[recvChannel]->recvBytes();
            deserializeCt(ctStr, scp[ctIdx]);
        }

        auto& [a_1, a_2, c_encrypted] = scp;
        bool b_i = (NTL::RandomBnd(NTL::to_ZZ(2)) == 1);

        if (b_i)
            std::swap(a_1, a_2);

        a_1 = ks05::add(a_1, encZeros[encZeroIdx++], mPubKey);
        a_2 = ks05::add(a_2, encZeros[encZeroIdx++], mPubKey);

        ZZ r = NTL::RandomBnd(randomBound - 1) + 1;
        ZZ r_prime = NTL::RandomBnd(r - 1) + 1;
        int64_t sign = (b_i ? -1 : 1);
        c_encrypted = ks05::mul(c_encrypted, NTL::to_ZZ(sign) * r, mPubKey);
        c_encrypted = ks05::add(c_encrypted, ks05::enc(NTL::to_ZZ(sign) * r_prime, mPubKey), mPubKey);

        for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
        {
            std::string ctStr;
            serializeCt(scp[ctIdx], ctStr);
            channels[sendChannel]->sendBytes(ctStr);
        }
    }

    logger.log("BEH21 Member ", mPartyID, " completed second round SCP pipeline");

    // Step 4.5: Joint decryption of second round SCP
    std::vector<Ciphertext> secondRoundC(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr = channels[0]->recvBytes();
        deserializeCt(ctStr, secondRoundC[elemIdx]);
    }

    std::vector<Ciphertext> secondRoundPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        secondRoundPartialDec[elemIdx] = ks05::partialDec(secondRoundC[elemIdx], mPubKey, mPrivKey);
    }

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr;
        serializeCt(secondRoundPartialDec[elemIdx], ctStr);
        channels[0]->sendBytes(ctStr);
    }

    logger.log("BEH21 Member ", mPartyID, " sent partial decryptions for round 2 to leader");

    // Step 5: Final joint decryption
    std::vector<Ciphertext> aggregatedC(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr = channels[0]->recvBytes();
        deserializeCt(ctStr, aggregatedC[elemIdx]);
    }

    std::vector<Ciphertext> aggregatedPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        aggregatedPartialDec[elemIdx] = ks05::partialDec(aggregatedC[elemIdx], mPubKey, mPrivKey);
    }

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr;
        serializeCt(aggregatedPartialDec[elemIdx], ctStr);
        channels[0]->sendBytes(ctStr);
    }

    logger.log("BEH21 Member ", mPartyID, " completed protocol");
}

// ============================================================================
// Leader
// ============================================================================

std::vector<Element> OtMpsiLeader::run(const std::vector<Element>& inputs,
                                        std::vector<mpsi::Channel*>& channels)
{
    auto& logger = ks05::Logger::getInstance();
    logger.log("BEH21 Leader begins");

    const size_t numMembers = channels.size();
    const size_t numLeaderElements = inputs.size();

    // Step 0: Negotiate set sizes with members
    negotiateSetSize(channels);

    // Step 1: Pre-compute Enc(0) for re-randomization (multi-threaded)
    size_t totalRerands = numLeaderElements * numMembers + numLeaderElements;
    std::vector<Ciphertext> encZeros(totalRerands);
    std::vector<std::thread> pThreads;
    pThreads.reserve(numMembers);

    for (size_t threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        pThreads.emplace_back([&, threadIdx]()
                              {
            for (size_t i = threadIdx; i < totalRerands; i += numMembers)
                encZeros[i] = ks05::enc(NTL::to_ZZ(0), mPubKey);
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    size_t encZeroIdx = 0;

    logger.log("BEH21 Leader: Pre-computed ", totalRerands, " encrypted zeros");

    // Step 2: Receive encrypted Bloom filters and compute membership tests
    // Use negotiated set size for consistent BF parameters across all parties
    size_t numBits, numHash;
    BloomFilter::optimalParams(mNegotiatedSetSize, numBits, numHash);
    auto seeds = generateHashSeeds(numHash);

    logger.log("BEH21 Leader: Bloom filter parameters: ", numBits, " bits, ", numHash, " hash functions");

    std::vector<std::vector<Ciphertext>> encryptedBFs(numMembers);
    for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        encryptedBFs[memberIdx].resize(numBits);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        pThreads.emplace_back([&, memberIdx]()
                              {
            for (size_t bitIdx = 0; bitIdx < numBits; ++bitIdx)
            {
                std::string ctStr = channels[memberIdx]->recvBytes();
                deserializeCt(ctStr, encryptedBFs[memberIdx][bitIdx]);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Received encrypted Bloom filters from all members");

    std::vector<std::vector<Ciphertext>> membershipTests(numLeaderElements);

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        membershipTests[elemIdx].resize(numMembers);
        const Element& element = inputs[elemIdx];

        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::vector<size_t> hashPositions(numHash);
            for (size_t hashIdx = 0; hashIdx < numHash; ++hashIdx)
            {
                uint64_t h = murmurHash(element, seeds[hashIdx]);
                hashPositions[hashIdx] = static_cast<size_t>(h % numBits);
            }

            Ciphertext result = encryptedBFs[memberIdx][hashPositions[0]];
            for (size_t hashIdx = 1; hashIdx < numHash; ++hashIdx)
                result = ks05::add(result, encryptedBFs[memberIdx][hashPositions[hashIdx]], mPubKey);

            result = ks05::add(result, encZeros[encZeroIdx++], mPubKey);
            membershipTests[elemIdx][memberIdx] = result;
        }
    }

    logger.log("BEH21 Leader: Computed membership tests for ", numLeaderElements, " elements");

    // Step 3a: First round SCP - send SCP triples to ring
    ZZ randomBound = NTL::ZZ(128);

    pThreads.clear();
    pThreads.emplace_back([&]()
                          {
        for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
        {
            for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
            {
                Ciphertext encC = membershipTests[elemIdx][memberIdx];

                ZZ r = NTL::RandomBnd(randomBound - 1) + 1;
                ZZ r_prime = NTL::RandomBnd(r - 1) + 1;

                Ciphertext posK = ks05::enc(NTL::to_ZZ(static_cast<int64_t>(numHash)), mPubKey);
                Ciphertext difference = ks05::sub(posK, encC, mPubKey);

                Ciphertext c_encrypted = ks05::mul(difference, r, mPubKey);
                c_encrypted = ks05::add(c_encrypted, ks05::enc(NTL::to_ZZ(0) - r_prime, mPubKey), mPubKey);

                Ciphertext a_1 = ks05::enc(NTL::to_ZZ(1), mPubKey);
                Ciphertext a_2 = ks05::enc(NTL::to_ZZ(0), mPubKey);

                std::array<Ciphertext, 3> scp = {a_1, a_2, c_encrypted};
                for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
                {
                    std::string ctStr;
                    serializeCt(scp[ctIdx], ctStr);
                    channels[0]->sendBytes(ctStr);
                }
            }
        }
        logger.log("BEH21 Leader: Initiated SCP for ", numLeaderElements * numMembers, " membership tests");
    });

    // Step 3b: Receive SCP results from ring end
    std::vector<std::vector<std::array<Ciphertext, 3>>> firstRoundSCP(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundSCP[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
            {
                std::string ctStr = channels[numMembers - 1]->recvBytes();
                deserializeCt(ctStr, firstRoundSCP[elemIdx][memberIdx][ctIdx]);
            }
        }
    }

    logger.log("BEH21 Leader: Received final SCP results from ring");

    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    // Send c_encrypted to all members for joint decryption
    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
                {
                    std::string ctStr;
                    serializeCt(firstRoundSCP[elemIdx][memberIdx][2], ctStr);
                    channels[recvMemberIdx]->sendBytes(ctStr);
                }
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Sent c_encrypted to members for joint decryption");

    // Receive partial decryptions from members
    size_t totalPairs = numLeaderElements * numMembers;
    std::vector<std::vector<Ciphertext>> firstRoundPartialDec(totalPairs);
    for (size_t pairIdx = 0; pairIdx < totalPairs; ++pairIdx)
        firstRoundPartialDec[pairIdx].resize(numMembers);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
                {
                    size_t pairIdx = elemIdx * numMembers + memberIdx;
                    std::string partialStr = channels[recvMemberIdx]->recvBytes();
                    deserializeCt(partialStr, firstRoundPartialDec[pairIdx][recvMemberIdx]);
                }
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Received partial decryptions from members");

    // Fuse decryptions
    std::vector<std::vector<Plaintext>> firstRoundDecrypted(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
        firstRoundDecrypted[elemIdx].resize(numMembers);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        pThreads.emplace_back([&, threadIdx]()
                              {
            for (size_t pairIdx = threadIdx; pairIdx < totalPairs; pairIdx += numMembers)
            {
                size_t elemIdx = pairIdx / numMembers;
                size_t memberIdx = pairIdx % numMembers;

                std::vector<Ciphertext> allPartials(numMembers + 1);
                for (size_t i = 0; i < numMembers; ++i)
                    allPartials[i] = firstRoundPartialDec[pairIdx][i];
                allPartials[numMembers] = ks05::partialDec(firstRoundSCP[elemIdx][memberIdx][2], mPubKey, mPrivKey);

                firstRoundDecrypted[elemIdx][memberIdx] = ks05::fuseDec(allPartials, mPubKey);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Completed first round joint decryption");

    // SCP selection
    std::vector<std::vector<Ciphertext>> firstRoundResults(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundResults[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            if (signedNonPositive(firstRoundDecrypted[elemIdx][memberIdx], mPubKey))
                firstRoundResults[elemIdx][memberIdx] = firstRoundSCP[elemIdx][memberIdx][0];
            else
                firstRoundResults[elemIdx][memberIdx] = firstRoundSCP[elemIdx][memberIdx][1];
        }
    }

    logger.log("BEH21 Leader: Selected final first round results based on SCP comparison");

    // Step 4a: Aggregate and initiate second round SCP
    std::vector<Ciphertext> aggregatedResults(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        aggregatedResults[elemIdx] = ks05::enc(NTL::to_ZZ(0), mPubKey);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
            aggregatedResults[elemIdx] = ks05::add(aggregatedResults[elemIdx], firstRoundResults[elemIdx][memberIdx], mPubKey);
    }

    logger.log("BEH21 Leader: Aggregated first round SCP results");

    pThreads.clear();
    pThreads.emplace_back([&]()
                          {
        for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
        {
            Ciphertext encC = aggregatedResults[elemIdx];

            ZZ r = NTL::RandomBnd(randomBound - 1) + 1;
            ZZ r_prime = NTL::RandomBnd(r - 1) + 1;

            Ciphertext posThreshold = ks05::enc(NTL::to_ZZ(mThreshold - 1), mPubKey);
            Ciphertext difference = ks05::sub(posThreshold, encC, mPubKey);

            Ciphertext c_encrypted = ks05::mul(difference, r, mPubKey);
            c_encrypted = ks05::add(c_encrypted, ks05::enc(NTL::to_ZZ(0) - r_prime, mPubKey), mPubKey);

            Ciphertext a_1 = ks05::enc(NTL::to_ZZ(1), mPubKey);
            Ciphertext a_2 = ks05::enc(NTL::to_ZZ(0), mPubKey);

            std::array<Ciphertext, 3> scp = {a_1, a_2, c_encrypted};
            for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
            {
                std::string ctStr;
                serializeCt(scp[ctIdx], ctStr);
                channels[0]->sendBytes(ctStr);
            }
        }
        logger.log("BEH21 Leader: Initiated second round SCP for ", numLeaderElements, " elements");
    });

    // Step 4b: Receive second round SCP results
    std::vector<std::array<Ciphertext, 3>> secondRoundSCP(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
        {
            std::string ctStr = channels[numMembers - 1]->recvBytes();
            deserializeCt(ctStr, secondRoundSCP[elemIdx][ctIdx]);
        }
    }

    logger.log("BEH21 Leader: Received second round SCP results from ring");

    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    // Send c_encrypted for second round joint decryption
    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string ctStr;
                serializeCt(secondRoundSCP[elemIdx][2], ctStr);
                channels[recvMemberIdx]->sendBytes(ctStr);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Sent c_encrypted to members for second round joint decryption");

    // Receive second round partial decryptions
    std::vector<std::vector<Ciphertext>> secondRoundPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
        secondRoundPartialDec[elemIdx].resize(numMembers);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string partialStr = channels[recvMemberIdx]->recvBytes();
                deserializeCt(partialStr, secondRoundPartialDec[elemIdx][recvMemberIdx]);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Received partial decryptions for second round from members");

    // Fuse second round decryptions
    std::vector<Plaintext> secondRoundDecrypted(numLeaderElements);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        pThreads.emplace_back([&, threadIdx]()
                              {
            for (size_t elemIdx = threadIdx; elemIdx < numLeaderElements; elemIdx += numMembers)
            {
                std::vector<Ciphertext> allPartials(numMembers + 1);
                for (size_t i = 0; i < numMembers; ++i)
                    allPartials[i] = secondRoundPartialDec[elemIdx][i];
                allPartials[numMembers] = ks05::partialDec(secondRoundSCP[elemIdx][2], mPubKey, mPrivKey);

                secondRoundDecrypted[elemIdx] = ks05::fuseDec(allPartials, mPubKey);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Completed second round joint decryption");

    std::vector<Ciphertext> secondRoundResults(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        if (signedNonPositive(secondRoundDecrypted[elemIdx], mPubKey))
            secondRoundResults[elemIdx] = secondRoundSCP[elemIdx][0];
        else
            secondRoundResults[elemIdx] = secondRoundSCP[elemIdx][1];
    }

    logger.log("BEH21 Leader: Selected final second round results based on SCP comparison");

    // Step 5: Final joint decryption
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
        secondRoundResults[elemIdx] = ks05::add(secondRoundResults[elemIdx], encZeros[encZeroIdx++], mPubKey);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string ctStr;
                serializeCt(secondRoundResults[elemIdx], ctStr);
                channels[recvMemberIdx]->sendBytes(ctStr);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Sent final results to members for joint decryption");

    // Receive final partial decryptions
    std::vector<std::vector<Ciphertext>> finalPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
        finalPartialDec[elemIdx].resize(numMembers);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string partialStr = channels[recvMemberIdx]->recvBytes();
                deserializeCt(partialStr, finalPartialDec[elemIdx][recvMemberIdx]);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Received partial decryptions for final results from members");

    // Fuse final decryptions
    std::vector<Plaintext> finalDecrypted(numLeaderElements);

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        pThreads.emplace_back([&, threadIdx]()
                              {
            for (size_t elemIdx = threadIdx; elemIdx < numLeaderElements; elemIdx += numMembers)
            {
                std::vector<Ciphertext> allPartials(numMembers + 1);
                for (size_t i = 0; i < numMembers; ++i)
                    allPartials[i] = finalPartialDec[elemIdx][i];
                allPartials[numMembers] = ks05::partialDec(secondRoundResults[elemIdx], mPubKey, mPrivKey);

                finalDecrypted[elemIdx] = ks05::fuseDec(allPartials, mPubKey);
            }
        });
    }
    for (auto& th : pThreads)
        if (th.joinable()) th.join();

    logger.log("BEH21 Leader: Completed final joint decryption");

    // Build intersection
    std::vector<Element> intersection;
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        if (finalDecrypted[elemIdx] == NTL::to_ZZ(1))
            intersection.push_back(inputs[elemIdx]);
    }

    logger.log("BEH21 Leader: Found intersection of size ", intersection.size(), " out of ", inputs.size(), " inputs");

    return intersection;
}

} // namespace mpsi::beh21
