#include "ot_mpsi.h"
#include "shared/util/logger.h"
#include "shared/crypto/defines.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "volePSI/SimpleIndex.h"
#include "bloom_filter.h"

#include <filesystem>
#include <coproto/coproto.h>
#include <sstream>
#include <coroutine>
#include <chrono>
#include <algorithm>

// Serialize a ZZ Ciphertext into a binary string
inline void SerializeToString(const Ciphertext &ct, std::string &out)
{
    long numBytes = NTL::NumBytes(ct);
    std::vector<unsigned char> buffer(numBytes);
    NTL::BytesFromZZ(buffer.data(), ct, numBytes);
    out.assign(reinterpret_cast<const char *>(buffer.data()), numBytes);
}

// Deserialize a ZZ Ciphertext from a binary string
inline void DeserializeFromString(const std::string &in, Ciphertext &ct, const PubKey &pk)
{
    ct = NTL::ZZFromBytes(reinterpret_cast<const unsigned char *>(in.data()), in.size());
}

void OtMpPsiBase::init(u64 numberOfParties,
                       u64 threshold,
                       u64 partyID,
                       u64 senderSize,
                       u64 recverSize,
                       block seed,
                       bool debug)
{
    mNumberOfParties = numberOfParties;
    mThreshold = threshold;
    mPartyID = partyID;
    mSenderSize = senderSize;
    mRecverSize = recverSize;

    mPrng.SetSeed(seed);
    mDebug = debug;

    ZZ zzSeed = NTL::to_ZZ(static_cast<unsigned long>(0x9e3779b97f4a7c15ULL));

    InitializeCrypto(numberOfParties, zzSeed);
}

Proto OtMpPsiMember::Run(span<block> inputs,
                         std::vector<Socket> &chls)
{
    Logger &logger = Logger::getInstance();
    setTimePoint("OtMpPsiMember::Run begin");
    logger.log("Member ", mPartyID, " begins");

    // ------------------------------------------------------------
    // Step 1: Build Bloom filter from member's inputs
    // All parties use the same fixed seed to ensure consistent hash functions
    // ------------------------------------------------------------

    size_t numBits, numHash;
    BloomFilter::optimalParams(inputs.size(), numBits, numHash);

    block hashSeedGeneratorSeed = oc::toBlock(0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL);
    OcPRNG hashSeedPrng(hashSeedGeneratorSeed);
    std::vector<u32> seeds(numHash);
    for (size_t i = 0; i < numHash; ++i)
    {
        seeds[i] = static_cast<u32>(hashSeedPrng.get<u64>());
    }

    BloomFilter bloomFilter(numBits, seeds);
    for (const auto &input : inputs)
    {
        bloomFilter.add(input);
    }

    logger.log("Member ", mPartyID, " inserted ", inputs.size(), " elements into Bloom filter");
    setTimePoint("OtMpPsiMember::Run built Bloom filter");

    // ------------------------------------------------------------
    // Step 1.5: Pre-compute Enc(0) for efficient re-randomization
    // Optimization: rerand(c) = add(c, Enc(0)) is cheaper than calling rerand()
    // Total needed: Step 3 (2 * numLeaderElements * numMembers) + Step 4 (2 * numLeaderElements)
    // ------------------------------------------------------------

    size_t numLeaderElements = mRecverSize;
    size_t numMembers = mNumberOfParties - 1;
    size_t totalRerands = (numLeaderElements * numMembers * 2) + (numLeaderElements * 2);

    std::vector<Ciphertext> encZeros(totalRerands);
    for (size_t i = 0; i < totalRerands; ++i)
    {
        encZeros[i] = enc(NTL::to_ZZ(0), mPubKey);
    }
    size_t encZeroIdx = 0;

    logger.log("Member ", mPartyID, " pre-computed ", totalRerands, " encrypted zeros");
    setTimePoint("OtMpPsiMember::Run pre-computed encrypted zeros");

    // ------------------------------------------------------------
    // Step 2: Encrypt Bloom filter and send to leader
    // ------------------------------------------------------------

    size_t bfSize = bloomFilter.size();
    std::vector<Ciphertext> encryptedBF(bfSize);

    for (size_t i = 0; i < bfSize; ++i)
    {
        u64 bitValue = bloomFilter[i] ? 1 : 0;
        encryptedBF[i] = enc(NTL::to_ZZ(bitValue), mPubKey);
    }

    for (size_t i = 0; i < bfSize; ++i)
    {
        std::string ctStr;
        SerializeToString(encryptedBF[i], ctStr);
        co_await chls[0].send(ctStr);
    }

    logger.log("Member ", mPartyID, " sent encrypted Bloom filter to leader");
    setTimePoint("OtMpPsiMember::Run sent encrypted BF");

    // ------------------------------------------------------------
    // Step 3: First round SCP - Ring-based membership test (pipelined)
    // SCP determines if each (element, member) pair satisfies Enc(sum) == Enc(k)
    // Ring topology: recv SCP → re-randomize & permute → send
    // ------------------------------------------------------------

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
                std::string ctStr;
                co_await chls[recvChannel].recvResize(ctStr);
                DeserializeFromString(ctStr, scp[ctIdx], mPubKey);
            }

            auto &[a_1, a_2, c_encrypted] = scp;
            bool b_i = (mPrng.get<u64>() % 2) == 1;

            if (b_i)
                std::swap(a_1, a_2);

            a_1 = add(a_1, encZeros[encZeroIdx++], mPubKey);
            a_2 = add(a_2, encZeros[encZeroIdx++], mPubKey);

            ZZ r = NTL::RandomBnd(randomBound - 1) + 1;
            ZZ r_prime = NTL::RandomBnd(r - 1) + 1;
            i64 sign = (b_i ? -1 : 1);
            c_encrypted = mul(c_encrypted, sign * r, mPubKey);
            c_encrypted = add(c_encrypted, enc(sign * r_prime, mPubKey), mPubKey);

            for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
            {
                std::string ctStr;
                SerializeToString(scp[ctIdx], ctStr);
                co_await chls[sendChannel].send(ctStr);
            }
        }
    }

    logger.log("Member ", mPartyID, " completed pipelined SCP processing");
    setTimePoint("OtMpPsiMember::Run completed SCP pipeline");

    // ------------------------------------------------------------
    // Step 3.5: Joint decryption of first round SCP (star topology)
    // Receive c_encrypted → partial decrypt → send shares to leader
    // ------------------------------------------------------------

    std::vector<std::vector<Ciphertext>> firstRoundC(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundC[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::string ctStr;
            co_await chls[0].recvResize(ctStr);
            DeserializeFromString(ctStr, firstRoundC[elemIdx][memberIdx], mPubKey);
        }
    }

    std::vector<std::vector<Ciphertext>> firstRoundPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundPartialDec[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            firstRoundPartialDec[elemIdx][memberIdx] = partialDec(firstRoundC[elemIdx][memberIdx], mPubKey, mPrivKey);
        }
    }

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::string ctStr;
            SerializeToString(firstRoundPartialDec[elemIdx][memberIdx], ctStr);
            co_await chls[0].send(ctStr);
        }
    }

    logger.log("Member ", mPartyID, " sent partial decryptions to leader");
    setTimePoint("OtMpPsiMember::Run sent partial decryptions");

    // ------------------------------------------------------------
    // Step 4: Second round SCP - Threshold check on aggregated results (pipelined ring)
    // Same SCP logic as Step 3, but for aggregated membership scores
    // ------------------------------------------------------------

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::array<Ciphertext, 3> scp;
        for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
        {
            std::string ctStr;
            co_await chls[recvChannel].recvResize(ctStr);
            DeserializeFromString(ctStr, scp[ctIdx], mPubKey);
        }

        auto &[a_1, a_2, c_encrypted] = scp;
        bool b_i = (mPrng.get<u64>() % 2) == 1;

        if (b_i)
            std::swap(a_1, a_2);

        a_1 = add(a_1, encZeros[encZeroIdx++], mPubKey);
        a_2 = add(a_2, encZeros[encZeroIdx++], mPubKey);

        ZZ r = NTL::RandomBnd(randomBound - 1) + 1;
        ZZ r_prime = NTL::RandomBnd(r - 1) + 1;
        i64 sign = (b_i ? -1 : 1);
        c_encrypted = mul(c_encrypted, sign * r, mPubKey);
        c_encrypted = add(c_encrypted, enc(sign * r_prime, mPubKey), mPubKey);

        for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
        {
            std::string ctStr;
            SerializeToString(scp[ctIdx], ctStr);
            co_await chls[sendChannel].send(ctStr);
        }
    }

    logger.log("Member ", mPartyID, " completed second round SCP pipeline");
    setTimePoint("OtMpPsiMember::Run completed SCP round 2");

    // ------------------------------------------------------------
    // Step 4.5: Joint decryption of second round SCP (star topology)
    // ------------------------------------------------------------

    std::vector<Ciphertext> secondRoundC(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr;
        co_await chls[0].recvResize(ctStr);
        DeserializeFromString(ctStr, secondRoundC[elemIdx], mPubKey);
    }

    std::vector<Ciphertext> secondRoundPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        secondRoundPartialDec[elemIdx] = partialDec(secondRoundC[elemIdx], mPubKey, mPrivKey);
    }

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr;
        SerializeToString(secondRoundPartialDec[elemIdx], ctStr);
        co_await chls[0].send(ctStr);
    }

    logger.log("Member ", mPartyID, " sent partial decryptions for round 2 to leader");
    setTimePoint("OtMpPsiMember::Run sent partial decryptions round 2");

    // ------------------------------------------------------------
    // Step 5: Final joint decryption to reveal intersection
    // Decrypt final results to learn which elements meet threshold
    // ------------------------------------------------------------

    std::vector<Ciphertext> aggregatedC(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr;
        co_await chls[0].recvResize(ctStr);
        DeserializeFromString(ctStr, aggregatedC[elemIdx], mPubKey);
    }

    std::vector<Ciphertext> aggregatedPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        aggregatedPartialDec[elemIdx] = partialDec(aggregatedC[elemIdx], mPubKey, mPrivKey);
    }

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        std::string ctStr;
        SerializeToString(aggregatedPartialDec[elemIdx], ctStr);
        co_await chls[0].send(ctStr);
    }

    logger.log("Member ", mPartyID, " sent partial decryptions for aggregated results to leader");
    setTimePoint("OtMpPsiMember::Run sent partial decryptions aggregated");

    logger.log("Member ", mPartyID, " completed protocol");
    setTimePoint("OtMpPsiMember::Run completed");

    co_return;
}

void OtMpPsiMember::InitializeCrypto(u64 n, const ZZ &seed)
{
    // Generate distributed Paillier keys using the seed
    // All parties generate the same public key but different secret key shares
    std::vector<PrivKey> allSecretKeys;
    distributedKeyGen(2048, n, seed, mPubKey, allSecretKeys);

    // Extract this member's secret key share (index mPartyID)
    mPrivKey = allSecretKeys[mPartyID];
}

void OtMpPsiMember::Sync(std::vector<Socket> &chls)
{
    std::string dummy;
    chls[0].recvResize(dummy);
}

Proto OtMpPsiLeader::Run(span<block> inputs,
                         std::vector<Socket> &chls)
{
    Logger &logger = Logger::getInstance();
    logger.log("Leader begins");
    setTimePoint("OtMpPsiLeader::Run begin");

    const size_t numMembers = chls.size();
    const size_t numLeaderElements = inputs.size();

    // ------------------------------------------------------------
    // Step 1: Pre-compute Enc(0) for re-randomization
    // Total: Step 2 (numLeaderElements * numMembers) + Step 5.1 (numLeaderElements)
    // Multi-threaded computation for efficiency
    // ------------------------------------------------------------

    size_t totalRerands = numLeaderElements * numMembers + numLeaderElements;
    std::vector<Ciphertext> encZeros(totalRerands);
    std::vector<std::thread> pThreads;
    pThreads.reserve(numMembers);

    for (size_t threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        pThreads.emplace_back([&, threadIdx]()
                              {
            for (size_t i = threadIdx; i < totalRerands; i += numMembers)
            {
                encZeros[i] = enc(NTL::to_ZZ(0), mPubKey);
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    size_t encZeroIdx = 0;

    logger.log("Leader: Pre-computed ", totalRerands, " encrypted zeros using ", numMembers, " threads");
    setTimePoint("OtMpPsiLeader::Run pre-computed encrypted zeros");

    // ------------------------------------------------------------
    // Step 2: Receive encrypted Bloom filters and compute membership tests
    // Use Paillier homomorphism: sum of Enc(bits) = Enc(sum of bits)
    // Result Enc(k) if element in BF, Enc(<k) otherwise
    // ------------------------------------------------------------

    size_t numBits, numHash;
    BloomFilter::optimalParams(mSenderSize, numBits, numHash);

    block hashSeedGeneratorSeed = oc::toBlock(0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL);
    OcPRNG hashSeedPrng(hashSeedGeneratorSeed);
    std::vector<u32> seeds(numHash);
    for (size_t i = 0; i < numHash; ++i)
    {
        seeds[i] = static_cast<u32>(hashSeedPrng.get<u64>());
    }

    logger.log("Leader: Bloom filter parameters: ", numBits, " bits, ", numHash, " hash functions");

    std::vector<std::vector<Ciphertext>> encryptedBFs(numMembers);
    for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        encryptedBFs[memberIdx].resize(numBits);
    }

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        pThreads.emplace_back([&, memberIdx]()
                              {
            for (size_t bitIdx = 0; bitIdx < numBits; ++bitIdx)
            {
                std::string ctStr;
                coproto::sync_wait(chls[memberIdx].recvResize(ctStr));
                DeserializeFromString(ctStr, encryptedBFs[memberIdx][bitIdx], mPubKey);
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Received encrypted Bloom filters from all members");
    setTimePoint("OtMpPsiLeader::Run received encrypted BFs");

    std::vector<std::vector<Ciphertext>> membershipTests(numLeaderElements);

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        membershipTests[elemIdx].resize(numMembers);
        const block &element = inputs[elemIdx];

        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::vector<size_t> hashPositions(numHash);
            for (size_t hashIdx = 0; hashIdx < numHash; ++hashIdx)
            {
                u64 h = murmurHash(element, seeds[hashIdx]);
                hashPositions[hashIdx] = static_cast<size_t>(h % numBits);
            }

            Ciphertext result = encryptedBFs[memberIdx][hashPositions[0]];
            for (size_t hashIdx = 1; hashIdx < numHash; ++hashIdx)
            {
                result = add(result, encryptedBFs[memberIdx][hashPositions[hashIdx]], mPubKey);
            }

            result = add(result, encZeros[encZeroIdx++], mPubKey);
            membershipTests[elemIdx][memberIdx] = result;
        }
    }

    logger.log("Leader: Computed membership tests for ", numLeaderElements, " elements across ", numMembers, " members");
    setTimePoint("OtMpPsiLeader::Run computed membership tests");

    // ------------------------------------------------------------
    // Step 3a: First round SCP - Check if Enc(sum) == Enc(k) for each (element, member) pair
    // SCP protocol: determine if k - c <= 0, i.e., c == k
    // Send SCP triple (a_1=Enc(1), a_2=Enc(0), c_encrypted) to ring
    // ------------------------------------------------------------

    ZZ randomBound = ZZ(128);

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

                Ciphertext posK = enc(NTL::to_ZZ(static_cast<i64>(numHash)), mPubKey);
                Ciphertext difference = sub(posK, encC, mPubKey);

                Ciphertext c_encrypted = mul(difference, r, mPubKey);
                c_encrypted = add(c_encrypted, enc(NTL::to_ZZ(0) - r_prime, mPubKey), mPubKey);

                Ciphertext a_1 = enc(NTL::to_ZZ(1), mPubKey);
                Ciphertext a_2 = enc(NTL::to_ZZ(0), mPubKey);

                std::array<Ciphertext, 3> scp = {a_1, a_2, c_encrypted};
                for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
                {
                    std::string ctStr;
                    SerializeToString(scp[ctIdx], ctStr);
                    coproto::sync_wait(chls[0].send(ctStr));
                }
            }
        }

        logger.log("Leader: Initiated SCP for ", numLeaderElements * numMembers, " membership tests");
        setTimePoint("OtMpPsiLeader::Run initiated SCP"); });

    // ------------------------------------------------------------
    // Step 3b: Receive SCP results and perform joint decryption
    // Decrypt c_encrypted to select between a_1 (Enc(1)) or a_2 (Enc(0))
    // ------------------------------------------------------------

    std::vector<std::vector<std::array<Ciphertext, 3>>> firstRoundSCP(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundSCP[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
            {
                std::string ctStr;
                coproto::sync_wait(chls[numMembers - 1].recvResize(ctStr));
                DeserializeFromString(ctStr, firstRoundSCP[elemIdx][memberIdx][ctIdx], mPubKey);
            }
        }
    }

    logger.log("Leader: Received final SCP results from ring");
    setTimePoint("OtMpPsiLeader::Run received SCP results");

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

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
                    SerializeToString(firstRoundSCP[elemIdx][memberIdx][2], ctStr);
                    coproto::sync_wait(chls[recvMemberIdx].send(ctStr));
                }
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Sent c_encrypted to members for joint decryption");
    setTimePoint("OtMpPsiLeader::Run sent for joint decryption");

    size_t totalPairs = numLeaderElements * numMembers;
    std::vector<std::vector<Ciphertext>> firstRoundPartialDec(totalPairs);
    for (size_t pairIdx = 0; pairIdx < totalPairs; ++pairIdx)
    {
        firstRoundPartialDec[pairIdx].resize(numMembers);
    }

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
                    std::string partialStr;
                    coproto::sync_wait(chls[recvMemberIdx].recvResize(partialStr));
                    DeserializeFromString(partialStr, firstRoundPartialDec[pairIdx][recvMemberIdx], mPubKey);
                }
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Received partial decryptions from members");
    setTimePoint("OtMpPsiLeader::Run received partial decryptions");

    std::vector<std::vector<Plaintext>> firstRoundDecrypted(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundDecrypted[elemIdx].resize(numMembers);
    }

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
                {
                    allPartials[i] = firstRoundPartialDec[pairIdx][i];
                }
                allPartials[numMembers] = partialDec(firstRoundSCP[elemIdx][memberIdx][2], mPubKey, mPrivKey);

                firstRoundDecrypted[elemIdx][memberIdx] = fuseDec(allPartials, mPubKey);
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Completed first round joint decryption");
    setTimePoint("OtMpPsiLeader::Run completed first round decryption");

    // SCP selection: if c_encrypted <= 0, choose a_1 (membership=1), else a_2 (membership=0)
    std::vector<std::vector<Ciphertext>> firstRoundResults(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        firstRoundResults[elemIdx].resize(numMembers);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            if (firstRoundDecrypted[elemIdx][memberIdx] <= NTL::to_ZZ(0))
            {
                firstRoundResults[elemIdx][memberIdx] = firstRoundSCP[elemIdx][memberIdx][0];
            }
            else
            {
                firstRoundResults[elemIdx][memberIdx] = firstRoundSCP[elemIdx][memberIdx][1];
            }
        }
    }

    logger.log("Leader: Selected final first round results based on SCP comparison");
    setTimePoint("OtMpPsiLeader::Run selected first round results");

    // ------------------------------------------------------------
    // Step 4a: Aggregate and initiate second round SCP for threshold check
    // Sum membership results per element, then check if sum >= threshold-1
    // (Leader already has element, so threshold-1 additional members needed)
    // ------------------------------------------------------------

    std::vector<Ciphertext> aggregatedResults(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        aggregatedResults[elemIdx] = enc(NTL::to_ZZ(0), mPubKey);
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            aggregatedResults[elemIdx] = add(aggregatedResults[elemIdx], firstRoundResults[elemIdx][memberIdx], mPubKey);
        }
    }

    logger.log("Leader: Aggregated first round SCP results");
    setTimePoint("OtMpPsiLeader::Run aggregated first round");

    pThreads.clear();
    pThreads.emplace_back([&]()
                          {
        for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
        {
            Ciphertext encC = aggregatedResults[elemIdx];

            ZZ r = NTL::RandomBnd(randomBound - 1) + 1;
            ZZ r_prime = NTL::RandomBnd(r - 1) + 1;

            Ciphertext posThreshold = enc(NTL::to_ZZ(mThreshold-1), mPubKey);
            Ciphertext difference = sub(posThreshold, encC, mPubKey);

            Ciphertext c_encrypted = mul(difference, r, mPubKey);
            c_encrypted = add(c_encrypted, enc(NTL::to_ZZ(0) - r_prime, mPubKey), mPubKey);

            Ciphertext a_1 = enc(NTL::to_ZZ(1), mPubKey);
            Ciphertext a_2 = enc(NTL::to_ZZ(0), mPubKey);

            std::array<Ciphertext, 3> scp = {a_1, a_2, c_encrypted};
            for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
            {
                std::string ctStr;
                SerializeToString(scp[ctIdx], ctStr);
                coproto::sync_wait(chls[0].send(ctStr));
            }
        }

        logger.log("Leader: Initiated second round SCP for ", numLeaderElements, " elements");
        setTimePoint("OtMpPsiLeader::Run initiated second round SCP"); });

    // ------------------------------------------------------------
    // Step 4b: Receive second round SCP and perform joint decryption
    // ------------------------------------------------------------

    std::vector<std::array<Ciphertext, 3>> secondRoundSCP(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        for (size_t ctIdx = 0; ctIdx < 3; ++ctIdx)
        {
            std::string ctStr;
            coproto::sync_wait(chls[numMembers - 1].recvResize(ctStr));
            DeserializeFromString(ctStr, secondRoundSCP[elemIdx][ctIdx], mPubKey);
        }
    }

    logger.log("Leader: Received second round SCP results from ring");
    setTimePoint("OtMpPsiLeader::Run received second round SCP results");

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string ctStr;
                SerializeToString(secondRoundSCP[elemIdx][2], ctStr);
                coproto::sync_wait(chls[recvMemberIdx].send(ctStr));
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Sent c_encrypted to members for second round joint decryption");
    setTimePoint("OtMpPsiLeader::Run sent for second round joint decryption");

    std::vector<std::vector<Ciphertext>> secondRoundPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        secondRoundPartialDec[elemIdx].resize(numMembers);
    }

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string partialStr;
                coproto::sync_wait(chls[recvMemberIdx].recvResize(partialStr));
                DeserializeFromString(partialStr, secondRoundPartialDec[elemIdx][recvMemberIdx], mPubKey);
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Received partial decryptions for second round from members");
    setTimePoint("OtMpPsiLeader::Run received second round partial decryptions");

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
                {
                    allPartials[i] = secondRoundPartialDec[elemIdx][i];
                }
                allPartials[numMembers] = partialDec(secondRoundSCP[elemIdx][2], mPubKey, mPrivKey);

                secondRoundDecrypted[elemIdx] = fuseDec(allPartials, mPubKey);
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Completed second round joint decryption");
    setTimePoint("OtMpPsiLeader::Run completed second round decryption");

    std::vector<Ciphertext> secondRoundResults(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        if (secondRoundDecrypted[elemIdx] <= NTL::to_ZZ(0))
        {
            secondRoundResults[elemIdx] = secondRoundSCP[elemIdx][0];
        }
        else
        {
            secondRoundResults[elemIdx] = secondRoundSCP[elemIdx][1];
        }
    }

    logger.log("Leader: Selected final second round results based on SCP comparison");
    setTimePoint("OtMpPsiLeader::Run selected second round results");

    // ------------------------------------------------------------
    // Step 5: Final joint decryption to determine intersection
    // Re-randomize before sending, then decrypt to reveal final results
    // ------------------------------------------------------------

    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        secondRoundResults[elemIdx] = add(secondRoundResults[elemIdx], encZeros[encZeroIdx++], mPubKey);
    }

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string ctStr;
                SerializeToString(secondRoundResults[elemIdx], ctStr);
                coproto::sync_wait(chls[recvMemberIdx].send(ctStr));
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Sent final results to members for joint decryption");
    setTimePoint("OtMpPsiLeader::Run sent final for joint decryption");

    std::vector<std::vector<Ciphertext>> finalPartialDec(numLeaderElements);
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        finalPartialDec[elemIdx].resize(numMembers);
    }

    pThreads.clear();
    pThreads.reserve(numMembers);

    for (size_t recvMemberIdx = 0; recvMemberIdx < numMembers; ++recvMemberIdx)
    {
        pThreads.emplace_back([&, recvMemberIdx]()
                              {
            for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
            {
                std::string partialStr;
                coproto::sync_wait(chls[recvMemberIdx].recvResize(partialStr));
                DeserializeFromString(partialStr, finalPartialDec[elemIdx][recvMemberIdx], mPubKey);
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Received partial decryptions for final results from members");
    setTimePoint("OtMpPsiLeader::Run received final partial decryptions");

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
                {
                    allPartials[i] = finalPartialDec[elemIdx][i];
                }
                allPartials[numMembers] = partialDec(secondRoundResults[elemIdx], mPubKey, mPrivKey);

                finalDecrypted[elemIdx] = fuseDec(allPartials, mPubKey);
            } });
    }

    for (auto &th : pThreads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader: Completed final joint decryption");
    setTimePoint("OtMpPsiLeader::Run completed final decryption");

    std::vector<block> intersection;
    for (size_t elemIdx = 0; elemIdx < numLeaderElements; ++elemIdx)
    {
        if (finalDecrypted[elemIdx] == NTL::to_ZZ(1))
        {
            intersection.push_back(inputs[elemIdx]);
        }
    }

    logger.log("Leader: Found intersection of size ", intersection.size(), " out of ", inputs.size(), " inputs");
    setTimePoint("OtMpPsiLeader::Run found intersection");

    setTimePoint("OtMpPsiLeader::Run completed PSI protocol");
    logger.log(getTimer());

    co_return;
}

void OtMpPsiLeader::InitializeCrypto(u64 n, const ZZ &seed)
{
    if (mNumberOfParties < 2)
        throw std::invalid_argument("[Leader] mNumberOfParties must be >= 2");
    if (n == 0)
        throw std::invalid_argument("[Leader] number of parties must be > 0");

    const u64 numParties = mNumberOfParties;
    const u64 leaderIdx = numParties - 1; // Leader is the last party

    // Generate distributed Paillier keys using the seed
    // All parties will generate the same public key but different secret key shares
    std::vector<PrivKey> allSecretKeys;
    distributedKeyGen(2048, numParties, seed, mPubKey, allSecretKeys);

    // Leader takes the last secret key share (index leaderIdx)
    mPrivKey = allSecretKeys[leaderIdx];
}

void OtMpPsiLeader::Sync(std::vector<Socket> &chls)
{
    std::vector<std::thread> pThreads;
    pThreads.reserve(mNumberOfParties - 1);
    {
        pThreads.clear();
        for (size_t memberIdx = 0; memberIdx < mNumberOfParties - 1; ++memberIdx)
        {
            std::string dummy = "0";
            pThreads.emplace_back(
                [&, memberIdx]()
                {
                    chls[memberIdx].send(dummy);
                    chls[memberIdx].flush();
                });
        }

        for (auto &th : pThreads)
        {
            if (th.joinable())
                th.join();
        }
    }
}
