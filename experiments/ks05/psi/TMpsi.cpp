#include "TMpsi.h"
#include "shared/util/logger.h"
#include "shared/crypto/defines.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "volePSI/SimpleIndex.h"
#include "polynomial.h"

#include <filesystem>
#include <coproto/coproto.h>
#include <sstream>
#include <coroutine>
#include <chrono>
#include <algorithm>

inline void SerializeToString(const Ciphertext &ct, std::string &out)
{
    long numBytes = NTL::NumBytes(ct);
    std::vector<unsigned char> buffer(numBytes);
    NTL::BytesFromZZ(buffer.data(), ct, numBytes);
    out.assign(reinterpret_cast<const char *>(buffer.data()), numBytes);
}

inline void DeserializeFromString(const std::string &in, Ciphertext &ct, const PubKey &pk)
{
    ct = NTL::ZZFromBytes(reinterpret_cast<const unsigned char *>(in.data()), in.size());
}

void TMpsiBase::init(u64 numberOfParties,
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

Proto TMpsiMember::Run(span<block> inputs, std::vector<Socket> &chls)
{
    Logger &logger = Logger::getInstance();
    setTimePoint("TMpsiMember::Run begin");
    logger.log("Member ", mPartyID, " begins");

    // ============================================================
    // Step 1: Encode member's inputs as plaintext polynomial
    // ============================================================
    // Convert block inputs to ZZ and encode as polynomial P(x) = (x - r1)(x - r2)...(x - rn)
    std::vector<ZZ> roots;
    roots.reserve(inputs.size());

    for (const auto &input : inputs)
    {
        // Convert block (128-bit) to ZZ and reduce modulo n
        const u64 *data = reinterpret_cast<const u64 *>(&input);
        ZZ value = NTL::to_ZZ(data[0]) + (NTL::to_ZZ(data[1]) << 64);
        ZZ reduced = value % mPubKey.n;
        if (reduced < 0)
            reduced += mPubKey.n;
        roots.push_back(reduced);
    }

    Polynomial poly = encodeAsPolynomial(roots, mPubKey.n);

    logger.log("Member ", mPartyID, " encoded ", inputs.size(), " inputs as polynomial of degree ", poly.degree());
    setTimePoint("TMpsiMember::Run encoded inputs");

    // ============================================================
    // Step 2: Pre-encrypt zeros for rerandomization
    // ============================================================
    // Optimization: Pre-encrypt zeros offline to reduce online encryption cost.
    // Members rerandomize at two critical points:
    // 1. After polynomial multiplication (before sending to next party in ring)
    // 2. After blinding (before sending back to leader)

    // Calculate expected degree after aggregation in ring
    // Leader starts with degree = receiverSize
    // After member i: degree = receiverSize + (i+1) × senderSize
    u64 degreeAfterAggregation = mRecverSize + (mPartyID + 1) * mSenderSize;
    u64 coeffsAfterAggregation = degreeAfterAggregation + 1;

    // Calculate expected degree after blinding: max(p × r_i, p^(t-1) × F × poly × s_i)
    // - p × r_i has degree: degOriginal * 2
    // - p^(t-1) × F × poly × s_i has degree ≈ 3 * degDerivative (conservative estimate)
    u64 expectedDegOriginal = mRecverSize + (mNumberOfParties - 1) * mSenderSize;
    u64 expectedDegDerivative = expectedDegOriginal - (mThreshold - 1);
    u64 degTerm1 = expectedDegOriginal * 2;
    u64 degTerm2 = expectedDegDerivative * 3;
    u64 degreeAfterBlinding = (degTerm1 > degTerm2) ? degTerm1 : degTerm2;
    u64 coeffsAfterBlinding = degreeAfterBlinding + 1;

    u64 totalZerosNeeded = coeffsAfterAggregation + coeffsAfterBlinding;
    std::vector<Ciphertext> encryptedZeros(totalZerosNeeded);

    for (u64 i = 0; i < totalZerosNeeded; ++i)
    {
        encryptedZeros[i] = enc(ZZ(0), mPubKey);
    }

    logger.log("Member ", mPartyID, " pre-encrypted ", totalZerosNeeded, " zeros");
    setTimePoint("TMpsiMember::Run pre-encrypted zeros");

    // ============================================================
    // Step 3: Polynomial aggregation via ring topology
    // ============================================================
    // Members form a ring: Leader → P0 → P1 → ... → Pn-2 → Leader
    // Each member multiplies received polynomial by their own polynomial
    // Optimization: Pipeline - send coefficient k as soon as it's ready

    // Channel mapping: chls[0] = leader, chls[1] = prev party, chls[2] = next party
    u64 prevPartyChl = (mPartyID == 0) ? 0 : 1;                    // P0 receives from leader
    u64 nextPartyChl = (mPartyID == mNumberOfParties - 2) ? 0 : 2; // Pn-2 sends to leader

    u64 numRecvCoeffs = 0;
    coproto::sync_wait(chls[prevPartyChl].recv(numRecvCoeffs));

    u64 myDegree = poly.degree();
    u64 resultDegree = numRecvCoeffs - 1 + myDegree;
    u64 numResultCoeffs = resultDegree + 1;

    coproto::sync_wait(chls[nextPartyChl].send(numResultCoeffs));

    std::vector<Ciphertext> resultCoeffs(numResultCoeffs, NTL::to_ZZ(0));

    // Pipelined polynomial multiplication
    for (u64 recvIdx = 0; recvIdx < numRecvCoeffs; ++recvIdx)
    {
        std::string serialized;
        coproto::sync_wait(chls[prevPartyChl].recvResize(serialized));

        Ciphertext recvCoeff;
        DeserializeFromString(serialized, recvCoeff, mPubKey);

        // Polynomial multiplication: result[k] = sum_{i+j=k} recv[i] * poly[j]
        for (u64 j = 0; j <= myDegree && recvIdx + j <= resultDegree; ++j)
        {
            u64 resultIdx = recvIdx + j;
            Ciphertext term = mul(recvCoeff, poly.coefficients[j], mPubKey);

            if (resultCoeffs[resultIdx] == NTL::to_ZZ(0))
            {
                resultCoeffs[resultIdx] = term;
            }
            else
            {
                resultCoeffs[resultIdx] = add(resultCoeffs[resultIdx], term, mPubKey);
            }
        }

        // Send completed coefficients immediately (pipeline optimization)
        // result[k] is complete when we've received all recv[i] where i+j=k
        for (u64 k = 0; k <= resultDegree; ++k)
        {
            u64 maxRecvIdxNeeded = std::min(k, numRecvCoeffs - 1);

            if (recvIdx == maxRecvIdxNeeded)
            {
                // Rerandomize before sending
                resultCoeffs[k] = add(resultCoeffs[k], encryptedZeros[k], mPubKey);

                std::string resultSerialized;
                SerializeToString(resultCoeffs[k], resultSerialized);
                coproto::sync_wait(chls[nextPartyChl].send(resultSerialized));
            }
        }
    }

    logger.log("Member ", mPartyID, " completed polynomial aggregation");
    setTimePoint("TMpsiMember::Run aggregation complete");

    // ============================================================
    // Step 4: Receive aggregated polynomial from leader
    // ============================================================
    u64 leaderChl = 0;
    u64 numCoeffs = 0;
    coproto::sync_wait(chls[leaderChl].recv(numCoeffs));

    std::vector<std::string> serializedCoeffs(numCoeffs);
    for (u64 i = 0; i < numCoeffs; ++i)
    {
        coproto::sync_wait(chls[leaderChl].recvResize(serializedCoeffs[i]));
    }

    std::vector<Ciphertext> coeffs;
    coeffs.reserve(numCoeffs);
    for (const auto &ser : serializedCoeffs)
    {
        Ciphertext coeff;
        DeserializeFromString(ser, coeff, mPubKey);
        coeffs.push_back(coeff);
    }

    PaillierPolynomial encPolyOriginal(coeffs, mPubKey);
    logger.log("Member ", mPartyID, " received polynomial, degree: ", encPolyOriginal.degree());
    setTimePoint("TMpsiMember::Run received polynomial");

    // ============================================================
    // Step 5: Compute (threshold-1)-th derivative for threshold-PSI
    // ============================================================
    // For threshold-PSI: items appearing in k parties have multiplicity k
    // Taking (threshold-1)-th derivative filters out items with multiplicity < threshold
    PaillierPolynomial encPolyDerivative = encPolyOriginal;

    logger.log("Member ", mPartyID, " computing ", mThreshold - 1, "-th derivative");

    for (u64 i = 0; i < mThreshold - 1; ++i)
    {
        encPolyDerivative.derivative();
    }

    logger.log("Member ", mPartyID, " completed derivative, degree: ", encPolyDerivative.degree());
    setTimePoint("TMpsiMember::Run computed derivative");

    // ============================================================
    // Step 6: Blind polynomial to hide member's inputs
    // ============================================================
    // Blinding formula: p × r_i + F × p^(t-1) × poly × s_i
    // where p = original polynomial, p^(t-1) = (threshold-1)-th derivative
    //
    // Key insight: For intersection items where poly(item) = 0,
    // the second term vanishes, preserving the root in the summed result
    size_t degOriginal = encPolyOriginal.degree();
    size_t degDerivative = encPolyDerivative.degree();
    size_t myDeg = poly.degree();

    // Generate random polynomial r_i with same degree as original
    std::vector<ZZ> r_coeffs(degOriginal + 1);
    for (size_t i = 0; i <= degOriginal; ++i)
    {
        r_coeffs[i] = NTL::RandomBnd(mPubKey.n);
    }
    Polynomial polyR(r_coeffs);

    // Generate random polynomial s_i with same degree as derivative
    std::vector<ZZ> s_coeffs(degDerivative + 1);
    for (size_t i = 0; i <= degDerivative; ++i)
    {
        s_coeffs[i] = NTL::RandomBnd(mPubKey.n);
    }
    Polynomial polyS(s_coeffs);

    // Generate padding polynomial F to align degrees
    std::vector<ZZ> f_coeffs;
    if (degDerivative >= myDeg)
    {
        size_t padDeg = degDerivative - myDeg;
        f_coeffs.resize(padDeg + 1);
        for (size_t i = 0; i <= padDeg; ++i)
        {
            f_coeffs[i] = NTL::RandomBnd(mPubKey.n);
        }
    }
    else
    {
        f_coeffs = {NTL::to_ZZ(1)};
    }
    Polynomial polyF(f_coeffs);

    // Compute first term: p × r_i
    PaillierPolynomial blindedPoly = encPolyOriginal;
    blindedPoly.mulPoly(polyR);

    // Compute second term: F × poly × s_i (plaintext)
    Polynomial polyBlind = polyF;
    polyBlind.mulPoly(poly);
    polyBlind.mulPoly(polyS);
    for (auto &coeff : polyBlind.coefficients)
    {
        coeff = coeff % mPubKey.n;
        if (coeff < 0)
            coeff += mPubKey.n;
    }

    // Compute second term: p^(t-1) × (F × poly × s_i)
    PaillierPolynomial derivativePart = encPolyDerivative;
    derivativePart.mulPoly(polyBlind);

    // Combine: p × r_i + p^(t-1) × (F × poly × s_i)
    blindedPoly.addPoly(derivativePart);
    setTimePoint("TMpsiMember::Run blinding complete");

    // Rerandomize before sending to leader
    u64 numCoeffsToRerand = blindedPoly.coefficients.size();
    for (u64 i = 0; i < numCoeffsToRerand; ++i)
    {
        blindedPoly.coefficients[i] = add(blindedPoly.coefficients[i], encryptedZeros[coeffsAfterAggregation + i], mPubKey);
    }

    logger.log("Member ", mPartyID, " completed blinding");
    setTimePoint("TMpsiMember::Run rerandomized");

    // ============================================================
    // Step 7: Send blinded polynomial to leader
    // ============================================================
    u64 sendNumCoeffs = blindedPoly.coefficients.size();
    coproto::sync_wait(chls[leaderChl].send(sendNumCoeffs));

    for (const auto &coeff : blindedPoly.coefficients)
    {
        std::string serialized;
        SerializeToString(coeff, serialized);
        coproto::sync_wait(chls[leaderChl].send(serialized));
    }

    logger.log("Member ", mPartyID, " sent blinded polynomial");
    setTimePoint("TMpsiMember::Run sent blinded polynomial");

    // ============================================================
    // Step 8: Joint decryption
    // ============================================================
    // Receive encrypted coefficients from leader
    u64 numCiphertexts = 0;
    coproto::sync_wait(chls[leaderChl].recv(numCiphertexts));

    std::vector<std::string> ctSerializedList(numCiphertexts);
    for (u64 i = 0; i < numCiphertexts; ++i)
    {
        coproto::sync_wait(chls[leaderChl].recvResize(ctSerializedList[i]));
    }

    std::vector<Ciphertext> ciphertexts;
    ciphertexts.reserve(numCiphertexts);
    for (const auto &ser : ctSerializedList)
    {
        Ciphertext ct;
        DeserializeFromString(ser, ct, mPubKey);
        ciphertexts.push_back(ct);
    }

    setTimePoint("TMpsiMember::Run received ciphertexts");

    // Perform partial decryption
    std::vector<Ciphertext> partialDecryptions;
    partialDecryptions.reserve(numCiphertexts);
    for (const auto &ct : ciphertexts)
    {
        Ciphertext partial = partialDec(ct, mPubKey, mPrivKey);
        partialDecryptions.push_back(partial);
    }

    logger.log("Member ", mPartyID, " performed partial decryption");
    setTimePoint("TMpsiMember::Run partial decryption");

    // Send partial decryptions back to leader
    coproto::sync_wait(chls[leaderChl].send(numCiphertexts));
    for (const auto &partialDec : partialDecryptions)
    {
        std::string serialized;
        SerializeToString(partialDec, serialized);
        coproto::sync_wait(chls[leaderChl].send(serialized));
    }

    logger.log("Member ", mPartyID, " completed");
    setTimePoint("TMpsiMember::Run complete");

    co_return;
}

void TMpsiMember::InitializeCrypto(u64 n, const ZZ &seed)
{
    std::vector<PrivKey> allSecretKeys;
    distributedKeyGen(2048, n, seed, mPubKey, allSecretKeys);
    mPrivKey = allSecretKeys[mPartyID];
}

void TMpsiMember::Sync(std::vector<Socket> &chls)
{
    std::string dummy;
    chls[0].recvResize(dummy);
}

Proto TMpsiLeader::Run(span<block> inputs, std::vector<Socket> &chls)
{
    Logger &logger = Logger::getInstance();
    logger.log("Leader begins");
    setTimePoint("TMpsiLeader::Run begin");

    const size_t numMembers = chls.size();

    // ============================================================
    // Step 1: Encode leader's inputs as Paillier-encrypted polynomial
    // ============================================================
    std::vector<ZZ> roots;
    roots.reserve(inputs.size());

    for (const auto &input : inputs)
    {
        // Convert block (128-bit) to ZZ and reduce modulo n
        const u64 *data = reinterpret_cast<const u64 *>(&input);
        ZZ value = NTL::to_ZZ(data[0]) + (NTL::to_ZZ(data[1]) << 64);
        ZZ reduced = value % mPubKey.n;
        if (reduced < 0)
            reduced += mPubKey.n;
        roots.push_back(reduced);
    }

    Polynomial plaintext_poly = encodeAsPolynomial(roots, mPubKey.n);
    logger.log("Leader encoded ", inputs.size(), " inputs, degree: ", plaintext_poly.degree());

    // Encrypt polynomial coefficients in parallel
    std::vector<Ciphertext> encrypted_coeffs(plaintext_poly.coefficients.size());
    std::vector<std::thread> threads;
    threads.reserve(numMembers);

    for (u64 threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        threads.emplace_back([&, threadIdx]()
                             {
            for (u64 i = threadIdx; i < plaintext_poly.coefficients.size(); i += numMembers)
            {
                encrypted_coeffs[i] = enc(plaintext_poly.coefficients[i], mPubKey);
            } });
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    PaillierPolynomial encPoly(encrypted_coeffs, mPubKey);
    logger.log("Leader encrypted polynomial, degree: ", encPoly.degree());
    setTimePoint("TMpsiLeader::Run encoded inputs");

    // ============================================================
    // Step 2: Ring aggregation - initiate polynomial multiplication
    // ============================================================
    // Leader sends encrypted polynomial to first member (P0)
    // and receives aggregated result from last member (Pn-2)
    u64 firstParty = 0;
    u64 lastParty = numMembers - 1;

    // Send encrypted polynomial to first party in ring
    u64 numCoeffs = encPoly.coefficients.size();
    coproto::sync_wait(chls[firstParty].send(numCoeffs));

    for (const auto &coeff : encPoly.coefficients)
    {
        std::string serialized;
        SerializeToString(coeff, serialized);
        coproto::sync_wait(chls[firstParty].send(serialized));
    }

    logger.log("Leader sent polynomial to first party");
    setTimePoint("TMpsiLeader::Run sent to ring");

    // Receive aggregated polynomial from last party in ring
    numCoeffs = 0;
    coproto::sync_wait(chls[lastParty].recv(numCoeffs));

    std::vector<std::string> serializedCoeffs(numCoeffs);
    for (u64 i = 0; i < numCoeffs; ++i)
    {
        coproto::sync_wait(chls[lastParty].recvResize(serializedCoeffs[i]));
    }

    std::vector<Ciphertext> coeffs;
    coeffs.reserve(numCoeffs);
    for (const auto &ser : serializedCoeffs)
    {
        Ciphertext coeff;
        DeserializeFromString(ser, coeff, mPubKey);
        coeffs.push_back(coeff);
    }

    encPoly = PaillierPolynomial(coeffs, mPubKey);
    logger.log("Leader received aggregated polynomial, degree: ", encPoly.degree());
    setTimePoint("TMpsiLeader::Run received from ring");

    // ============================================================
    // Step 3: Broadcast aggregated polynomial to all members
    // ============================================================
    // Note: Leader does NOT compute derivative here.
    // Members will compute (threshold-1)-th derivative before blinding.
    numCoeffs = encPoly.coefficients.size();

    // Broadcast in parallel to all members
    threads.clear();
    threads.reserve(numMembers);

    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        threads.emplace_back([&, memberIdx]()
                             {
            coproto::sync_wait(chls[memberIdx].send(numCoeffs));

            for (const auto &coeff : encPoly.coefficients)
            {
                std::string serialized;
                SerializeToString(coeff, serialized);
                coproto::sync_wait(chls[memberIdx].send(serialized));
            } });
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader broadcasted polynomial to all members");
    setTimePoint("TMpsiLeader::Run broadcasted");

    // ============================================================
    // Step 4: Receive blinded polynomials from all members
    // ============================================================
    std::vector<PaillierPolynomial> blindedPolys;
    blindedPolys.reserve(numMembers);

    std::vector<std::vector<Ciphertext>> allMemberCoeffs(numMembers);

    // Receive in parallel from all members
    threads.clear();
    threads.reserve(numMembers);

    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        threads.emplace_back([&, memberIdx]()
                             {
            u64 memberNumCoeffs = 0;
            coproto::sync_wait(chls[memberIdx].recv(memberNumCoeffs));

            std::vector<std::string> serializedCoeffs(memberNumCoeffs);
            for (u64 i = 0; i < memberNumCoeffs; ++i)
            {
                coproto::sync_wait(chls[memberIdx].recvResize(serializedCoeffs[i]));
            }

            allMemberCoeffs[memberIdx].reserve(memberNumCoeffs);
            for (const auto &ser : serializedCoeffs)
            {
                Ciphertext coeff;
                DeserializeFromString(ser, coeff, mPubKey);
                allMemberCoeffs[memberIdx].push_back(coeff);
            } });
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        blindedPolys.emplace_back(allMemberCoeffs[memberIdx], mPubKey);
    }

    logger.log("Leader received blinded polynomials");
    setTimePoint("TMpsiLeader::Run received blinded");

    // ============================================================
    // Step 5: Sum all blinded polynomials
    // ============================================================
    PaillierPolynomial summedPoly = blindedPolys[0];

    for (u64 memberIdx = 1; memberIdx < numMembers; ++memberIdx)
    {
        summedPoly.addPoly(blindedPolys[memberIdx]);
    }

    logger.log("Leader summed blinded polynomials, degree: ", summedPoly.degree());
    setTimePoint("TMpsiLeader::Run summed");

    // ============================================================
    // Step 6: Joint decryption
    // ============================================================
    std::vector<Ciphertext> encryptedCoeffs = summedPoly.coefficients;
    u64 numCoeffsToDecrypt = encryptedCoeffs.size();
    u64 numEvaluations = numCoeffsToDecrypt;

    // Broadcast encrypted coefficients to all members
    threads.clear();
    threads.reserve(numMembers);

    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        threads.emplace_back([&, memberIdx]()
                             {
            coproto::sync_wait(chls[memberIdx].send(numEvaluations));

            for (const auto &ct : encryptedCoeffs)
            {
                std::string serialized;
                SerializeToString(ct, serialized);
                coproto::sync_wait(chls[memberIdx].send(serialized));
            } });
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader broadcasted ciphertexts for joint decryption");

    // Perform leader's partial decryption in parallel
    std::vector<std::vector<Ciphertext>> allPartialDecryptions(numEvaluations);
    for (u64 i = 0; i < numEvaluations; ++i)
    {
        allPartialDecryptions[i].resize(numMembers + 1); // +1 for leader's share
    }

    threads.clear();
    threads.reserve(numMembers);

    for (u64 threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        threads.emplace_back([&, threadIdx]()
                             {
            for (u64 i = threadIdx; i < numEvaluations; i += numMembers)
            {
                allPartialDecryptions[i][numMembers] = partialDec(encryptedCoeffs[i], mPubKey, mPrivKey);
            } });
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader completed partial decryption");

    // Receive partial decryptions from all members
    threads.clear();
    threads.reserve(numMembers);

    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        threads.emplace_back([&, memberIdx]()
                             {
            u64 numPartials = 0;
            coproto::sync_wait(chls[memberIdx].recv(numPartials));

            for (u64 i = 0; i < numPartials; ++i)
            {
                std::string serialized;
                coproto::sync_wait(chls[memberIdx].recvResize(serialized));
                DeserializeFromString(serialized, allPartialDecryptions[i][memberIdx], mPubKey);
            } });
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader received partial decryptions");

    // Fuse all partial decryptions to recover plaintexts
    std::vector<Plaintext> decryptedResults(numEvaluations);

    threads.clear();
    threads.reserve(numMembers);

    for (u64 threadIdx = 0; threadIdx < numMembers; ++threadIdx)
    {
        threads.emplace_back([&, threadIdx]()
                             {
            for (u64 i = threadIdx; i < numEvaluations; i += numMembers)
            {
                decryptedResults[i] = fuseDec(allPartialDecryptions[i], mPubKey);
            } });
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    logger.log("Leader completed joint decryption");
    setTimePoint("TMpsiLeader::Run decrypted");

    // ============================================================
    // Step 7: Find intersection by polynomial evaluation
    // ============================================================
    // Note: The original paper does not specify which polynomial factorization
    // algorithm to use for root extraction. Polynomial factorization is computationally
    // expensive. Instead, we implement a simpler evaluation-based approach:
    // evaluate the decrypted polynomial at each leader input and check for zeros.
    Polynomial decryptedPoly(decryptedResults);
    logger.log("Leader reconstructed polynomial, degree: ", decryptedPoly.degree());

    std::vector<block> intersection;
    intersection.reserve(inputs.size());

    for (const auto &input : inputs)
    {
        const u64 *data = reinterpret_cast<const u64 *>(&input);
        ZZ value = NTL::to_ZZ(data[0]) + (NTL::to_ZZ(data[1]) << 64);
        ZZ y = value % mPubKey.n;
        if (y < 0)
            y += mPubKey.n;

        ZZ result = decryptedPoly.evaluateAt(y, mPubKey.n);

        if (result == 0)
        {
            intersection.push_back(input);
        }
    }

    logger.log("Leader found intersection: ", intersection.size(), " / ", inputs.size());
    setTimePoint("TMpsiLeader::Run found intersection");
    setTimePoint("TMpsiLeader::Run complete");
    logger.log(getTimer());

    co_return;
}

void TMpsiLeader::InitializeCrypto(u64 n, const ZZ &seed)
{
    if (mNumberOfParties < 2)
        throw std::invalid_argument("mNumberOfParties must be >= 2");
    if (n == 0)
        throw std::invalid_argument("number of parties must be > 0");

    const u64 numParties = mNumberOfParties;
    const u64 leaderIdx = numParties - 1;

    std::vector<PrivKey> allSecretKeys;
    distributedKeyGen(2048, numParties, seed, mPubKey, allSecretKeys);

    mPrivKey = allSecretKeys[leaderIdx];
}

void TMpsiLeader::Sync(std::vector<Socket> &chls)
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
