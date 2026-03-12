#include "t_mpsi.h"
#include "logger.h"
#include "../crypto/polynomial.h"

#include <thread>
#include <algorithm>
#include <stdexcept>

namespace {
// Sanity limit: no single polynomial should have more than this many
// coefficients.  Prevents a malicious peer from triggering huge allocations.
constexpr uint64_t MAX_COEFFICIENTS = 1'000'000;

void checkCoeffCount(uint64_t n) {
    if (n == 0 || n > MAX_COEFFICIENTS)
        throw std::runtime_error(
            "Invalid coefficient count from peer: " + std::to_string(n));
}
} // anonymous namespace

namespace mpsi::ks05 {

void serializeCiphertext(const Ciphertext& ct, std::string& out) {
    long numBytes = NTL::NumBytes(ct);
    std::vector<unsigned char> buffer(numBytes);
    NTL::BytesFromZZ(buffer.data(), ct, numBytes);
    out.assign(reinterpret_cast<const char*>(buffer.data()), numBytes);
}

void deserializeCiphertext(const std::string& in, Ciphertext& ct) {
    ct = NTL::ZZFromBytes(reinterpret_cast<const unsigned char*>(in.data()), in.size());
}

void serializeZZ(const ZZ& val, std::string& out) {
    long numBytes = NTL::NumBytes(val);
    std::vector<unsigned char> buffer(numBytes);
    NTL::BytesFromZZ(buffer.data(), val, numBytes);
    out.assign(reinterpret_cast<const char*>(buffer.data()), numBytes);
}

void deserializeZZ(const std::string& in, ZZ& val) {
    val = NTL::ZZFromBytes(reinterpret_cast<const unsigned char*>(in.data()), in.size());
}

void TMpsiBase::init(u64 numberOfParties,
                        u64 threshold,
                        u64 partyID,
                        u64 senderSize,
                        u64 recverSize,
                        bool debug) {
    mNumberOfParties = numberOfParties;
    mThreshold = threshold;
    mPartyID = partyID;
    mSenderSize = senderSize;
    mRecverSize = recverSize;
    mLocalSetSize = senderSize;
    mNegotiatedSetSize = 0;
    mDebug = debug;
    mCryptoInitialized = false;
}

void TMpsiBase::setKeys(const PubKey& pk, const PrivKey& sk) {
    mPubKey = pk;
    mPrivKey = sk;
    mCryptoInitialized = true;
}

// ============================================================================
// Set-size negotiation (runs at the start of the protocol, not during DKG)
// ============================================================================

void TMpsiMember::negotiateSetSize(mpsi::Channel* leaderChannel) {
    // Send our set size to leader
    leaderChannel->sendU64(mLocalSetSize);

    // Receive negotiated (max) size from leader
    mNegotiatedSetSize = leaderChannel->recvU64();
    mSenderSize = mNegotiatedSetSize;
    mRecverSize = mNegotiatedSetSize;
}

void TMpsiLeader::negotiateSetSize(std::vector<mpsi::Channel*>& channels) {
    u64 maxSetSize = mLocalSetSize;

    for (auto* ch : channels) {
        u64 memberSetSize = ch->recvU64();
        if (memberSetSize > maxSetSize)
            maxSetSize = memberSetSize;
    }

    mNegotiatedSetSize = maxSetSize;
    mSenderSize = maxSetSize;
    mRecverSize = maxSetSize;

    // Broadcast negotiated size to all members
    for (auto* ch : channels)
        ch->sendU64(maxSetSize);
}

// ============================================================================
// Member
// ============================================================================

void TMpsiMember::run(const std::vector<ZZ>& inputs, std::vector<mpsi::Channel*>& channels) {
    Logger& logger = Logger::getInstance();
    logger.log("Member ", mPartyID, " begins");

    if (!mCryptoInitialized)
        throw std::runtime_error("Keys not set. Call setKeys() with dealer-distributed keys before run().");

    // Negotiate uniform set size across all parties.
    negotiateSetSize(channels[0]);
    logger.log("Member ", mPartyID, " negotiated set size: ", mNegotiatedSetSize);

    // Step 1: Encode inputs as plaintext polynomial.
    // Pad to negotiated set size with random elements if our set is smaller.
    std::vector<ZZ> paddedInputs = inputs;
    if (paddedInputs.size() < mNegotiatedSetSize) {
        logger.log("Member ", mPartyID, " padding set from ", paddedInputs.size(),
                   " to ", mNegotiatedSetSize);
        while (paddedInputs.size() < mNegotiatedSetSize)
            paddedInputs.push_back(NTL::RandomBnd(mPubKey.n));
    }

    std::vector<ZZ> roots;
    roots.reserve(paddedInputs.size());
    for (const auto& input : paddedInputs) {
        ZZ reduced = input % mPubKey.n;
        if (reduced < 0)
            reduced += mPubKey.n;
        roots.push_back(reduced);
    }

    Polynomial poly = encodeAsPolynomial(roots, mPubKey.n);
    logger.log("Member ", mPartyID, " encoded ", paddedInputs.size(), " inputs as polynomial of degree ", poly.degree());

    // Step 2: Pre-encrypt zeros for rerandomization
    u64 degreeAfterAggregation = mRecverSize + (mPartyID + 1) * mSenderSize;
    u64 coeffsAfterAggregation = degreeAfterAggregation + 1;

    u64 expectedDegOriginal = mRecverSize + (mNumberOfParties - 1) * mSenderSize;
    u64 expectedDegDerivative = expectedDegOriginal - (mThreshold - 1);
    u64 degTerm1 = expectedDegOriginal * 2;
    u64 degTerm2 = expectedDegDerivative * 3;
    u64 degreeAfterBlinding = (degTerm1 > degTerm2) ? degTerm1 : degTerm2;
    u64 coeffsAfterBlinding = degreeAfterBlinding + 1;

    u64 totalZerosNeeded = coeffsAfterAggregation + coeffsAfterBlinding;
    std::vector<Ciphertext> encryptedZeros(totalZerosNeeded);
    for (u64 i = 0; i < totalZerosNeeded; ++i)
        encryptedZeros[i] = enc(ZZ(0), mPubKey);

    logger.log("Member ", mPartyID, " pre-encrypted ", totalZerosNeeded, " zeros");

    // Step 3: Polynomial aggregation via ring topology
    // Channel mapping: channels[0]=leader, channels[1]=prev, channels[2]=next
    u64 prevPartyChl = (mPartyID == 0) ? 0 : 1;
    u64 nextPartyChl = (mPartyID == mNumberOfParties - 2) ? 0 : 2;

    u64 numRecvCoeffs = channels[prevPartyChl]->recvU64();
    checkCoeffCount(numRecvCoeffs);

    u64 myDegree = poly.degree();
    u64 resultDegree = numRecvCoeffs - 1 + myDegree;
    u64 numResultCoeffs = resultDegree + 1;

    channels[nextPartyChl]->sendU64(numResultCoeffs);

    std::vector<Ciphertext> resultCoeffs(numResultCoeffs, NTL::to_ZZ(0));

    // Pipelined polynomial multiplication
    for (u64 recvIdx = 0; recvIdx < numRecvCoeffs; ++recvIdx) {
        std::string serialized = channels[prevPartyChl]->recvBytes();

        Ciphertext recvCoeff;
        deserializeCiphertext(serialized, recvCoeff);

        for (u64 j = 0; j <= myDegree && recvIdx + j <= resultDegree; ++j) {
            u64 resultIdx = recvIdx + j;
            Ciphertext term = mul(recvCoeff, poly.coefficients[j], mPubKey);

            if (resultCoeffs[resultIdx] == NTL::to_ZZ(0))
                resultCoeffs[resultIdx] = term;
            else
                resultCoeffs[resultIdx] = add(resultCoeffs[resultIdx], term, mPubKey);
        }

        // Send completed coefficients immediately (pipeline)
        for (u64 k = 0; k <= resultDegree; ++k) {
            u64 maxRecvIdxNeeded = std::min(k, static_cast<u64>(numRecvCoeffs - 1));
            if (recvIdx == maxRecvIdxNeeded) {
                resultCoeffs[k] = add(resultCoeffs[k], encryptedZeros[k], mPubKey);

                std::string resultSerialized;
                serializeCiphertext(resultCoeffs[k], resultSerialized);
                channels[nextPartyChl]->sendBytes(resultSerialized);
            }
        }
    }

    logger.log("Member ", mPartyID, " completed polynomial aggregation");

    // Step 4: Receive aggregated polynomial from leader
    u64 leaderChl = 0;
    u64 numCoeffs = channels[leaderChl]->recvU64();
    checkCoeffCount(numCoeffs);

    std::vector<Ciphertext> coeffs;
    coeffs.reserve(numCoeffs);
    for (u64 i = 0; i < numCoeffs; ++i) {
        std::string ser = channels[leaderChl]->recvBytes();
        Ciphertext coeff;
        deserializeCiphertext(ser, coeff);
        coeffs.push_back(coeff);
    }

    PaillierPolynomial encPolyOriginal(coeffs, mPubKey);
    logger.log("Member ", mPartyID, " received polynomial, degree: ", encPolyOriginal.degree());

    // Step 5: Compute (threshold-1)-th derivative
    PaillierPolynomial encPolyDerivative = encPolyOriginal;
    for (u64 i = 0; i < mThreshold - 1; ++i)
        encPolyDerivative.derivative();

    logger.log("Member ", mPartyID, " completed derivative, degree: ", encPolyDerivative.degree());

    // Step 6: Blind polynomial
    size_t degOriginal = encPolyOriginal.degree();
    size_t degDerivative = encPolyDerivative.degree();
    size_t myDeg = poly.degree();

    std::vector<ZZ> r_coeffs(degOriginal + 1);
    for (size_t i = 0; i <= degOriginal; ++i)
        r_coeffs[i] = NTL::RandomBnd(mPubKey.n);
    Polynomial polyR(r_coeffs);

    std::vector<ZZ> s_coeffs(degDerivative + 1);
    for (size_t i = 0; i <= degDerivative; ++i)
        s_coeffs[i] = NTL::RandomBnd(mPubKey.n);
    Polynomial polyS(s_coeffs);

    std::vector<ZZ> f_coeffs;
    if (degDerivative >= myDeg) {
        size_t padDeg = degDerivative - myDeg;
        f_coeffs.resize(padDeg + 1);
        for (size_t i = 0; i <= padDeg; ++i)
            f_coeffs[i] = NTL::RandomBnd(mPubKey.n);
    } else {
        f_coeffs = {NTL::to_ZZ(1)};
    }
    Polynomial polyF(f_coeffs);

    PaillierPolynomial blindedPoly = encPolyOriginal;
    blindedPoly.mulPoly(polyR);

    Polynomial polyBlind = polyF;
    polyBlind.mulPoly(poly);
    polyBlind.mulPoly(polyS);
    for (auto& coeff : polyBlind.coefficients) {
        coeff = coeff % mPubKey.n;
        if (coeff < 0)
            coeff += mPubKey.n;
    }

    PaillierPolynomial derivativePart = encPolyDerivative;
    derivativePart.mulPoly(polyBlind);

    blindedPoly.addPoly(derivativePart);

    // Rerandomize before sending
    u64 numCoeffsToRerand = blindedPoly.coefficients.size();
    for (u64 i = 0; i < numCoeffsToRerand; ++i)
        blindedPoly.coefficients[i] = add(blindedPoly.coefficients[i], encryptedZeros[coeffsAfterAggregation + i], mPubKey);

    logger.log("Member ", mPartyID, " completed blinding");

    // Step 7: Send blinded polynomial to leader
    u64 sendNumCoeffs = blindedPoly.coefficients.size();
    channels[leaderChl]->sendU64(sendNumCoeffs);

    for (const auto& coeff : blindedPoly.coefficients) {
        std::string serialized;
        serializeCiphertext(coeff, serialized);
        channels[leaderChl]->sendBytes(serialized);
    }

    logger.log("Member ", mPartyID, " sent blinded polynomial");

    // Step 8: Joint decryption
    u64 numCiphertexts = channels[leaderChl]->recvU64();
    checkCoeffCount(numCiphertexts);

    std::vector<Ciphertext> ciphertexts;
    ciphertexts.reserve(numCiphertexts);
    for (u64 i = 0; i < numCiphertexts; ++i) {
        std::string ser = channels[leaderChl]->recvBytes();
        Ciphertext ct;
        deserializeCiphertext(ser, ct);
        ciphertexts.push_back(ct);
    }

    // Partial decryption
    std::vector<Ciphertext> partialDecryptions;
    partialDecryptions.reserve(numCiphertexts);
    for (const auto& ct : ciphertexts)
        partialDecryptions.push_back(partialDec(ct, mPubKey, mPrivKey));

    logger.log("Member ", mPartyID, " performed partial decryption");

    // Send partial decryptions to leader
    channels[leaderChl]->sendU64(numCiphertexts);
    for (const auto& pd : partialDecryptions) {
        std::string serialized;
        serializeCiphertext(pd, serialized);
        channels[leaderChl]->sendBytes(serialized);
    }

    logger.log("Member ", mPartyID, " completed");
}

// ============================================================================
// Leader
// ============================================================================

std::vector<ZZ> TMpsiLeader::run(const std::vector<ZZ>& inputs, std::vector<mpsi::Channel*>& channels) {
    Logger& logger = Logger::getInstance();
    logger.log("Leader begins");

    if (!mCryptoInitialized)
        throw std::runtime_error("Keys not set. Call setKeys() with dealer-distributed keys before run().");

    // Negotiate uniform set size across all parties.
    negotiateSetSize(channels);
    logger.log("Leader negotiated set size: ", mNegotiatedSetSize);

    const size_t numMembers = channels.size();

    // Step 1: Encode leader's inputs as encrypted polynomial.
    // Pad to negotiated set size with random elements if our set is smaller.
    std::vector<ZZ> paddedInputs = inputs;
    if (paddedInputs.size() < mNegotiatedSetSize) {
        logger.log("Leader padding set from ", paddedInputs.size(),
                   " to ", mNegotiatedSetSize);
        while (paddedInputs.size() < mNegotiatedSetSize)
            paddedInputs.push_back(NTL::RandomBnd(mPubKey.n));
    }

    std::vector<ZZ> roots;
    roots.reserve(paddedInputs.size());
    for (const auto& input : paddedInputs) {
        ZZ reduced = input % mPubKey.n;
        if (reduced < 0)
            reduced += mPubKey.n;
        roots.push_back(reduced);
    }

    Polynomial plaintext_poly = encodeAsPolynomial(roots, mPubKey.n);
    logger.log("Leader encoded ", paddedInputs.size(), " inputs, degree: ", plaintext_poly.degree());

    // Encrypt polynomial coefficients in parallel
    std::vector<Ciphertext> encrypted_coeffs(plaintext_poly.coefficients.size());
    std::vector<std::thread> threads;
    threads.reserve(numMembers);

    for (u64 threadIdx = 0; threadIdx < numMembers; ++threadIdx) {
        threads.emplace_back([&, threadIdx]() {
            for (u64 i = threadIdx; i < plaintext_poly.coefficients.size(); i += numMembers)
                encrypted_coeffs[i] = enc(plaintext_poly.coefficients[i], mPubKey);
        });
    }
    for (auto& th : threads)
        if (th.joinable()) th.join();

    PaillierPolynomial encPoly(encrypted_coeffs, mPubKey);
    logger.log("Leader encrypted polynomial, degree: ", encPoly.degree());

    // Step 2: Ring aggregation - send to first member, receive from last
    u64 firstParty = 0;
    u64 lastParty = numMembers - 1;

    u64 numCoeffs = encPoly.coefficients.size();
    channels[firstParty]->sendU64(numCoeffs);

    for (const auto& coeff : encPoly.coefficients) {
        std::string serialized;
        serializeCiphertext(coeff, serialized);
        channels[firstParty]->sendBytes(serialized);
    }

    logger.log("Leader sent polynomial to first party");

    // Receive aggregated polynomial from last party
    numCoeffs = channels[lastParty]->recvU64();
    checkCoeffCount(numCoeffs);

    std::vector<Ciphertext> aggCoeffs;
    aggCoeffs.reserve(numCoeffs);
    for (u64 i = 0; i < numCoeffs; ++i) {
        std::string ser = channels[lastParty]->recvBytes();
        Ciphertext coeff;
        deserializeCiphertext(ser, coeff);
        aggCoeffs.push_back(coeff);
    }

    encPoly = PaillierPolynomial(aggCoeffs, mPubKey);
    logger.log("Leader received aggregated polynomial, degree: ", encPoly.degree());

    // Step 3: Broadcast aggregated polynomial to all members
    numCoeffs = encPoly.coefficients.size();

    threads.clear();
    threads.reserve(numMembers);
    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx) {
        threads.emplace_back([&, memberIdx]() {
            channels[memberIdx]->sendU64(numCoeffs);
            for (const auto& coeff : encPoly.coefficients) {
                std::string serialized;
                serializeCiphertext(coeff, serialized);
                channels[memberIdx]->sendBytes(serialized);
            }
        });
    }
    for (auto& th : threads)
        if (th.joinable()) th.join();

    logger.log("Leader broadcasted polynomial to all members");

    // Step 4: Receive blinded polynomials from all members
    std::vector<PaillierPolynomial> blindedPolys;
    blindedPolys.reserve(numMembers);

    std::vector<std::vector<Ciphertext>> allMemberCoeffs(numMembers);

    threads.clear();
    threads.reserve(numMembers);
    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx) {
        threads.emplace_back([&, memberIdx]() {
            u64 memberNumCoeffs = channels[memberIdx]->recvU64();
            checkCoeffCount(memberNumCoeffs);

            allMemberCoeffs[memberIdx].reserve(memberNumCoeffs);
            for (u64 i = 0; i < memberNumCoeffs; ++i) {
                std::string ser = channels[memberIdx]->recvBytes();
                Ciphertext coeff;
                deserializeCiphertext(ser, coeff);
                allMemberCoeffs[memberIdx].push_back(coeff);
            }
        });
    }
    for (auto& th : threads)
        if (th.joinable()) th.join();

    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        blindedPolys.emplace_back(allMemberCoeffs[memberIdx], mPubKey);

    logger.log("Leader received blinded polynomials");

    // Step 5: Sum all blinded polynomials
    PaillierPolynomial summedPoly = blindedPolys[0];
    for (u64 memberIdx = 1; memberIdx < numMembers; ++memberIdx)
        summedPoly.addPoly(blindedPolys[memberIdx]);

    logger.log("Leader summed blinded polynomials, degree: ", summedPoly.degree());

    // Step 6: Joint decryption
    std::vector<Ciphertext> encryptedCoeffs = summedPoly.coefficients;
    u64 numCoeffsToDecrypt = encryptedCoeffs.size();
    u64 numEvaluations = numCoeffsToDecrypt;

    // Broadcast for joint decryption
    threads.clear();
    threads.reserve(numMembers);
    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx) {
        threads.emplace_back([&, memberIdx]() {
            channels[memberIdx]->sendU64(numEvaluations);
            for (const auto& ct : encryptedCoeffs) {
                std::string serialized;
                serializeCiphertext(ct, serialized);
                channels[memberIdx]->sendBytes(serialized);
            }
        });
    }
    for (auto& th : threads)
        if (th.joinable()) th.join();

    logger.log("Leader broadcasted ciphertexts for joint decryption");

    // Leader's partial decryption
    std::vector<std::vector<Ciphertext>> allPartialDecryptions(numEvaluations);
    for (u64 i = 0; i < numEvaluations; ++i)
        allPartialDecryptions[i].resize(numMembers + 1);

    threads.clear();
    threads.reserve(numMembers);
    for (u64 threadIdx = 0; threadIdx < numMembers; ++threadIdx) {
        threads.emplace_back([&, threadIdx]() {
            for (u64 i = threadIdx; i < numEvaluations; i += numMembers)
                allPartialDecryptions[i][numMembers] = partialDec(encryptedCoeffs[i], mPubKey, mPrivKey);
        });
    }
    for (auto& th : threads)
        if (th.joinable()) th.join();

    logger.log("Leader completed partial decryption");

    // Receive partial decryptions from all members
    threads.clear();
    threads.reserve(numMembers);
    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx) {
        threads.emplace_back([&, memberIdx]() {
            u64 numPartials = channels[memberIdx]->recvU64();
            checkCoeffCount(numPartials);
            for (u64 i = 0; i < numPartials; ++i) {
                std::string ser = channels[memberIdx]->recvBytes();
                deserializeCiphertext(ser, allPartialDecryptions[i][memberIdx]);
            }
        });
    }
    for (auto& th : threads)
        if (th.joinable()) th.join();

    logger.log("Leader received partial decryptions");

    // Fuse partial decryptions
    std::vector<Plaintext> decryptedResults(numEvaluations);

    threads.clear();
    threads.reserve(numMembers);
    for (u64 threadIdx = 0; threadIdx < numMembers; ++threadIdx) {
        threads.emplace_back([&, threadIdx]() {
            for (u64 i = threadIdx; i < numEvaluations; i += numMembers)
                decryptedResults[i] = fuseDec(allPartialDecryptions[i], mPubKey);
        });
    }
    for (auto& th : threads)
        if (th.joinable()) th.join();

    logger.log("Leader completed joint decryption");

    // Step 7: Find intersection by polynomial evaluation
    Polynomial decryptedPoly(decryptedResults);
    logger.log("Leader reconstructed polynomial, degree: ", decryptedPoly.degree());

    std::vector<ZZ> intersection;
    intersection.reserve(inputs.size());

    for (const auto& input : inputs) {
        ZZ y = input % mPubKey.n;
        if (y < 0)
            y += mPubKey.n;

        ZZ result = decryptedPoly.evaluateAt(y, mPubKey.n);
        if (result == 0)
            intersection.push_back(input);
    }

    logger.log("Leader found intersection: ", intersection.size(), " / ", inputs.size());

    return intersection;
}

} // namespace mpsi::ks05
