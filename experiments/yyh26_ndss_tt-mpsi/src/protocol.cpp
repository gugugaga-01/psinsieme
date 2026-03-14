#include "protocol.h"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <unistd.h>

using namespace lbcrypto;
// Note: do NOT "using namespace osuCrypto" — it conflicts with osuCryptoNew
// (e.g., block, PRNG, toBlock are ambiguous). Use explicit qualifiers.

namespace yyh26 {

// Number of OPPRF instances = (NUM_CRT_MODULI + 1 (OLE index)) * nParties
// Phase 1: NUM_CRT_MODULI rounds, Phase 3: NUM_CRT_MODULI + 1 rounds

std::unordered_set<u64> tparty(
    u64 myIdx, u64 nParties, u64 threshold, u64 setSize)
{
    // Bring in osuCrypto types that don't conflict with osuCryptoNew
    using osuCrypto::KkrtNcoOtReceiver;
    using osuCrypto::KkrtNcoOtSender;
    using osuCrypto::OPPRFSender;
    using osuCrypto::OPPRFReceiver;
    using osuCrypto::binSet;
    using osuCrypto::block;
    using osuCrypto::ZeroBlock;

    u64 leaderIdx = nParties - 1;
    u64 totalNumShares = nParties;
    u64 numThreads = 1;

    // CRT moduli as vector (for OPPRF interface)
    std::vector<u64> twoModulo = {CRT_MODULI[0], CRT_MODULI[1]};
    std::vector<NTL::ZZ> twoModuloZZ;
    for (auto mod : twoModulo) twoModuloZZ.push_back(NTL::ZZ(mod));

    // Large prime for ZZ_p context (must be > product of CRT moduli)
    NTL::ZZ p = NTL::conv<NTL::ZZ>("339933312435546022214350946152556052481");

    osuCrypto::PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));

    // ── Generate set ──
    auto now = std::chrono::high_resolution_clock::now();
    unsigned int seed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();
    seed ^= static_cast<unsigned int>(getpid());
    srand(seed);

    std::vector<NTL::ZZ> set_zz(setSize);
    std::vector<osuCrypto::block> set(setSize);
    std::set<int> party_set;

    u64 elementRange = (nParties / 2) * setSize;
    assert(elementRange < MAX_ELEMENT_VALUE &&
           "Element range must fit in 24 bits for 2-modulus CRT");

    for (u64 j = 0; j < setSize; j++) {
        u64 new_element;
        do {
            new_element = rand() % elementRange;
        } while (party_set.find(new_element) != party_set.end());

        party_set.insert(new_element);
        set[j] = osuCrypto::toBlock(new_element);
        set_zz[j] = NTL::conv<NTL::ZZ>(new_element);
    }

    // ══════════════════════════════════════════════
    // Setup channels for Phase 1 (OPPRF)
    // ══════════════════════════════════════════════
    ChannelSet channels(myIdx, nParties, numThreads);
    channels.setupOPPRF();
    syncParties(myIdx, channels.opprfChls);

    // ── Hashing ──
    u64 opt = 0;
    binSet bins;
    bins.init(myIdx, nParties, setSize, PSI_SEC_PARAM, opt);
    bins.hashing2Bins(set, 1);

    u64 otCountSend = bins.mSimpleBins.mBins.size();
    u64 otCountRecv = bins.mCuckooBins.mBins.size();

    // OPPRF instances: need (NUM_CRT_MODULI * nParties) for Phase 1,
    // (NUM_CRT_MODULI + 1) * nParties for Phase 3
    u64 opprfNum = (2 * NUM_CRT_MODULI + 1) * nParties;
    std::vector<KkrtNcoOtReceiver> otRecv(opprfNum);
    std::vector<KkrtNcoOtSender> otSend(opprfNum);
    std::vector<OPPRFSender> send(opprfNum);
    std::vector<OPPRFReceiver> recv(opprfNum);

    // ══════════════════════════════════════════════
    // Phase 1: Secret Sharing + OPPRF
    // ══════════════════════════════════════════════
    auto phase1Start = std::chrono::high_resolution_clock::now();

    // Secret sharing payloads: NUM_CRT_MODULI * nParties * setSize
    std::vector<std::vector<std::vector<block>>>
        sendSSPayLoads(NUM_CRT_MODULI),
        recvSSPayLoads(NUM_CRT_MODULI);

    // Leader's server shares: NUM_CRT_MODULI * setSize (as ZZ)
    std::vector<std::vector<NTL::ZZ>> ServerShares(NUM_CRT_MODULI);
    for (int i = 0; i < NUM_CRT_MODULI; i++)
        ServerShares[i].resize(setSize);

    for (int i = 0; i < NUM_CRT_MODULI; i++) {
        recvSSPayLoads[i].resize(totalNumShares);
        sendSSPayLoads[i].resize(totalNumShares);
        for (u64 j = 0; j < totalNumShares; j++) {
            recvSSPayLoads[i][j].resize(setSize);
            sendSSPayLoads[i][j].resize(setSize);
        }
    }

    // Leader creates Shamir shares
    std::vector<std::vector<std::vector<NTL::ZZ_p>>> shares_zz(NUM_CRT_MODULI);
    if (myIdx == leaderIdx) {
        NTL::ZZ_p::init(p);
        for (int i = 0; i < NUM_CRT_MODULI; i++) {
            shares_zz[i].resize(totalNumShares,
                std::vector<NTL::ZZ_p>(setSize));
            NTL::ZZ currentModulo = NTL::conv<NTL::ZZ>(twoModulo[i]);

            for (u64 j = 0; j < setSize; j++) {
                NTL::ZZ_p secret = NTL::conv<NTL::ZZ_p>(set_zz[j]);
                std::vector<NTL::ZZ_p> secretShares =
                    ShareSecret(secret, totalNumShares, threshold, currentModulo);
                NTL::ZZ_p::init(p);

                for (u64 k = 0; k < totalNumShares; k++)
                    shares_zz[i][k][j] = secretShares[k];

                ServerShares[i][j] =
                    NTL::conv<NTL::ZZ>(shares_zz[i][totalNumShares - 1][j]);
            }

            // Convert shares to blocks for OPPRF transmission
            for (u64 j = 0; j < totalNumShares; j++) {
                for (u64 k = 0; k < setSize; k++) {
                    NTL::BytesFromZZ((u8*)&sendSSPayLoads[i][j][k],
                        NTL::conv<NTL::ZZ>(shares_zz[i][j][k]),
                        sizeof(block));
                }
            }
        }
    }

    // Run NUM_CRT_MODULI OPPRF rounds (Phase 1: distribute shares)
    for (int modIdx = 0; modIdx < NUM_CRT_MODULI; modIdx++) {
        u64 thrBase = modIdx * nParties;

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                send[thr].init(opt, nParties, setSize, PSI_SEC_PARAM,
                    BIT_SIZE, channels.opprfChls[pIdx], otCountSend,
                    otSend[thr], otRecv[thr],
                    prng.get<block>(), false);
            }
        } else {
            u64 thr = thrBase;
            recv[modIdx].init(opt, nParties, setSize, PSI_SEC_PARAM,
                BIT_SIZE, channels.opprfChls[leaderIdx], otCountRecv,
                otRecv[thr], otSend[thr],
                ZeroBlock, false);
        }

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                send[thr].getOPRFkeys(pIdx, bins,
                    channels.opprfChls[pIdx], false);
            }
        } else {
            recv[modIdx].getOPRFkeys(leaderIdx, bins,
                channels.opprfChls[leaderIdx], false);
        }

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                send[thr].sendSSTableBased(pIdx, bins,
                    sendSSPayLoads[modIdx][pIdx],
                    channels.opprfChls[pIdx], twoModulo, modIdx);
            }
        } else {
            recv[modIdx].recvSSTableBased(leaderIdx, bins,
                recvSSPayLoads[modIdx][0],
                channels.opprfChls[leaderIdx], twoModulo, modIdx);
        }

        // Reset bin state for next OPPRF round
        for (size_t i = 0; i < bins.mSimpleBins.mBins.size(); i++) {
            for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++) {
                bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
                bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
            }
        }
    }

    auto phase1End = std::chrono::high_resolution_clock::now();

    // ══════════════════════════════════════════════
    // Prepare update values (between Phase 1 and Phase 2)
    // ══════════════════════════════════════════════
    u64 UpdateValueSize = bins.mSimpleBins.mBins.size();

    std::vector<std::vector<std::vector<NTL::ZZ_p>>> genUpdateValues(NUM_CRT_MODULI);
    std::vector<std::vector<std::vector<block>>> sendUpdateValues(NUM_CRT_MODULI);
    std::vector<std::vector<std::vector<NTL::ZZ>>> serverUpdateValues(NUM_CRT_MODULI);

    for (int i = 0; i < NUM_CRT_MODULI; i++) {
        sendUpdateValues[i].resize(totalNumShares);
        for (u64 j = 0; j < totalNumShares; j++)
            sendUpdateValues[i][j].resize(UpdateValueSize);
    }

    for (int i = 0; i < NUM_CRT_MODULI; i++) {
        serverUpdateValues[i].resize(nParties);
        for (u64 j = 0; j < nParties; j++)
            serverUpdateValues[i][j].resize(UpdateValueSize);
    }

    // Each non-leader party generates update values
    if (myIdx != leaderIdx) {
        for (int i = 0; i < NUM_CRT_MODULI; i++) {
            NTL::ZZ currentModulo = NTL::conv<NTL::ZZ>(twoModulo[i]);
            genUpdateValues[i].resize(UpdateValueSize);

            for (u64 j = 0; j < UpdateValueSize; j++) {
                genUpdateValues[i][j] =
                    GenerateUpdateValues(totalNumShares, threshold, currentModulo);
                NTL::ZZ_p::init(p);
            }

            for (u64 j = 0; j < totalNumShares; j++) {
                for (u64 k = 0; k < UpdateValueSize; k++) {
                    NTL::BytesFromZZ((u8*)&sendUpdateValues[i][j][k],
                        rep(genUpdateValues[i][k][j]), sizeof(block));
                }
            }
        }
    }

    // Send update values to leader via OPPRF channels
    if (myIdx != leaderIdx) {
        for (int i = 0; i < NUM_CRT_MODULI; i++) {
            for (u64 j = 0; j < UpdateValueSize; j++) {
                unsigned char buf[4]; // 32-bit value
                NTL::ZZ value = NTL::conv<NTL::ZZ>(
                    genUpdateValues[i][j][totalNumShares - 1]);
                NTL::BytesFromZZ(buf, value, 4);
                channels.opprfChls[leaderIdx][0]->send(&buf, 4);
            }
        }
    } else {
        for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
            for (int i = 0; i < NUM_CRT_MODULI; i++) {
                for (u64 j = 0; j < UpdateValueSize; j++) {
                    unsigned char buf[4];
                    channels.opprfChls[pIdx][0]->recv(&buf, 4);
                    NTL::ZZFromBytes(serverUpdateValues[i][pIdx][j], buf, 4);
                }
            }
        }
    }

    // Leader updates its shares
    if (myIdx == leaderIdx) {
        // Sum up all clients' update values
        for (int i = 0; i < NUM_CRT_MODULI; i++) {
            NTL::ZZ mod = NTL::conv<NTL::ZZ>(twoModulo[i]);
            for (u64 j = 0; j < nParties - 1; j++) {
                for (u64 k = 0; k < UpdateValueSize; k++) {
                    serverUpdateValues[i][nParties - 1][k] += serverUpdateValues[i][j][k];
                    serverUpdateValues[i][nParties - 1][k] %= mod;
                }
            }
        }

        // Add aggregated update values to leader's shares
        for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++) {
            auto& bin = bins.mCuckooBins.mBins[bIdx];
            if (!bin.isEmpty()) {
                u64 inputIdx = bin.idx();
                for (int i = 0; i < NUM_CRT_MODULI; i++) {
                    NTL::ZZ mod = NTL::conv<NTL::ZZ>(twoModulo[i]);
                    ServerShares[i][inputIdx] = AddMod(
                        ServerShares[i][inputIdx],
                        serverUpdateValues[i][nParties - 1][bIdx], mod);
                }
            }
        }
    }

    // OPPRF channels stay open — used again in Phase 3

    // ══════════════════════════════════════════════
    // Phase 2: OLE (BOLE)
    // ══════════════════════════════════════════════
    auto phase2Start = std::chrono::high_resolution_clock::now();
    channels.setupOLE();

    constexpr ui32 logn = BOLE_LOGN;
    const ui32 oleSize = 1 << logn;

    // Leader OLE with each client
    u64 leaderOleNum = (nParties - 1) *
        (bins.mCuckooBins.mBinCount[0] * bins.mCuckooBins.mParams.mSenderBinSize[0] +
         bins.mCuckooBins.mBinCount[1] * bins.mCuckooBins.mParams.mSenderBinSize[1]);
    u64 leaderBoleNum = static_cast<u64>(
        ceil(leaderOleNum / (oleSize * 1.0)));
    // Leader input: element values replicated across bin positions
    std::vector<std::vector<uint64_t>> leaderInput(leaderBoleNum);
    for (u64 i = 0; i < leaderInput.size(); i++)
        leaderInput[i].resize(oleSize);

    // Random and partial update values for OLE
    std::vector<std::vector<std::vector<uint64_t>>> randomValue(nParties - 1);
    std::vector<std::vector<std::vector<uint64_t>>> partUpValue(nParties - 1);
    std::vector<std::vector<std::vector<uint64_t>>> recvOLE(nParties - 1);

    std::vector<std::vector<uint64_t>> randomValueForLeader(leaderBoleNum);
    std::vector<std::vector<uint64_t>> partUpValueForLeader(leaderBoleNum);
    std::vector<std::vector<uint64_t>> UpdateForLeader(leaderBoleNum);
    std::vector<std::vector<uint64_t>> ReInput(leaderBoleNum);

    for (u64 i = 0; i < randomValueForLeader.size(); i++) {
        randomValueForLeader[i].resize(oleSize);
        partUpValueForLeader[i].resize(oleSize);
        UpdateForLeader[i].resize(oleSize);
    }

    NTL::ZZ element;

    // Prepare random values (non-leader only)
    if (myIdx != leaderIdx) {
        for (u64 i = 0; i < nParties - 1; i++) {
            randomValue[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
            partUpValue[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
            for (u64 j = 0; j < bins.mSimpleBins.mMaxBinSize[1]; j++) {
                randomValue[i][j].resize(UpdateValueSize);
                partUpValue[i][j].resize(UpdateValueSize);
                for (u64 k = 0; k < UpdateValueSize; k++) {
                    // Random CRT-packed values
                    NTL::RandomBnd(element, p);
                    randomValue[i][j][k] = crt_encode(
                        NTL::conv<long>(element) % MAX_ELEMENT_VALUE);
                    NTL::RandomBnd(element, p);
                    partUpValue[i][j][k] = crt_encode(
                        NTL::conv<long>(element) % MAX_ELEMENT_VALUE);
                }
            }
        }

        // Pack into OLE-sized blocks
        int row = 0, col = 0;
        for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
            for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++) {
                u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                    ? bins.mSimpleBins.mMaxBinSize[0]
                    : bins.mSimpleBins.mMaxBinSize[1];
                for (u64 eIdx = 0; eIdx < numMax; eIdx++) {
                    if (col >= oleSize) { row++; col = 0; }
                    randomValueForLeader[row][col] = randomValue[pIdx][eIdx][bIdx];
                    partUpValueForLeader[row][col] = partUpValue[pIdx][eIdx][bIdx];
                    col++;
                }
            }
        }
    }

    for (u64 i = 0; i < recvOLE.size(); i++) {
        recvOLE[i].resize(leaderBoleNum);
        for (u64 j = 0; j < recvOLE[i].size(); j++)
            recvOLE[i][j].resize(oleSize);
    }

    // ── Leader-Client OLE ──
    if (myIdx == leaderIdx) {
        // Prepare leader input
        int row = 0, col = 0;
        for (u64 uIdx = 0; uIdx < nParties - 1; uIdx++) {
            for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++) {
                auto& bin = bins.mCuckooBins.mBins[bIdx];
                uint64_t inputVal;
                if (!bin.isEmpty()) {
                    inputVal = crt_encode(
                        NTL::conv<long>(set_zz[bin.idx()]));
                } else {
                    NTL::RandomBnd(element, p);
                    inputVal = crt_encode(
                        NTL::conv<long>(element) % MAX_ELEMENT_VALUE);
                }

                u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                    ? bins.mSimpleBins.mMaxBinSize[0]
                    : bins.mSimpleBins.mMaxBinSize[1];
                for (u64 numinBin = 0; numinBin < numMax; numinBin++) {
                    if (col >= oleSize) { row++; col = 0; }
                    leaderInput[row][col] = inputVal;
                    col++;
                }
            }
        }

        // Run BOLE with each client
        for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
            auto& oleChl = channels.oleChls[pIdx][0];

            const MainSchemeType scheme(BOLE_STD_DEV);
            using KPS = typename MainSchemeType::KeyPairSeeded;
            using SK = typename MainSchemeType::SecretKey;

            KPS kpSeeded = scheme.KeyGenSeeded();
            sendPublicKey(kpSeeded.pkSeeded, oleChl);
            SK& sk = kpSeeded.sk;

            using enc_input_t = typename MainSchemeType::encoding_context_t::encoding_input_t;

            // Prepare receiver inputs (split CRT)
            TwoBOLEReceiverInputs<enc_input_t> twoInputs(leaderBoleNum);
            twoInputs.processModule(leaderInput);

            // Run 2 BOLE calls (one per modulus)
            std::vector<BOLEReceiverOutput<enc_input_t>> twoOutputs(NUM_CRT_MODULI);

            twoOutputs[0] = ReceiverOnline<CRT_MODULI[0], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                twoInputs.receiverInputs[0], sk, scheme, oleChl);
            twoOutputs[1] = ReceiverOnline<CRT_MODULI[1], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                twoInputs.receiverInputs[1], sk, scheme, oleChl);

            // Pack outputs back to u64
            for (u64 BoleIdx = 0; BoleIdx < leaderBoleNum; BoleIdx++) {
                for (u64 i = 0; i < oleSize; i++) {
                    uint32_t r0 = static_cast<uint32_t>(
                        twoOutputs[0].cBlocks[BoleIdx][i]);
                    uint32_t r1 = static_cast<uint32_t>(
                        twoOutputs[1].cBlocks[BoleIdx][i]);
                    recvOLE[pIdx][BoleIdx][i] = crt_pack(r0, r1);
                }
            }
        }
    } else {
        // Client (OLE sender) with leader
        auto& oleChl = channels.oleChls[leaderIdx][0];

        const MainSchemeType scheme(BOLE_STD_DEV);
        using SPK = typename MainSchemeType::PublicKeySeeded;
        using PK = typename MainSchemeType::PublicKey;
        SPK seededPK;
        receivePublicKey(seededPK, oleChl);
        PK pk = seededPK.expand();

        // Prepare update values for OLE-sized blocks
        int row = 0, col = 0;
        for (u64 uIdx = 0; uIdx < nParties - 1; uIdx++) {
            for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++) {
                // Get packed update value from sendUpdateValues
                uint64_t updatePacked = 0;
                for (int m = 0; m < NUM_CRT_MODULI; m++) {
                    NTL::ZZ part_zz = NTL::ZZFromBytes(
                        (u8*)&sendUpdateValues[m][uIdx][bIdx], sizeof(block));
                    uint32_t part = static_cast<uint32_t>(
                        NTL::conv<long>(part_zz) % CRT_MODULI[m]);
                    if (m == 0) updatePacked |= static_cast<uint64_t>(part);
                    else updatePacked |= static_cast<uint64_t>(part) << 32;
                }

                u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                    ? bins.mSimpleBins.mMaxBinSize[0]
                    : bins.mSimpleBins.mMaxBinSize[1];
                for (u64 numinBin = 0; numinBin < numMax; numinBin++) {
                    if (col >= oleSize) { row++; col = 0; }
                    UpdateForLeader[row][col] = updatePacked;
                    col++;
                }
            }
        }

        using enc_input_t = typename MainSchemeType::encoding_context_t::encoding_input_t;

        // Prepare sender a/b vectors per modulus
        std::vector<std::vector<enc_input_t>> aVecs(NUM_CRT_MODULI);
        std::vector<std::vector<enc_input_t>> bVecs(NUM_CRT_MODULI);

        for (int m = 0; m < NUM_CRT_MODULI; m++) {
            aVecs[m].resize(leaderBoleNum);
            bVecs[m].resize(leaderBoleNum);
            for (u64 BoleIdx = 0; BoleIdx < leaderBoleNum; BoleIdx++) {
                for (ui32 j = 0; j < oleSize; j++) {
                    auto [rv0, rv1] = crt_unpack(randomValueForLeader[BoleIdx][j]);
                    auto [up0, up1] = crt_unpack(partUpValueForLeader[BoleIdx][j]);
                    auto [uv0, uv1] = crt_unpack(UpdateForLeader[BoleIdx][j]);

                    uint32_t rv = (m == 0) ? rv0 : rv1;
                    uint32_t up = (m == 0) ? up0 : up1;
                    uint32_t uv = (m == 0) ? uv0 : uv1;

                    aVecs[m][BoleIdx].vals[j] =
                        static_cast<ui128>(rv % CRT_MODULI[m]);
                    bVecs[m][BoleIdx].vals[j] =
                        static_cast<ui128>((uv + CRT_MODULI[m] - up) % CRT_MODULI[m]);
                }
            }
        }

        BOLESenderInput<enc_input_t> senderInput0(aVecs[0], bVecs[0]);
        BOLESenderInput<enc_input_t> senderInput1(aVecs[1], bVecs[1]);

        SenderOnline<CRT_MODULI[0], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
            senderInput0, pk, scheme, oleChl);
        SenderOnline<CRT_MODULI[1], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
            senderInput1, pk, scheme, oleChl);
    }

    // ── Client-Client OLE ──
    u64 ClientOleNum =
        bins.mSimpleBins.mBinCount[0] * bins.mSimpleBins.mMaxBinSize[0] +
        bins.mSimpleBins.mBinCount[1] * bins.mSimpleBins.mMaxBinSize[1];
    u64 ClientBoleNum = static_cast<u64>(ceil(ClientOleNum / (1.0 * oleSize)));

    std::vector<std::vector<uint64_t>> ClientInput(ClientBoleNum);
    std::vector<std::vector<uint64_t>> randomValueForClient(ClientBoleNum);
    std::vector<std::vector<uint64_t>> partUpValueForClient(ClientBoleNum);
    std::vector<std::vector<uint64_t>> UpdateForClient(ClientBoleNum);

    for (u64 i = 0; i < ClientBoleNum; i++) {
        ClientInput[i].resize(oleSize);
        randomValueForClient[i].resize(oleSize);
        partUpValueForClient[i].resize(oleSize);
        UpdateForClient[i].resize(oleSize);
    }

    if (myIdx != leaderIdx) {
        // Prepare client input from bin contents
        u64 row = 0, col = 0;
        for (u64 bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++) {
            auto& bin = bins.mSimpleBins.mBins[bIdx];
            auto eNum = bin.mIdx.size();
            for (u64 i = 0; i < eNum; i++) {
                if (col >= oleSize) { row++; col = 0; }
                u64 elemVal = NTL::conv<long>(set_zz[bin.mIdx[i]]);
                ClientInput[row][col] = crt_encode(elemVal);
                col++;
            }
            u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                ? bins.mSimpleBins.mMaxBinSize[0]
                : bins.mSimpleBins.mMaxBinSize[1];
            for (u64 i = eNum; i < numMax; i++) {
                if (col >= oleSize) { row++; col = 0; }
                NTL::RandomBnd(element, p);
                ClientInput[row][col] = crt_encode(
                    NTL::conv<long>(element) % MAX_ELEMENT_VALUE);
                col++;
            }
        }

        recvOLE.resize(nParties - 1);
        for (u64 i = 0; i < recvOLE.size(); i++) {
            recvOLE[i].resize(ClientBoleNum);
            for (u64 j = 0; j < recvOLE[i].size(); j++)
                recvOLE[i][j].resize(oleSize);
        }

        // First pass: myIdx > pIdx => receiver, myIdx < pIdx => sender
        for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
            if (myIdx > pIdx) {
                // OLE receiver
                auto& oleChl = channels.oleChls[pIdx][0];
                const MainSchemeType scheme(BOLE_STD_DEV);
                auto kpSeeded = scheme.KeyGenSeeded();
                sendPublicKey(kpSeeded.pkSeeded, oleChl);
                auto& sk = kpSeeded.sk;

                using enc_input_t = typename MainSchemeType::encoding_context_t::encoding_input_t;
                TwoBOLEReceiverInputs<enc_input_t> twoInputs(ClientBoleNum);
                twoInputs.processModule(ClientInput);

                std::vector<BOLEReceiverOutput<enc_input_t>> twoOutputs(NUM_CRT_MODULI);
                twoOutputs[0] = ReceiverOnline<CRT_MODULI[0], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    twoInputs.receiverInputs[0], sk, scheme, oleChl);
                twoOutputs[1] = ReceiverOnline<CRT_MODULI[1], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    twoInputs.receiverInputs[1], sk, scheme, oleChl);

                for (u64 BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++) {
                    for (u64 i = 0; i < oleSize; i++) {
                        recvOLE[pIdx][BoleIdx][i] = crt_pack(
                            static_cast<uint32_t>(twoOutputs[0].cBlocks[BoleIdx][i]),
                            static_cast<uint32_t>(twoOutputs[1].cBlocks[BoleIdx][i]));
                    }
                }
            } else if (myIdx < pIdx) {
                // OLE sender — prepare a/b from random/partUp values
                int row = 0, col = 0;
                auto& oleChl = channels.oleChls[pIdx][0];

                for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++) {
                    u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                        ? bins.mSimpleBins.mMaxBinSize[0]
                        : bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 eIdx = 0; eIdx < numMax; eIdx++) {
                        if (col >= oleSize) { row++; col = 0; }
                        randomValueForClient[row][col] = randomValue[pIdx][eIdx][bIdx];
                        partUpValueForClient[row][col] = partUpValue[pIdx][eIdx][bIdx];
                        col++;
                    }
                }

                const MainSchemeType scheme(BOLE_STD_DEV);
                typename MainSchemeType::PublicKeySeeded seededPK;
                receivePublicKey(seededPK, oleChl);
                auto pk = seededPK.expand();

                using enc_input_t = typename MainSchemeType::encoding_context_t::encoding_input_t;
                std::vector<std::vector<enc_input_t>> aVecs(NUM_CRT_MODULI);
                std::vector<std::vector<enc_input_t>> bVecs(NUM_CRT_MODULI);

                for (int m = 0; m < NUM_CRT_MODULI; m++) {
                    aVecs[m].resize(ClientBoleNum);
                    bVecs[m].resize(ClientBoleNum);
                    for (u64 BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++) {
                        for (ui32 j = 0; j < oleSize; j++) {
                            auto [rv0, rv1] = crt_unpack(randomValueForClient[BoleIdx][j]);
                            auto [pv0, pv1] = crt_unpack(partUpValueForClient[BoleIdx][j]);
                            uint32_t rv = (m == 0) ? rv0 : rv1;
                            uint32_t pv = (m == 0) ? pv0 : pv1;
                            aVecs[m][BoleIdx].vals[j] =
                                static_cast<ui128>((CRT_MODULI[m] - rv % CRT_MODULI[m]) % CRT_MODULI[m]);
                            bVecs[m][BoleIdx].vals[j] =
                                static_cast<ui128>(pv % CRT_MODULI[m]);
                        }
                    }
                }

                BOLESenderInput<enc_input_t> si0(aVecs[0], bVecs[0]);
                BOLESenderInput<enc_input_t> si1(aVecs[1], bVecs[1]);
                SenderOnline<CRT_MODULI[0], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    si0, pk, scheme, oleChl);
                SenderOnline<CRT_MODULI[1], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    si1, pk, scheme, oleChl);
            }
        }

        // Second pass: reversed roles
        for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
            if (myIdx < pIdx) {
                // OLE receiver
                auto& oleChl = channels.oleChls[pIdx][0];
                const MainSchemeType scheme(BOLE_STD_DEV);
                auto kpSeeded = scheme.KeyGenSeeded();
                sendPublicKey(kpSeeded.pkSeeded, oleChl);
                auto& sk = kpSeeded.sk;

                using enc_input_t = typename MainSchemeType::encoding_context_t::encoding_input_t;
                TwoBOLEReceiverInputs<enc_input_t> twoInputs(ClientBoleNum);
                twoInputs.processModule(ClientInput);

                std::vector<BOLEReceiverOutput<enc_input_t>> twoOutputs(NUM_CRT_MODULI);
                twoOutputs[0] = ReceiverOnline<CRT_MODULI[0], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    twoInputs.receiverInputs[0], sk, scheme, oleChl);
                twoOutputs[1] = ReceiverOnline<CRT_MODULI[1], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    twoInputs.receiverInputs[1], sk, scheme, oleChl);

                for (u64 BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++) {
                    for (u64 i = 0; i < oleSize; i++) {
                        recvOLE[pIdx][BoleIdx][i] = crt_pack(
                            static_cast<uint32_t>(twoOutputs[0].cBlocks[BoleIdx][i]),
                            static_cast<uint32_t>(twoOutputs[1].cBlocks[BoleIdx][i]));
                    }
                }
            } else if (myIdx > pIdx) {
                // OLE sender
                int row = 0, col = 0;
                auto& oleChl = channels.oleChls[pIdx][0];

                for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++) {
                    u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                        ? bins.mSimpleBins.mMaxBinSize[0]
                        : bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 eIdx = 0; eIdx < numMax; eIdx++) {
                        if (col >= oleSize) { row++; col = 0; }
                        randomValueForClient[row][col] = randomValue[pIdx][eIdx][bIdx];
                        partUpValueForClient[row][col] = partUpValue[pIdx][eIdx][bIdx];
                        col++;
                    }
                }

                const MainSchemeType scheme(BOLE_STD_DEV);
                typename MainSchemeType::PublicKeySeeded seededPK;
                receivePublicKey(seededPK, oleChl);
                auto pk = seededPK.expand();

                using enc_input_t = typename MainSchemeType::encoding_context_t::encoding_input_t;
                std::vector<std::vector<enc_input_t>> aVecs(NUM_CRT_MODULI);
                std::vector<std::vector<enc_input_t>> bVecs(NUM_CRT_MODULI);

                for (int m = 0; m < NUM_CRT_MODULI; m++) {
                    aVecs[m].resize(ClientBoleNum);
                    bVecs[m].resize(ClientBoleNum);
                    for (u64 BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++) {
                        for (ui32 j = 0; j < oleSize; j++) {
                            auto [rv0, rv1] = crt_unpack(randomValueForClient[BoleIdx][j]);
                            auto [pv0, pv1] = crt_unpack(partUpValueForClient[BoleIdx][j]);
                            uint32_t rv = (m == 0) ? rv0 : rv1;
                            uint32_t pv = (m == 0) ? pv0 : pv1;
                            aVecs[m][BoleIdx].vals[j] =
                                static_cast<ui128>((CRT_MODULI[m] - rv % CRT_MODULI[m]) % CRT_MODULI[m]);
                            bVecs[m][BoleIdx].vals[j] =
                                static_cast<ui128>(pv % CRT_MODULI[m]);
                        }
                    }
                }

                BOLESenderInput<enc_input_t> si0(aVecs[0], bVecs[0]);
                BOLESenderInput<enc_input_t> si1(aVecs[1], bVecs[1]);
                SenderOnline<CRT_MODULI[0], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    si0, pk, scheme, oleChl);
                SenderOnline<CRT_MODULI[1], BOLE_LOGN, BOLE_NUM_LIMBS, MainSchemeType>(
                    si1, pk, scheme, oleChl);
            }
        }
    }

    // ── Process OLE results ──
    std::vector<std::vector<std::vector<uint64_t>>> OLE_result(nParties - 1);
    for (u64 i = 0; i < OLE_result.size(); i++) {
        OLE_result[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
        for (u64 j = 0; j < OLE_result[i].size(); j++)
            OLE_result[i][j].resize(bins.mSimpleBins.mBins.size());
    }

    if (myIdx == leaderIdx) {
        for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
            std::vector<std::vector<std::vector<uint64_t>>> temp(nParties - 1);
            for (u64 i = 0; i < temp.size(); i++) {
                temp[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
                for (u64 j = 0; j < temp[i].size(); j++)
                    temp[i][j].resize(bins.mSimpleBins.mBins.size());
            }

            int row = 0, col = 0;
            for (u64 i = 0; i < nParties - 1; i++) {
                for (u64 bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++) {
                    u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                        ? bins.mSimpleBins.mMaxBinSize[0]
                        : bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 j = 0; j < numMax; j++) {
                        if (col >= oleSize) { row++; col = 0; }
                        temp[i][j][bIdx] = recvOLE[pIdx][row][col];
                        col++;
                    }
                }
            }

            for (u64 i = 0; i < temp.size(); i++) {
                for (u64 j = 0; j < temp[i].size(); j++) {
                    for (u64 k = 0; k < temp[i][j].size(); k++) {
                        OLE_result[i][j][k] = crt_add(
                            OLE_result[i][j][k], temp[i][j][k]);
                    }
                }
            }
        }
    } else {
        // Unpack client OLE results
        for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
            int row = 0, col = 0;
            for (u64 bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++) {
                u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
                    ? bins.mSimpleBins.mMaxBinSize[0]
                    : bins.mSimpleBins.mMaxBinSize[1];
                for (u64 j = 0; j < numMax; j++) {
                    if (col >= oleSize) { row++; col = 0; }
                    OLE_result[pIdx][j][bIdx] = recvOLE[pIdx][row][col];
                    col++;
                }
            }
        }

        // Compute own contribution: (-r * x + δ) for each CRT component
        for (u64 bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++) {
            auto& bin = bins.mSimpleBins.mBins[bIdx];
            auto eNum = bin.mIdx.size();
            for (u64 i = 0; i < eNum; i++) {
                uint64_t inputVal = crt_encode(
                    NTL::conv<long>(set_zz[bin.mIdx[i]]));
                uint64_t random = randomValue[myIdx][i][bIdx];
                uint64_t partial = partUpValue[myIdx][i][bIdx];

                auto [in0, in1] = crt_unpack(inputVal);
                auto [rv0, rv1] = crt_unpack(random);
                auto [pv0, pv1] = crt_unpack(partial);

                uint32_t res0 = static_cast<uint32_t>(
                    ((uint64_t)(CRT_MODULI[0] - rv0 % CRT_MODULI[0]) * in0 + pv0) % CRT_MODULI[0]);
                uint32_t res1 = static_cast<uint32_t>(
                    ((uint64_t)(CRT_MODULI[1] - rv1 % CRT_MODULI[1]) * in1 + pv1) % CRT_MODULI[1]);

                OLE_result[myIdx][i][bIdx] = crt_pack(res0, res1);
            }
        }

        // Sum across all parties
        for (u64 i = 1; i < nParties - 1; i++) {
            for (u64 j = 0; j < bins.mSimpleBins.mMaxBinSize[1]; j++) {
                for (u64 k = 0; k < bins.mSimpleBins.mBins.size(); k++) {
                    OLE_result[0][j][k] = crt_add(
                        OLE_result[0][j][k], OLE_result[i][j][k]);
                }
            }
        }
    }

    auto phase2End = std::chrono::high_resolution_clock::now();

    // Keep OLE channels open — teardown at end (like original code)

    // ══════════════════════════════════════════════
    // Phase 3: Collect updated shares via OPPRF
    // ══════════════════════════════════════════════
    auto phase3Start = std::chrono::high_resolution_clock::now();
    // OPPRF channels are still open from Phase 1

    // Convert OLE_result to the block-based format for OPPRF
    // OLE_result[0] is the aggregated OLE result for each client
    // We need to convert it to std::vector<std::vector<u128>> for sendSSTableBased

    // For clients: we need OLE_result as vector<vector<u128>>
    std::vector<std::vector<ui128>> oleResultU128;
    if (myIdx != leaderIdx) {
        oleResultU128.resize(bins.mSimpleBins.mMaxBinSize[1]);
        for (u64 j = 0; j < oleResultU128.size(); j++) {
            oleResultU128[j].resize(bins.mSimpleBins.mBins.size());
            for (u64 k = 0; k < oleResultU128[j].size(); k++) {
                // Pack u64 CRT values into u128 in the format expected by
                // sendSSTableBased: low 32 bits per modulus, shifted by (3-idx)*32
                // With 2 moduli: mod0 at shift (3-0)*32=96, mod1 at shift (3-1)*32=64
                // Actually, the original code uses FourModulo layout:
                // res |= value << ((3-idx)*32) for idx=0..3
                // We need to match this since sendSSTableBased uses the same layout
                auto [r0, r1] = crt_unpack(OLE_result[0][j][k]);
                ui128 val = 0;
                val |= static_cast<ui128>(r0) << (3 * 32);  // idx=0 → shift=96
                val |= static_cast<ui128>(r1) << (2 * 32);  // idx=1 → shift=64
                oleResultU128[j][k] = val;
            }
        }
    }

    std::vector<std::vector<block>> endPayLoads(nParties - 1);
    std::vector<std::vector<std::vector<block>>> endPayLoads_divide(NUM_CRT_MODULI);

    for (u64 i = 0; i < endPayLoads.size(); i++)
        endPayLoads[i].resize(setSize);

    for (int i = 0; i < NUM_CRT_MODULI; i++) {
        endPayLoads_divide[i].resize(nParties - 1);
        for (u64 j = 0; j < endPayLoads_divide[i].size(); j++)
            endPayLoads_divide[i][j].resize(setSize);
    }

    // NUM_CRT_MODULI OPPRF rounds for collecting updated shares
    for (int modIdx = 0; modIdx < NUM_CRT_MODULI; modIdx++) {
        u64 thrBase = NUM_CRT_MODULI * nParties + modIdx * nParties;

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                recv[thr].init(opt, nParties, setSize, PSI_SEC_PARAM,
                    BIT_SIZE, channels.opprfChls[pIdx], otCountRecv,
                    otRecv[thr], otSend[thr],
                    ZeroBlock, false);
            }
        } else {
            u64 thr = thrBase;
            send[thr].init(opt, nParties, setSize, PSI_SEC_PARAM,
                BIT_SIZE, channels.opprfChls[leaderIdx], otCountSend,
                otSend[thr], otRecv[thr],
                prng.get<block>(), false);
        }

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                recv[thr].getOPRFkeys(pIdx, bins,
                    channels.opprfChls[pIdx], false);
            }
        } else {
            u64 thr = thrBase;
            send[thr].getOPRFkeys(leaderIdx, bins,
                channels.opprfChls[leaderIdx], false);
        }

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                recv[thr].recvSSTableBased(pIdx, bins,
                    endPayLoads_divide[modIdx][pIdx],
                    channels.opprfChls[pIdx], twoModulo, modIdx);
            }
        } else {
            u64 thr = thrBase;
            send[thr].sendSSTableBased(leaderIdx, bins,
                recvSSPayLoads[modIdx][0],
                oleResultU128,
                channels.opprfChls[leaderIdx], twoModulo, modIdx);
        }

        // Reset bins
        for (size_t i = 0; i < bins.mSimpleBins.mBins.size(); i++) {
            for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++) {
                bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
                bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
            }
        }
    }

    // 5th OPPRF round: OLE index
    std::vector<std::vector<block>> OleIndex(nParties - 1);
    for (u64 i = 0; i < OleIndex.size(); i++)
        OleIndex[i].resize(setSize);

    {
        u64 thrBase = (2 * NUM_CRT_MODULI) * nParties;

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                recv[thr].init(opt, nParties, setSize, PSI_SEC_PARAM,
                    BIT_SIZE, channels.opprfChls[pIdx], otCountRecv,
                    otRecv[thr], otSend[thr],
                    ZeroBlock, false);
            }
        } else {
            u64 thr = thrBase;
            send[thr].init(opt, nParties, setSize, PSI_SEC_PARAM,
                BIT_SIZE, channels.opprfChls[leaderIdx], otCountSend,
                otSend[thr], otRecv[thr],
                prng.get<block>(), false);
        }

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                recv[thr].getOPRFkeys(pIdx, bins,
                    channels.opprfChls[pIdx], false);
            }
        } else {
            u64 thr = thrBase;
            send[thr].getOPRFkeys(leaderIdx, bins,
                channels.opprfChls[leaderIdx], false);
        }

        if (myIdx == leaderIdx) {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                u64 thr = thrBase + pIdx;
                recv[thr].recvSSTableBased(pIdx, bins,
                    OleIndex[pIdx], channels.opprfChls[pIdx]);
            }
        } else {
            u64 thr = thrBase;
            send[thr].sendSSTableBased(leaderIdx, bins,
                channels.opprfChls[leaderIdx]);
        }
    }

    // Leader processes received updated shares
    if (myIdx == leaderIdx) {
        // Combine per-modulus payloads into u64 packed form
        for (u64 i = 0; i < endPayLoads.size(); i++) {
            for (u64 j = 0; j < endPayLoads[i].size(); j++) {
                uint32_t r0 = 0, r1 = 0;
                for (int m = 0; m < NUM_CRT_MODULI; m++) {
                    ui128 val = block_to_ui128(endPayLoads_divide[m][i][j]);
                    uint32_t part = static_cast<uint32_t>(val & 0xFFFFFFFF);
                    if (m == 0) r0 = part;
                    else r1 = part;
                }
                endPayLoads[i][j] = ui128_to_block(
                    static_cast<ui128>(crt_pack(r0, r1)));
            }
        }
    }

    auto phase3End = std::chrono::high_resolution_clock::now();

    // ══════════════════════════════════════════════
    // Phase 4: Reconstruction (leader only)
    // ══════════════════════════════════════════════
    auto phase4Start = std::chrono::high_resolution_clock::now();

    std::unordered_set<u64> result;

    if (myIdx == leaderIdx) {
        // Collect all updated shares: n * setSize
        std::vector<std::vector<uint64_t>> endShares(totalNumShares);
        for (u64 i = 0; i < endShares.size(); i++)
            endShares[i].resize(setSize);

        // Process clients' shares
        for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++) {
            auto& bin = bins.mCuckooBins.mBins[bIdx];
            if (!bin.isEmpty()) {
                u64 inputIdx = bin.idx();
                for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++) {
                    uint64_t recv_packed = static_cast<uint64_t>(
                        block_to_ui128(endPayLoads[pIdx][inputIdx]));

                    ui128 index = block_to_ui128(OleIndex[pIdx][inputIdx]);
                    index = index & 0x3F;

                    uint64_t oleVal = OLE_result[pIdx][index][bIdx];
                    endShares[pIdx][inputIdx] = crt_add(oleVal, recv_packed);
                }
            }
        }

        // Leader's own shares
        for (u64 i = 0; i < setSize; i++) {
            uint32_t r0 = static_cast<uint32_t>(
                NTL::conv<long>(ServerShares[0][i]));
            uint32_t r1 = static_cast<uint32_t>(
                NTL::conv<long>(ServerShares[1][i]));
            endShares[nParties - 1][i] = crt_pack(r0, r1);
        }

        // Reconstruct: try all combinations
        std::vector<std::vector<std::pair<int, uint64_t>>> endShares_T(setSize);
        for (u64 i = 0; i < setSize; i++) {
            endShares_T[i].resize(totalNumShares);
            for (u64 j = 0; j < totalNumShares; j++) {
                endShares_T[i][j] = {static_cast<int>(j + 1), endShares[j][i]};
            }
        }

        std::vector<std::vector<int>> all_combinations;
        get_combinations_iterative(totalNumShares - 1, threshold - 1,
            all_combinations);

        // Always include leader's share
        for (auto& combo : all_combinations)
            combo.push_back(static_cast<int>(leaderIdx));

        for (u64 eIdx = 0; eIdx < setSize; eIdx++) {
            for (const auto& combo : all_combinations) {
                int res = reconstruct_secret(
                    combo, endShares_T[eIdx], set_zz[eIdx]);
                if (res == 1) {
                    result.insert(eIdx);
                    break;
                }
            }
        }
    }

    auto phase4End = std::chrono::high_resolution_clock::now();

    // Print timing
    if (myIdx == 0 || myIdx == leaderIdx) {
        auto p1 = std::chrono::duration_cast<std::chrono::milliseconds>(phase1End - phase1Start).count();
        auto p2 = std::chrono::duration_cast<std::chrono::milliseconds>(phase2End - phase2Start).count();
        auto p3 = std::chrono::duration_cast<std::chrono::milliseconds>(phase3End - phase3Start).count();
        auto p4 = std::chrono::duration_cast<std::chrono::milliseconds>(phase4End - phase4Start).count();

        std::cout << "Party [" << myIdx << "] timing (ms):"
                  << " P1=" << p1 << " P2=" << p2
                  << " P3=" << p3 << " P4=" << p4
                  << " Total=" << (p1 + p2 + p3 + p4) << std::endl;
    }

    if (myIdx == leaderIdx) {
        std::cout << "Intersection size: " << result.size() << std::endl;
    }

    // Teardown all channels at the end
    channels.teardownOLE();
    channels.teardownOPPRF();

    return result;
}

} // namespace yyh26
