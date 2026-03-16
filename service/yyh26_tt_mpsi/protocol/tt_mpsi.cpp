#include "tt_mpsi.h"
#include "shamir_ss.h"
#include "crt_utils.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <unordered_set>

// cryptoTools networking
#include "Network/BtEndpoint.h"
#include "Network/BtIOService.h"
#include "Common/Defines.h"
#include "Crypto/PRNG.h"

// libOTe
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

// libOPRF
#include "OPPRF/OPPRFSender.h"
#include "OPPRF/OPPRFReceiver.h"

// libOLE (BFV-based BOLE)
#include "pke/ole.h"
#include "pke/gazelle-network.h"

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>

namespace mpsi::yyh26 {

// Qualify osuCrypto types explicitly to avoid ambiguity with libOLE's
// copy of cryptoTools (osuCryptoNew::block vs osuCrypto::block).
using osuCrypto::BtIOService;
using osuCrypto::BtEndpoint;
using osuCrypto::Channel;
using osuCrypto::PRNG;
using osuCrypto::block;
using osuCrypto::ZeroBlock;
using osuCrypto::KkrtNcoOtReceiver;
using osuCrypto::KkrtNcoOtSender;
using osuCrypto::OPPRFSender;
using osuCrypto::OPPRFReceiver;
using osuCrypto::binSet;

// lbcrypto types for BOLE (BFV homomorphic encryption)
using namespace lbcrypto;

// ============================================================================
// Type conversions
// ============================================================================

// Sync helpers (replaces frontend/util.h)
static void senderSync(Channel& chl) {
    uint8_t b = 0;
    chl.send(&b, 1);
    chl.recv(&b, 1);
}

static void recverSync(Channel& chl) {
    uint8_t b = 0;
    chl.recv(&b, 1);
    chl.send(&b, 1);
}

static ui128 zzToUi128(const NTL::ZZ& zz) {
    uint8_t bytes[16] = {0};
    NTL::BytesFromZZ(bytes, zz, 16);
    ui128 result = 0;
    for (int i = 0; i < 16; i++)
        result |= static_cast<ui128>(bytes[i]) << (8 * i);
    return result;
}

static block stringToBlock(const std::string& s) {
    block b = ZeroBlock;
    size_t len = std::min(s.size(), sizeof(block));
    std::memcpy(&b, s.data(), len);
    return b;
}

static ui128 blockToU128(block b) {
    ui128 result;
    std::memcpy(&result, &b, sizeof(result));
    return result;
}

static block u128ToBlock(ui128 v) {
    block b;
    std::memcpy(&b, &v, sizeof(b));
    return b;
}

// ============================================================================
// BFV scheme types (matching experiments code)
// ============================================================================

constexpr double STD_DEV = 3.2;
constexpr uint32_t LOG_N = 13;
constexpr uint32_t OLE_SIZE = 1 << LOG_N; // 8192
constexpr uint64_t UP = 4294475777ULL;     // largest CRT modulus

using PlaintextRing = DCRT_Poly_Ring<params<uint64_t>, LOG_N>;
using enc_ctx_t = EncodingContext<PlaintextRing, UP>;
using IntCryptoRing = DCRT_Ring<fast_four_limb_reduction_params>;
using dcrt_params_t = DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, UP>;
using SchemeType = BFV_DCRT<enc_ctx_t, dcrt_params_t>;
using encoding_input_t = typename enc_ctx_t::encoding_input_t;

// Split 128-bit CRT-packed values into 4 × 32-bit BOLEReceiverInput objects.
template <typename encoding_input_t>
struct FourBOLEReceiverInputs {
    std::vector<BOLEReceiverInput<encoding_input_t>> receiverInputs;
    FourBOLEReceiverInputs(ui32 numBlocks) {
        for (int i = 0; i < 4; i++)
            receiverInputs.emplace_back(numBlocks);
    }
    void processModule(const std::vector<std::vector<ui128>>& ReInput) {
        for (ui32 blockIdx = 0; blockIdx < ReInput.size(); blockIdx++) {
            for (ui32 slotIdx = 0; slotIdx < ReInput[blockIdx].size(); slotIdx++) {
                ui128 val = ReInput[blockIdx][slotIdx];
                for (int k = 0; k < 4; k++) {
                    ui64 shift = (3 - k) * 32;
                    receiverInputs[k].x[blockIdx].vals[slotIdx] =
                        (val >> shift) & 0xFFFFFFFF;
                }
            }
        }
    }
};

// ============================================================================
// BOLE helpers (one per CRT modulus)
// ============================================================================

template <uint64_t p>
static BOLEReceiverOutput<encoding_input_t> runBoleReceiver(
    const BOLEReceiverInput<encoding_input_t>& input,
    const typename SchemeType::SecretKey& sk,
    osuCryptoNew::Channel& chl)
{
    using PR = DCRT_Poly_Ring<params<uint64_t>, LOG_N>;
    using EC = EncodingContext<PR, p>;
    using ICR = DCRT_Ring<fast_four_limb_reduction_params>;
    using DP = DCRT_Fast_Four_Limb_Reduction_Params<ICR, p>;
    using ST = BFV_DCRT<EC, DP>;

    ST scheme(STD_DEV);
    return BOLEReceiver::online(input, sk, scheme, chl);
}

template <uint64_t p>
static void runBoleSender(
    BOLESenderInput<encoding_input_t>& input,
    const typename SchemeType::PublicKey& pk,
    osuCryptoNew::Channel& chl)
{
    using PR = DCRT_Poly_Ring<params<uint64_t>, LOG_N>;
    using EC = EncodingContext<PR, p>;
    using ICR = DCRT_Ring<fast_four_limb_reduction_params>;
    using DP = DCRT_Fast_Four_Limb_Reduction_Params<ICR, p>;
    using ST = BFV_DCRT<EC, DP>;

    ST scheme(STD_DEV);
    BOLESender::online(input, pk, scheme, chl);
}

// Run all 4 CRT-modulus BOLEs as receiver and return packed 128-bit results.
static std::vector<std::vector<ui128>> runFourBoleReceiver(
    std::vector<std::vector<ui128>>& receiverInput,
    u64 boleNum,
    osuCryptoNew::Channel& chl)
{
    const SchemeType scheme(STD_DEV);
    auto kpSeeded = scheme.KeyGenSeeded();
    sendPublicKey(kpSeeded.pkSeeded, chl);
    auto& sk = kpSeeded.sk;

    FourBOLEReceiverInputs<encoding_input_t> fourInputs(boleNum);
    fourInputs.processModule(receiverInput);

    std::vector<BOLEReceiverOutput<encoding_input_t>> fourOutputs(4,
        BOLEReceiverOutput<encoding_input_t>(fourInputs.receiverInputs[0].numBlocks));

    fourOutputs[0] = runBoleReceiver<4293230593ULL>(fourInputs.receiverInputs[0], sk, chl);
    fourOutputs[1] = runBoleReceiver<4293836801ULL>(fourInputs.receiverInputs[1], sk, chl);
    fourOutputs[2] = runBoleReceiver<4293918721ULL>(fourInputs.receiverInputs[2], sk, chl);
    fourOutputs[3] = runBoleReceiver<4294475777ULL>(fourInputs.receiverInputs[3], sk, chl);

    // Pack 4 modular results into 128-bit values
    std::vector<std::vector<ui128>> result(boleNum, std::vector<ui128>(OLE_SIZE));
    for (u64 bIdx = 0; bIdx < boleNum; bIdx++) {
        for (u64 i = 0; i < OLE_SIZE; i++) {
            ui128 res = 0;
            for (u64 j = 0; j < 4; j++)
                res |= static_cast<ui128>(fourOutputs[j].cBlocks[bIdx][i]) << ((3 - j) * 32);
            result[bIdx][i] = res;
        }
    }
    return result;
}

// Run all 4 CRT-modulus BOLEs as sender.
static void runFourBoleSender(
    std::vector<std::vector<ui128>>& aValues,
    std::vector<std::vector<ui128>>& bValues,
    u64 boleNum,
    osuCryptoNew::Channel& chl)
{
    const SchemeType scheme(STD_DEV);
    using SeededPublicKey = typename SchemeType::PublicKeySeeded;
    SeededPublicKey seededPK;
    receivePublicKey(seededPK, chl);
    auto pk = seededPK.expand();

    std::vector<std::vector<encoding_input_t>> aVecs(4);
    std::vector<std::vector<encoding_input_t>> bVecs(4);

    for (uint32_t m = 0; m < 4; m++) {
        aVecs[m].resize(boleNum);
        bVecs[m].resize(boleNum);
        for (uint32_t bIdx = 0; bIdx < boleNum; bIdx++) {
            for (uint32_t j = 0; j < OLE_SIZE; j++) {
                uint64_t shift = (3 - m) * 32;
                aVecs[m][bIdx].vals[j] = ((aValues[bIdx][j] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                bVecs[m][bIdx].vals[j] = ((bValues[bIdx][j] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
            }
        }
    }

    std::vector<BOLESenderInput<encoding_input_t>> fourInputs;
    for (uint32_t m = 0; m < 4; m++)
        fourInputs.emplace_back(BOLESenderInput<encoding_input_t>(aVecs[m], bVecs[m]));

    runBoleSender<4293230593ULL>(fourInputs[0], pk, chl);
    runBoleSender<4293836801ULL>(fourInputs[1], pk, chl);
    runBoleSender<4293918721ULL>(fourInputs[2], pk, chl);
    runBoleSender<4294475777ULL>(fourInputs[3], pk, chl);
}

// ============================================================================
// OPPRF round helper: runs init + getOPRFkeys + sendSS/recvSS for one modulus
// ============================================================================

static void resetBins(binSet& bins) {
    for (size_t i = 0; i < bins.mSimpleBins.mBins.size(); i++) {
        for (size_t j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++) {
            bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
            bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
        }
    }
}

// ============================================================================
// Setup: TCP connections + hashing
// ============================================================================

struct ProtocolContext {
    u64 myIdx;
    u64 nParties;
    u64 threshold;
    u64 setSize;
    u64 leaderIdx;

    BtIOService* ios = nullptr;
    std::vector<std::unique_ptr<BtEndpoint>> ep;
    std::vector<std::vector<osuCrypto::Channel*>> chls;

    // Separate OLE connections (osuCryptoNew namespace, ports oleBasePort+)
    osuCryptoNew::IOService* iosOLE = nullptr;
    std::vector<osuCryptoNew::Session> epOLE;
    std::vector<osuCryptoNew::Channel> chlsOLE;

    binSet bins;
    std::unique_ptr<PRNG> prng;

    // Input data in both formats
    std::vector<block> setBlocks;
    std::vector<NTL::ZZ> setZZ;
    NTL::ZZ p; // master modulus for ZZ_p context

    std::vector<NTL::ZZ> fourModuloZZ;

    // Number of real (non-padding) elements
    u64 realSize;

    void setup(const TTMpsiConfig& config, const std::vector<std::string>& inputs) {
        myIdx = config.partyID;
        nParties = config.numParties;
        threshold = config.threshold;
        realSize = inputs.size();
        leaderIdx = nParties - 1;

        // Protocol requires setSize >= 32 for hashing bins to work correctly.
        // Pad with unique dummy elements that won't collide across parties.
        constexpr u64 MIN_SET_SIZE = 32;
        setSize = realSize;
        if (setSize < MIN_SET_SIZE)
            setSize = MIN_SET_SIZE;

        prng = std::make_unique<PRNG>(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));

        p = NTL::conv<NTL::ZZ>("339933312435546022214350946152556052481");
        NTL::ZZ_p::init(p);

        for (auto mod : CRT_MODULI)
            fourModuloZZ.push_back(NTL::ZZ(mod));

        // Convert inputs to block and ZZ
        setBlocks.resize(setSize);
        setZZ.resize(setSize);
        for (u64 i = 0; i < realSize; i++) {
            setBlocks[i] = stringToBlock(inputs[i]);
            ui128 blockVal = blockToU128(setBlocks[i]);
            uint8_t zzBytes[16];
            std::memcpy(zzBytes, &blockVal, 16);
            setZZ[i] = NTL::ZZFromBytes(zzBytes, 16);
        }
        // Pad with party-unique dummy elements (won't intersect with other parties)
        for (u64 i = realSize; i < setSize; i++) {
            // Use party-specific seed to ensure uniqueness across parties
            setBlocks[i] = _mm_set_epi64x(
                static_cast<int64_t>(0xDEADBEEF00000000ULL | (myIdx << 16) | i),
                static_cast<int64_t>(0xCAFEBABE00000000ULL | (myIdx << 16) | i));
            uint64_t dummyVal = 0xDEAD000000ULL + myIdx * 100000 + i;
            setZZ[i] = NTL::conv<NTL::ZZ>(static_cast<long>(dummyVal));
        }

        // OPPRF TCP connections (ports tcpBasePort+)
        std::string name("psi");
        ios = new BtIOService(1);
        ep.resize(nParties);
        for (u64 i = 0; i < nParties; i++) {
            ep[i] = std::make_unique<BtEndpoint>();
            if (i < myIdx) {
                uint32_t port = config.tcpBasePort + i * 100 + myIdx;
                ep[i]->start(*ios, config.getHostname(i), port, false, name);
            } else if (i > myIdx) {
                uint32_t port = config.tcpBasePort + myIdx * 100 + i;
                ep[i]->start(*ios, config.getHostname(i), port, true, name);
            }
        }

        chls.resize(nParties);
        for (u64 i = 0; i < nParties; i++) {
            if (i != myIdx) {
                chls[i].resize(NUM_THREADS);
                for (u64 j = 0; j < NUM_THREADS; j++)
                    chls[i][j] = &ep[i]->addChannel(name, name);
            }
        }

        // OLE TCP connections (ports tcpBasePort + 5900 +)
        uint32_t oleBasePort = config.tcpBasePort + 5900;
        iosOLE = new osuCryptoNew::IOService(0);
        epOLE.resize(nParties);
        for (u64 i = 0; i < nParties; i++) {
            if (i < myIdx) {
                uint32_t port = oleBasePort + i * 100 + myIdx;
                epOLE[i].start(*iosOLE, config.getHostname(i), port,
                               osuCryptoNew::SessionMode::Client, name);
            } else if (i > myIdx) {
                uint32_t port = oleBasePort + myIdx * 100 + i;
                epOLE[i].start(*iosOLE, config.getHostname(i), port,
                               osuCryptoNew::SessionMode::Server, name);
            }
        }
        chlsOLE.resize(nParties);
        for (u64 i = 0; i < nParties; i++) {
            if (i != myIdx)
                chlsOLE[i] = epOLE[i].addChannel(name, name);
        }

        // Hashing
        bins.init(myIdx, nParties, setSize, PSI_SEC_PARAM, 0);
        bins.hashing2Bins(setBlocks, 1);
    }

    void cleanup() {
        // Close OLE channels and sessions first
        for (u64 i = 0; i < nParties; i++) {
            if (i != myIdx) {
                chlsOLE[i].close();
                epOLE[i].stop();
            }
        }
        if (iosOLE) {
            iosOLE->stop();
            delete iosOLE;
            iosOLE = nullptr;
        }

        // Then close OPPRF channels and endpoints
        for (u64 i = 0; i < nParties; i++) {
            if (i != myIdx) {
                for (auto* ch : chls[i])
                    if (ch) ch->close();
                ep[i]->stop();
            }
        }
        if (ios) {
            ios->stop();
            delete ios;
            ios = nullptr;
        }
    }

    ~ProtocolContext() {
        cleanup();
    }
};

// Synchronization helper (leader sends, members receive)
static void syncParties(ProtocolContext& ctx) {
    if (ctx.myIdx == ctx.leaderIdx) {
        for (u64 i = 0; i < ctx.nParties - 1; i++)
            senderSync(*ctx.chls[i][0]);
    } else {
        recverSync(*ctx.chls[ctx.leaderIdx][0]);
    }
}

// ============================================================================
// Phase 1: Secret sharing via OPPRF (leader → members)
// ============================================================================

struct Phase1Result {
    // Leader: shares_zz[4][nParties][setSize] — all shares
    std::vector<std::vector<std::vector<NTL::ZZ_p>>> sharesZZ;
    // Leader: ServerShares[4][setSize] — leader's own shares
    std::vector<std::vector<NTL::ZZ>> serverShares;
    // Member: recvSSPayLoads[4][1][setSize] — received shares
    std::vector<std::vector<std::vector<block>>> recvSSPayLoads;
};

static Phase1Result runPhase1(ProtocolContext& ctx) {
    Phase1Result result;
    u64 totalNumShares = ctx.nParties;

    // Prepare payloads
    std::vector<std::vector<std::vector<block>>> sendSSPayLoads(4);
    result.recvSSPayLoads.resize(4);

    for (u64 i = 0; i < 4; i++) {
        result.recvSSPayLoads[i].resize(totalNumShares);
        sendSSPayLoads[i].resize(totalNumShares);
        for (u64 j = 0; j < totalNumShares; j++) {
            result.recvSSPayLoads[i][j].resize(ctx.setSize);
            sendSSPayLoads[i][j].resize(ctx.setSize);
        }
    }

    result.serverShares.resize(4);
    for (u64 i = 0; i < 4; i++)
        result.serverShares[i].resize(ctx.setSize);

    if (ctx.myIdx == ctx.leaderIdx) {
        // Leader: Shamir share each element over 4 CRT moduli
        result.sharesZZ.resize(4);
        for (u64 m = 0; m < 4; m++) {
            NTL::ZZ currentMod = ctx.fourModuloZZ[m];
            result.sharesZZ[m].resize(totalNumShares, std::vector<NTL::ZZ_p>(ctx.setSize));

            for (u64 j = 0; j < ctx.setSize; j++) {
                NTL::ZZ_p secret = NTL::conv<NTL::ZZ_p>(ctx.setZZ[j]);
                auto shares = shamirShare(secret, totalNumShares, ctx.threshold, currentMod);
                NTL::ZZ_p::init(ctx.p);

                for (u64 k = 0; k < totalNumShares; k++)
                    result.sharesZZ[m][k][j] = shares[k];

                result.serverShares[m][j] = NTL::conv<NTL::ZZ>(result.sharesZZ[m][totalNumShares - 1][j]);
            }
        }

        // Convert shares to block payloads for OPPRF
        for (u64 m = 0; m < 4; m++) {
            for (u64 j = 0; j < totalNumShares; j++) {
                for (u64 k = 0; k < ctx.setSize; k++) {
                    NTL::BytesFromZZ(reinterpret_cast<uint8_t*>(&sendSSPayLoads[m][j][k]),
                                     NTL::conv<NTL::ZZ>(result.sharesZZ[m][j][k]),
                                     sizeof(block));
                }
            }
        }
    }

    // OPPRF for each of 4 CRT moduli
    u64 otCountSend = ctx.bins.mSimpleBins.mBins.size();
    u64 otCountRecv = ctx.bins.mCuckooBins.mBins.size();

    std::vector<u64> fourModuloU64(CRT_MODULI.begin(), CRT_MODULI.end());

    for (u64 m = 0; m < 4; m++) {
        u64 opprfBase = m * ctx.nParties;

        if (ctx.myIdx == ctx.leaderIdx) {
            for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
                OPPRFSender sender;
                KkrtNcoOtSender otS;
                KkrtNcoOtReceiver otR;
                sender.init(0, ctx.nParties, ctx.setSize, PSI_SEC_PARAM, BIT_SIZE,
                           ctx.chls[pIdx], otCountSend, otS, otR,
                           ctx.prng->get<block>(), false);
                sender.getOPRFkeys(pIdx, ctx.bins, ctx.chls[pIdx], false);
                sender.sendSSTableBased(pIdx, ctx.bins, sendSSPayLoads[m][pIdx],
                                       ctx.chls[pIdx], fourModuloU64, m);
            }
        } else {
            OPPRFReceiver receiver;
            KkrtNcoOtReceiver otR;
            KkrtNcoOtSender otS;
            receiver.init(0, ctx.nParties, ctx.setSize, PSI_SEC_PARAM, BIT_SIZE,
                         ctx.chls[ctx.leaderIdx], otCountRecv, otR, otS,
                         ZeroBlock, false);
            receiver.getOPRFkeys(ctx.leaderIdx, ctx.bins, ctx.chls[ctx.leaderIdx], false);
            receiver.recvSSTableBased(ctx.leaderIdx, ctx.bins, result.recvSSPayLoads[m][0],
                                     ctx.chls[ctx.leaderIdx], fourModuloU64, m);
        }

        resetBins(ctx.bins);
    }

    return result;
}

// ============================================================================
// Phase 2: Update values via BOLE
// ============================================================================

struct Phase2Result {
    // OLE results for reconstruction: [nParties-1][maxBinSize][numBins]
    std::vector<std::vector<std::vector<ui128>>> oleResult;
};

static Phase2Result runPhase2(ProtocolContext& ctx, Phase1Result& phase1) {
    Phase2Result result;
    u64 totalNumShares = ctx.nParties;
    u64 updateValueSize = ctx.bins.mSimpleBins.mBins.size();

    // Members generate update values (zero-sharing polynomials)
    std::vector<std::vector<std::vector<NTL::ZZ_p>>> genUpdateValues(4);
    std::vector<std::vector<std::vector<block>>> sendUpdateValues(4);
    std::vector<std::vector<std::vector<NTL::ZZ>>> serverUpdateValues(4);

    for (u64 i = 0; i < 4; i++) {
        sendUpdateValues[i].resize(totalNumShares);
        for (u64 j = 0; j < totalNumShares; j++)
            sendUpdateValues[i][j].resize(updateValueSize);
    }

    for (u64 i = 0; i < 4; i++) {
        serverUpdateValues[i].resize(ctx.nParties);
        for (u64 j = 0; j < ctx.nParties; j++)
            serverUpdateValues[i][j].resize(updateValueSize);
    }

    if (ctx.myIdx != ctx.leaderIdx) {
        for (u64 m = 0; m < 4; m++) {
            NTL::ZZ currentMod = ctx.fourModuloZZ[m];
            genUpdateValues[m].resize(updateValueSize);

            for (u64 j = 0; j < updateValueSize; j++) {
                genUpdateValues[m][j] = generateUpdateValues(totalNumShares, ctx.threshold, currentMod);
                NTL::ZZ_p::init(ctx.p);
            }

            for (u64 j = 0; j < totalNumShares; j++) {
                for (u64 k = 0; k < updateValueSize; k++) {
                    NTL::BytesFromZZ(reinterpret_cast<uint8_t*>(&sendUpdateValues[m][j][k]),
                                     NTL::rep(genUpdateValues[m][k][j]), sizeof(block));
                }
            }
        }

        // Send leader's update values
        for (u64 m = 0; m < 4; m++) {
            for (u64 j = 0; j < updateValueSize; j++) {
                unsigned char buf[4];
                NTL::ZZ value = NTL::conv<NTL::ZZ>(genUpdateValues[m][j][totalNumShares - 1]);
                NTL::BytesFromZZ(buf, value, 4);
                ctx.chls[ctx.leaderIdx][0]->send(buf, 4);
            }
        }
    } else {
        // Leader receives update values from all members
        for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
            for (u64 m = 0; m < 4; m++) {
                for (u64 j = 0; j < updateValueSize; j++) {
                    unsigned char buf[4];
                    ctx.chls[pIdx][0]->recv(buf, 4);
                    NTL::ZZFromBytes(serverUpdateValues[m][pIdx][j], buf, 4);
                }
            }
        }

        // Leader updates its own shares
        for (u64 m = 0; m < 4; m++) {
            NTL::ZZ mod = ctx.fourModuloZZ[m];
            for (u64 j = 0; j < ctx.nParties - 1; j++) {
                for (u64 k = 0; k < updateValueSize; k++) {
                    serverUpdateValues[m][ctx.nParties - 1][k] += serverUpdateValues[m][j][k];
                    serverUpdateValues[m][ctx.nParties - 1][k] %= mod;
                }
            }

            for (u64 bIdx = 0; bIdx < ctx.bins.mCuckooBins.mBins.size(); bIdx++) {
                auto& bin = ctx.bins.mCuckooBins.mBins[bIdx];
                if (!bin.isEmpty()) {
                    u64 inputIdx = bin.idx();
                    NTL::ZZ num1 = phase1.serverShares[m][inputIdx];
                    NTL::ZZ num2 = serverUpdateValues[m][ctx.nParties - 1][bIdx];
                    phase1.serverShares[m][inputIdx] = NTL::AddMod(num1, num2, mod);
                }
            }
        }
    }

    // ---- BOLE Phase: Leader ↔ Members ----
    u64 leaderOleNum = (ctx.nParties - 1) * (
        ctx.bins.mCuckooBins.mBinCount[0] * ctx.bins.mCuckooBins.mParams.mSenderBinSize[0] +
        ctx.bins.mCuckooBins.mBinCount[1] * ctx.bins.mCuckooBins.mParams.mSenderBinSize[1]);
    u64 leaderBoleNum = (leaderOleNum + OLE_SIZE - 1) / OLE_SIZE;

    std::vector<std::vector<ui128>> recvOLE;
    std::vector<std::vector<std::vector<ui128>>> randomValue;
    std::vector<std::vector<std::vector<ui128>>> partUpValue;

    if (ctx.myIdx == ctx.leaderIdx) {
        // Leader prepares BOLE receiver input
        std::vector<std::vector<ui128>> leaderInput(leaderBoleNum, std::vector<ui128>(OLE_SIZE));
        NTL::ZZ element;

        {
            int row = 0, col = 0;
            for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
                NTL::SetSeed(NTL::ZZ(ctx.myIdx));
                for (u64 bIdx = 0; bIdx < ctx.bins.mCuckooBins.mBins.size(); bIdx++) {
                    auto& bin = ctx.bins.mCuckooBins.mBins[bIdx];
                    ui128 inputIdx;
                    if (!bin.isEmpty()) {
                        inputIdx = blockToU128(ctx.setBlocks[bin.idx()]);
                    } else {
                        NTL::RandomBnd(element, ctx.p);
                        inputIdx = zzToUi128(element);
                    }

                    u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                        ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                        : ctx.bins.mSimpleBins.mMaxBinSize[1];

                    for (u64 e = 0; e < numMax; e++) {
                        if (col >= static_cast<int>(OLE_SIZE)) { row++; col = 0; }
                        leaderInput[row][col] = inputIdx;
                        col++;
                    }
                }
            }
        }

        // Reduce input mod each CRT modulus and pack into CRT slots
        std::vector<std::vector<ui128>> reInput(leaderBoleNum, std::vector<ui128>(OLE_SIZE));
        for (u64 i = 0; i < leaderBoleNum; i++) {
            for (u64 j = 0; j < OLE_SIZE; j++) {
                reInput[i][j] = crtReduceAndPack(leaderInput[i][j]);
            }
        }

        // Run leader-client BOLEs
        std::vector<std::vector<std::vector<ui128>>> allRecvOLE(ctx.nParties - 1);
        for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
            allRecvOLE[pIdx] = runFourBoleReceiver(reInput, leaderBoleNum, ctx.chlsOLE[pIdx]);
        }
        // Store for later processing
        recvOLE.resize(leaderBoleNum);
        for (u64 i = 0; i < leaderBoleNum; i++)
            recvOLE[i].resize(OLE_SIZE);
        // Will be processed per-party below

        // Process OLE results for leader
        result.oleResult.resize(ctx.nParties - 1);
        for (u64 i = 0; i < ctx.nParties - 1; i++) {
            result.oleResult[i].resize(ctx.bins.mSimpleBins.mMaxBinSize[1]);
            for (u64 j = 0; j < result.oleResult[i].size(); j++)
                result.oleResult[i][j].resize(ctx.bins.mSimpleBins.mBins.size(), 0);
        }

        for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
            std::vector<std::vector<std::vector<ui128>>> temp(ctx.nParties - 1);
            for (u64 i = 0; i < temp.size(); i++) {
                temp[i].resize(ctx.bins.mSimpleBins.mMaxBinSize[1]);
                for (u64 j = 0; j < temp[i].size(); j++)
                    temp[i][j].resize(ctx.bins.mSimpleBins.mBins.size());
            }

            int row = 0, col = 0;
            for (u64 i = 0; i < ctx.nParties - 1; i++) {
                for (u64 bIdx = 0; bIdx < ctx.bins.mSimpleBins.mBins.size(); bIdx++) {
                    u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                        ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                        : ctx.bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 j = 0; j < numMax; j++) {
                        if (col >= static_cast<int>(OLE_SIZE)) { row++; col = 0; }
                        temp[i][j][bIdx] = allRecvOLE[pIdx][row][col];
                        col++;
                    }
                }
            }

            for (u64 i = 0; i < temp.size(); i++) {
                for (u64 j = 0; j < temp[i].size(); j++) {
                    for (u64 k = 0; k < temp[i][j].size(); k++) {
                        result.oleResult[i][j][k] = crtAdd(result.oleResult[i][j][k], temp[i][j][k]);
                    }
                }
            }
        }
    } else {
        // Member: prepare random values and run BOLE as sender
        randomValue.resize(ctx.nParties - 1);
        partUpValue.resize(ctx.nParties - 1);
        NTL::ZZ element;

        for (u64 i = 0; i < ctx.nParties - 1; i++) {
            randomValue[i].resize(ctx.bins.mSimpleBins.mMaxBinSize[1]);
            partUpValue[i].resize(ctx.bins.mSimpleBins.mMaxBinSize[1]);
            for (u64 j = 0; j < ctx.bins.mSimpleBins.mMaxBinSize[1]; j++) {
                randomValue[i][j].resize(updateValueSize);
                partUpValue[i][j].resize(updateValueSize);
                for (u64 k = 0; k < updateValueSize; k++) {
                    NTL::RandomBnd(element, ctx.p);
                    randomValue[i][j][k] = zzToUi128(element);
                    NTL::RandomBnd(element, ctx.p);
                    partUpValue[i][j][k] = zzToUi128(element);
                }
            }
        }

        // Prepare a/b vectors for leader BOLE
        std::vector<std::vector<ui128>> randomForLeader(leaderBoleNum, std::vector<ui128>(OLE_SIZE));
        std::vector<std::vector<ui128>> partUpForLeader(leaderBoleNum, std::vector<ui128>(OLE_SIZE));
        std::vector<std::vector<ui128>> updateForLeader(leaderBoleNum, std::vector<ui128>(OLE_SIZE));

        {
            int row = 0, col = 0;
            for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
                for (u64 bIdx = 0; bIdx < updateValueSize; bIdx++) {
                    u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                        ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                        : ctx.bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 eIdx = 0; eIdx < numMax; eIdx++) {
                        if (col >= static_cast<int>(OLE_SIZE)) { row++; col = 0; }
                        randomForLeader[row][col] = randomValue[pIdx][eIdx][bIdx];
                        partUpForLeader[row][col] = partUpValue[pIdx][eIdx][bIdx];
                        col++;
                    }
                }
            }
        }

        // Build update values from sendUpdateValues
        {
            int row = 0, col = 0;
            for (u64 uIdx = 0; uIdx < ctx.nParties - 1; uIdx++) {
                for (u64 bIdx = 0; bIdx < ctx.bins.mCuckooBins.mBins.size(); bIdx++) {
                    ui128 res = 0;
                    for (u64 m = 0; m < 4; m++) {
                        NTL::ZZ part_zz = NTL::ZZFromBytes(
                            reinterpret_cast<uint8_t*>(&sendUpdateValues[m][uIdx][bIdx]), sizeof(block));
                        ui128 part = zzToUi128(part_zz);
                        res |= static_cast<ui128>(part) << ((3 - m) * 32);
                    }

                    u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                        ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                        : ctx.bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 e = 0; e < numMax; e++) {
                        if (col >= static_cast<int>(OLE_SIZE)) { row++; col = 0; }
                        updateForLeader[row][col] = res;
                        col++;
                    }
                }
            }
        }

        // Build sender (a, b) values per CRT modulus
        std::vector<u64> fourModuloU64(CRT_MODULI.begin(), CRT_MODULI.end());
        std::vector<std::vector<ui128>> aValues(leaderBoleNum, std::vector<ui128>(OLE_SIZE));
        std::vector<std::vector<ui128>> bValues(leaderBoleNum, std::vector<ui128>(OLE_SIZE));

        for (u64 bIdx = 0; bIdx < leaderBoleNum; bIdx++) {
            for (u64 j = 0; j < OLE_SIZE; j++) {
                ui128 aVal = 0, bVal = 0;
                for (uint32_t m = 0; m < 4; m++) {
                    uint64_t shift = (3 - m) * 32;
                    uint64_t a_m = ((randomForLeader[bIdx][j] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                    uint64_t randA = ((partUpForLeader[bIdx][j] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                    uint64_t randB = ((updateForLeader[bIdx][j] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                    aVal |= static_cast<ui128>(a_m) << shift;
                    bVal |= static_cast<ui128>((randB + CRT_MODULI[m] - randA) % CRT_MODULI[m]) << shift;
                }
                aValues[bIdx][j] = aVal;
                bValues[bIdx][j] = bVal;
            }
        }

        runFourBoleSender(aValues, bValues, leaderBoleNum, ctx.chlsOLE[ctx.leaderIdx]);

        // ---- Client ↔ Client BOLEs ----
        u64 clientOleNum = ctx.bins.mSimpleBins.mBinCount[0] * ctx.bins.mSimpleBins.mMaxBinSize[0]
                         + ctx.bins.mSimpleBins.mBinCount[1] * ctx.bins.mSimpleBins.mMaxBinSize[1];
        u64 clientBoleNum = (clientOleNum + OLE_SIZE - 1) / OLE_SIZE;

        // Prepare client input
        std::vector<std::vector<ui128>> clientInput(clientBoleNum, std::vector<ui128>(OLE_SIZE));
        {
            u64 row = 0, col = 0;
            for (u64 bIdx = 0; bIdx < ctx.bins.mSimpleBins.mBins.size(); bIdx++) {
                auto& bin = ctx.bins.mSimpleBins.mBins[bIdx];
                auto eNum = bin.mIdx.size();
                for (u64 i = 0; i < eNum; i++) {
                    if (col >= OLE_SIZE) { row++; col = 0; }
                    ui128 elem = blockToU128(ctx.setBlocks[bin.mIdx[i]]);
                    clientInput[row][col] = crtReduceAndPack(elem);
                    col++;
                }

                u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                    ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                    : ctx.bins.mSimpleBins.mMaxBinSize[1];
                for (u64 i = eNum; i < numMax; i++) {
                    if (col >= OLE_SIZE) { row++; col = 0; }
                    NTL::ZZ randElem;
                    NTL::RandomBnd(randElem, ctx.p);
                    ui128 elem = zzToUi128(randElem);
                    clientInput[row][col] = crtReduceAndPack(elem);
                    col++;
                }
            }
        }

        // Client-Client BOLEs (bidirectional based on party index ordering)
        std::vector<std::vector<std::vector<ui128>>> clientRecvOLE(ctx.nParties - 1);
        for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
            if (pIdx == ctx.myIdx) continue;

            if (ctx.myIdx > pIdx) {
                // We are BOLE receiver
                clientRecvOLE[pIdx] = runFourBoleReceiver(clientInput, clientBoleNum, ctx.chlsOLE[pIdx]);
            } else {
                // We are BOLE sender — prepare a/b from random/partUp values
                std::vector<std::vector<ui128>> clientA(clientBoleNum, std::vector<ui128>(OLE_SIZE));
                std::vector<std::vector<ui128>> clientB(clientBoleNum, std::vector<ui128>(OLE_SIZE));

                int row = 0, col = 0;
                for (u64 bIdx = 0; bIdx < updateValueSize; bIdx++) {
                    u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                        ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                        : ctx.bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 eIdx = 0; eIdx < numMax; eIdx++) {
                        if (col >= static_cast<int>(OLE_SIZE)) { row++; col = 0; }
                        ui128 aVal = 0, bVal = 0;
                        for (uint32_t m = 0; m < 4; m++) {
                            uint64_t shift = (3 - m) * 32;
                            uint64_t r = ((randomValue[pIdx][eIdx][bIdx] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                            r = CRT_MODULI[m] - r;
                            aVal |= static_cast<ui128>(r) << shift;
                            bVal |= static_cast<ui128>(((partUpValue[pIdx][eIdx][bIdx] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m]) << shift;
                        }
                        clientA[row][col] = aVal;
                        clientB[row][col] = bVal;
                        col++;
                    }
                }

                runFourBoleSender(clientA, clientB, clientBoleNum, ctx.chlsOLE[pIdx]);
            }
        }

        // Second pass (reversed roles)
        for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
            if (pIdx == ctx.myIdx) continue;

            if (ctx.myIdx < pIdx) {
                clientRecvOLE[pIdx] = runFourBoleReceiver(clientInput, clientBoleNum, ctx.chlsOLE[pIdx]);
            } else {
                std::vector<std::vector<ui128>> clientA(clientBoleNum, std::vector<ui128>(OLE_SIZE));
                std::vector<std::vector<ui128>> clientB(clientBoleNum, std::vector<ui128>(OLE_SIZE));

                int row = 0, col = 0;
                for (u64 bIdx = 0; bIdx < updateValueSize; bIdx++) {
                    u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                        ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                        : ctx.bins.mSimpleBins.mMaxBinSize[1];
                    for (u64 eIdx = 0; eIdx < numMax; eIdx++) {
                        if (col >= static_cast<int>(OLE_SIZE)) { row++; col = 0; }
                        ui128 aVal = 0, bVal = 0;
                        for (uint32_t m = 0; m < 4; m++) {
                            uint64_t shift = (3 - m) * 32;
                            uint64_t r = ((randomValue[pIdx][eIdx][bIdx] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                            r = CRT_MODULI[m] - r;
                            aVal |= static_cast<ui128>(r) << shift;
                            bVal |= static_cast<ui128>(((partUpValue[pIdx][eIdx][bIdx] >> shift) & 0xFFFFFFFF) % CRT_MODULI[m]) << shift;
                        }
                        clientA[row][col] = aVal;
                        clientB[row][col] = bVal;
                        col++;
                    }
                }

                runFourBoleSender(clientA, clientB, clientBoleNum, ctx.chlsOLE[pIdx]);
            }
        }

        // Process member OLE results
        result.oleResult.resize(ctx.nParties - 1);
        for (u64 i = 0; i < ctx.nParties - 1; i++) {
            result.oleResult[i].resize(ctx.bins.mSimpleBins.mMaxBinSize[1]);
            for (u64 j = 0; j < result.oleResult[i].size(); j++)
                result.oleResult[i][j].resize(ctx.bins.mSimpleBins.mBins.size(), 0);
        }

        for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
            if (pIdx == ctx.myIdx || clientRecvOLE[pIdx].empty()) continue;
            int row = 0, col = 0;
            for (u64 bIdx = 0; bIdx < ctx.bins.mSimpleBins.mBins.size(); bIdx++) {
                u64 numMax = (bIdx < ctx.bins.mSimpleBins.mBinCount[0])
                    ? ctx.bins.mSimpleBins.mMaxBinSize[0]
                    : ctx.bins.mSimpleBins.mMaxBinSize[1];
                for (u64 j = 0; j < numMax; j++) {
                    if (col >= static_cast<int>(OLE_SIZE)) { row++; col = 0; }
                    result.oleResult[pIdx][j][bIdx] = clientRecvOLE[pIdx][row][col];
                    col++;
                }
            }
        }

        // Add self terms (r*x + δ for own party)
        for (u64 bIdx = 0; bIdx < ctx.bins.mSimpleBins.mBins.size(); bIdx++) {
            auto& bin = ctx.bins.mSimpleBins.mBins[bIdx];
            if (bin.mIdx.size() > 0) {
                for (u64 i = 0; i < bin.mIdx.size(); i++) {
                    ui128 inputIdx = blockToU128(ctx.setBlocks[bin.mIdx[i]]);
                    ui128 random = randomValue[ctx.myIdx][i][bIdx];
                    ui128 partial = partUpValue[ctx.myIdx][i][bIdx];

                    ui128 res = 0;
                    for (u64 m = 0; m < 4; m++) {
                        uint64_t shift = (3 - m) * 32;
                        uint64_t r = ((random >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                        uint64_t p_val = ((partial >> shift) & 0xFFFFFFFF) % CRT_MODULI[m];
                        uint64_t x_m = static_cast<uint64_t>(inputIdx % CRT_MODULI[m]);
                        uint64_t temp = ((CRT_MODULI[m] - r) * x_m + p_val) % CRT_MODULI[m];
                        res |= static_cast<ui128>(temp) << shift;
                    }
                    result.oleResult[ctx.myIdx][i][bIdx] = res;
                }
            }
        }

        // Sum all OLE results into slot [0]
        for (u64 i = 1; i < ctx.nParties - 1; i++) {
            for (u64 j = 0; j < ctx.bins.mSimpleBins.mMaxBinSize[1]; j++) {
                for (u64 k = 0; k < ctx.bins.mSimpleBins.mBins.size(); k++) {
                    result.oleResult[0][j][k] = crtAdd(result.oleResult[0][j][k], result.oleResult[i][j][k]);
                }
            }
        }
    }

    return result;
}

// ============================================================================
// Phase 3: Reconstruction via OPPRF (members → leader)
// ============================================================================

struct Phase3Result {
    // Leader: endShares[nParties][setSize] — updated shares from all parties
    std::vector<std::vector<ui128>> endShares;
};

static Phase3Result runPhase3(ProtocolContext& ctx, Phase1Result& phase1, Phase2Result& phase2) {
    Phase3Result result;
    u64 totalNumShares = ctx.nParties;
    u64 otCountSend = ctx.bins.mSimpleBins.mBins.size();
    u64 otCountRecv = ctx.bins.mCuckooBins.mBins.size();
    std::vector<u64> fourModuloU64(CRT_MODULI.begin(), CRT_MODULI.end());

    std::vector<std::vector<std::vector<block>>> endPayLoadsDivide(4);
    for (u64 m = 0; m < 4; m++) {
        endPayLoadsDivide[m].resize(ctx.nParties - 1);
        for (u64 j = 0; j < ctx.nParties - 1; j++)
            endPayLoadsDivide[m][j].resize(ctx.setSize);
    }

    // 4 OPPRF rounds for updated shares (roles reversed: members send, leader receives)
    for (u64 m = 0; m < 4; m++) {
        if (ctx.myIdx == ctx.leaderIdx) {
            for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
                OPPRFReceiver receiver;
                KkrtNcoOtReceiver otR;
                KkrtNcoOtSender otS;
                receiver.init(0, ctx.nParties, ctx.setSize, PSI_SEC_PARAM, BIT_SIZE,
                            ctx.chls[pIdx], otCountRecv, otR, otS, ZeroBlock, false);
                receiver.getOPRFkeys(pIdx, ctx.bins, ctx.chls[pIdx], false);
                receiver.recvSSTableBased(pIdx, ctx.bins, endPayLoadsDivide[m][pIdx],
                                         ctx.chls[pIdx], fourModuloU64, m);
            }
        } else {
            OPPRFSender sender;
            KkrtNcoOtSender otS;
            KkrtNcoOtReceiver otR;
            sender.init(0, ctx.nParties, ctx.setSize, PSI_SEC_PARAM, BIT_SIZE,
                       ctx.chls[ctx.leaderIdx], otCountSend, otS, otR,
                       ctx.prng->get<block>(), false);
            sender.getOPRFkeys(ctx.leaderIdx, ctx.bins, ctx.chls[ctx.leaderIdx], false);
            sender.sendSSTableBased(ctx.leaderIdx, ctx.bins, phase1.recvSSPayLoads[m][0],
                                   phase2.oleResult[0], ctx.chls[ctx.leaderIdx], fourModuloU64, m);
        }
        resetBins(ctx.bins);
    }

    // 5th OPPRF round: OLE indices
    std::vector<std::vector<block>> oleIndex(ctx.nParties - 1);
    for (u64 i = 0; i < oleIndex.size(); i++)
        oleIndex[i].resize(ctx.setSize);

    if (ctx.myIdx == ctx.leaderIdx) {
        for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
            OPPRFReceiver receiver;
            KkrtNcoOtReceiver otR;
            KkrtNcoOtSender otS;
            receiver.init(0, ctx.nParties, ctx.setSize, PSI_SEC_PARAM, BIT_SIZE,
                        ctx.chls[pIdx], otCountRecv, otR, otS, ZeroBlock, false);
            receiver.getOPRFkeys(pIdx, ctx.bins, ctx.chls[pIdx], false);
            receiver.recvSSTableBased(pIdx, ctx.bins, oleIndex[pIdx], ctx.chls[pIdx]);
        }
    } else {
        OPPRFSender sender;
        KkrtNcoOtSender otS;
        KkrtNcoOtReceiver otR;
        sender.init(0, ctx.nParties, ctx.setSize, PSI_SEC_PARAM, BIT_SIZE,
                   ctx.chls[ctx.leaderIdx], otCountSend, otS, otR,
                   ctx.prng->get<block>(), false);
        sender.getOPRFkeys(ctx.leaderIdx, ctx.bins, ctx.chls[ctx.leaderIdx], false);
        sender.sendSSTableBased(ctx.leaderIdx, ctx.bins, ctx.chls[ctx.leaderIdx]);
    }

    // Leader assembles final shares
    if (ctx.myIdx == ctx.leaderIdx) {
        // Combine 4 CRT payloads into single 128-bit values
        std::vector<std::vector<block>> endPayLoads(ctx.nParties - 1);
        for (u64 i = 0; i < endPayLoads.size(); i++)
            endPayLoads[i].resize(ctx.setSize);

        for (u64 i = 0; i < endPayLoads.size(); i++) {
            for (u64 j = 0; j < ctx.setSize; j++) {
                ui128 res = 0;
                for (u64 m = 0; m < 4; m++) {
                    ui128 val = blockToU128(endPayLoadsDivide[m][i][j]);
                    ui128 temp = val & 0xFFFFFFFF;
                    res |= static_cast<ui128>(temp) << ((3 - m) * 32);
                }
                endPayLoads[i][j] = u128ToBlock(res);
            }
        }

        result.endShares.resize(totalNumShares);
        for (u64 i = 0; i < totalNumShares; i++)
            result.endShares[i].resize(ctx.setSize);

        // Process members' shares
        for (u64 bIdx = 0; bIdx < ctx.bins.mCuckooBins.mBins.size(); bIdx++) {
            auto& bin = ctx.bins.mCuckooBins.mBins[bIdx];
            if (!bin.isEmpty()) {
                u64 inputIdx = bin.idx();
                for (u64 pIdx = 0; pIdx < ctx.nParties - 1; pIdx++) {
                    ui128 recvVal = blockToU128(endPayLoads[pIdx][inputIdx]);
                    ui128 index = blockToU128(oleIndex[pIdx][inputIdx]) & 0x3F;
                    ui128 oleVal = phase2.oleResult[pIdx][index][bIdx];
                    result.endShares[pIdx][inputIdx] = crtAdd(oleVal, recvVal);
                }
            }
        }

        // Leader's own shares
        for (u64 i = 0; i < ctx.setSize; i++) {
            ui128 res = 0;
            for (u64 m = 0; m < 4; m++) {
                uint64_t shift = (3 - m) * 32;
                ui128 val = zzToUi128(phase1.serverShares[m][i]);
                res |= static_cast<ui128>(val) << shift;
            }
            result.endShares[ctx.nParties - 1][i] = res;
        }
    }

    return result;
}

// ============================================================================
// Phase 4: Intersection (leader only)
// ============================================================================

static std::unordered_set<u64> computeIntersection(
    ProtocolContext& ctx, Phase3Result& phase3)
{
    std::unordered_set<u64> resultSet;
    u64 totalNumShares = ctx.nParties;

    // Transpose: endShares_T[elementIdx][partyIdx] = (eval_point, share)
    std::vector<std::vector<std::pair<int, ui128>>> endSharesT(ctx.setSize);
    for (u64 i = 0; i < ctx.setSize; i++) {
        endSharesT[i].resize(totalNumShares);
        for (u64 j = 0; j < totalNumShares; j++) {
            endSharesT[i][j].first = j + 1;
            endSharesT[i][j].second = phase3.endShares[j][i];
        }
    }

    // Try all C(n-1, t-1) combinations (always including leader)
    auto combinations = getCombinations(totalNumShares - 1, ctx.threshold - 1);
    for (auto& combo : combinations)
        combo.push_back(ctx.leaderIdx);

    for (u64 eIdx = 0; eIdx < ctx.setSize; eIdx++) {
        for (const auto& combo : combinations) {
            if (reconstructAndVerify(combo, endSharesT[eIdx],
                                    ctx.fourModuloZZ, ctx.setZZ[eIdx])) {
                resultSet.insert(eIdx);
                break;
            }
        }
    }

    return resultSet;
}

// ============================================================================
// Public API
// ============================================================================

void TTMpsiLeader::init(const TTMpsiConfig& config) {
    config_ = config;
}

std::vector<std::string> TTMpsiLeader::run(const std::vector<std::string>& inputs) {
    std::cerr << "[YYH26 Leader " << config_.partyID << "] Starting protocol ("
              << config_.numParties << " parties, threshold=" << config_.threshold
              << ", setSize=" << inputs.size() << ")" << std::endl;

    ProtocolContext ctx;
    ctx.setup(config_, inputs);

    syncParties(ctx);

    auto phase1 = runPhase1(ctx);
    std::cerr << "[YYH26 Leader] Phase 1 (secret sharing) done" << std::endl;

    auto phase2 = runPhase2(ctx, phase1);
    std::cerr << "[YYH26 Leader] Phase 2 (update values via BOLE) done" << std::endl;

    auto phase3 = runPhase3(ctx, phase1, phase2);
    std::cerr << "[YYH26 Leader] Phase 3 (reconstruction) done" << std::endl;

    auto intersectionIndices = computeIntersection(ctx, phase3);
    std::cerr << "[YYH26 Leader] Phase 4 (intersection): "
              << intersectionIndices.size() << " elements" << std::endl;

    // Map indices back to original strings (skip padding elements)
    std::vector<std::string> result;
    result.reserve(intersectionIndices.size());
    for (u64 idx : intersectionIndices) {
        if (idx < ctx.realSize)
            result.push_back(inputs[idx]);
    }

    return result;
}

void TTMpsiMember::init(const TTMpsiConfig& config) {
    config_ = config;
}

void TTMpsiMember::run(const std::vector<std::string>& inputs) {
    std::cerr << "[YYH26 Member " << config_.partyID << "] Starting protocol ("
              << config_.numParties << " parties, threshold=" << config_.threshold
              << ", setSize=" << inputs.size() << ")" << std::endl;

    ProtocolContext ctx;
    ctx.setup(config_, inputs);

    syncParties(ctx);

    auto phase1 = runPhase1(ctx);
    std::cerr << "[YYH26 Member " << config_.partyID << "] Phase 1 done" << std::endl;

    auto phase2 = runPhase2(ctx, phase1);
    std::cerr << "[YYH26 Member " << config_.partyID << "] Phase 2 done" << std::endl;

    auto phase3 = runPhase3(ctx, phase1, phase2);
    std::cerr << "[YYH26 Member " << config_.partyID << "] Phase 3 done" << std::endl;

    std::cerr << "[YYH26 Member " << config_.partyID << "] Protocol completed" << std::endl;
}

} // namespace mpsi::yyh26
