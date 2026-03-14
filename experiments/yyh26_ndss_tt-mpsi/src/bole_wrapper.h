#pragma once
#include "config.h"
#include "crt.h"
#include <pke/ole.h>
#include <pke/gazelle-network.h>
#include <pke/bfv.h>
#include <math/params.h>
#include <math/dcrt.h>
#include <cryptoTools/Network/Channel.h>
#include <vector>

using namespace lbcrypto;

namespace yyh26 {

// ── BFV scheme type used throughout ──
typedef DCRT_Poly_Ring<params<ui64>, BOLE_LOGN> PlaintextRing;
typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
typedef EncodingContext<PlaintextRing, CRT_MODULI[0]> EncodingCtx0;
typedef EncodingContext<PlaintextRing, CRT_MODULI[1]> EncodingCtx1;
typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, CRT_MODULI[0]> DcrtParams0;
typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, CRT_MODULI[1]> DcrtParams1;
typedef BFV_DCRT<EncodingCtx0, DcrtParams0> SchemeType0;
typedef BFV_DCRT<EncodingCtx1, DcrtParams1> SchemeType1;

// Common scheme type for key generation (uses first modulus)
typedef BFV_DCRT<EncodingContext<PlaintextRing, CRT_MODULI[0]>,
                 DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, CRT_MODULI[0]>>
    MainSchemeType;

// Wrapper: splits u64 packed CRT values into 2 BOLEReceiverInput sets
template <typename encoding_input_t>
struct TwoBOLEReceiverInputs {
    std::array<BOLEReceiverInput<encoding_input_t>, NUM_CRT_MODULI> receiverInputs;

    TwoBOLEReceiverInputs(ui32 numBlocks)
        : receiverInputs{BOLEReceiverInput<encoding_input_t>(numBlocks),
                         BOLEReceiverInput<encoding_input_t>(numBlocks)} {}

    // Split packed u64 values (low32=mod0, high32=mod1) into per-modulus inputs.
    // input[block][slot] is a u64 packed CRT value.
    void processModule(const std::vector<std::vector<uint64_t>>& input) {
        ui32 numBlocks = receiverInputs[0].numBlocks;
        ui32 oleSize = input.empty() ? 0 : static_cast<ui32>(input[0].size());

        for (ui32 block = 0; block < numBlocks; block++) {
            for (ui32 slot = 0; slot < oleSize; slot++) {
                auto [r0, r1] = crt_unpack(input[block][slot]);
                receiverInputs[0].x[block].vals[slot] =
                    static_cast<ui128>(r0) % CRT_MODULI[0];
                receiverInputs[1].x[block].vals[slot] =
                    static_cast<ui128>(r1) % CRT_MODULI[1];
            }
        }
    }
};

// Run BOLE receiver for a specific modulus index (0 or 1).
// Returns the BOLE output.
template <ui64 p, ui32 logn, ui32 numLimbs, typename SchemeType>
BOLEReceiverOutput<typename SchemeType::encoding_context_t::encoding_input_t>
ReceiverOnline(
    const BOLEReceiverInput<typename SchemeType::encoding_context_t::encoding_input_t>& input,
    const typename SchemeType::SecretKey& sk,
    const SchemeType& scheme_origin,
    osuCryptoNew::Channel& chl)
{
    typedef DCRT_Poly_Ring<params<ui64>, logn> PT;
    typedef EncodingContext<PT, p> EncCtx;
    typedef DCRT_Ring<fast_four_limb_reduction_params> ICR;
    typedef DCRT_Fast_Four_Limb_Reduction_Params<ICR, p> DP;
    typedef BFV_DCRT<EncCtx, DP> ST;

    ST scheme(BOLE_STD_DEV);
    using enc_input_t = typename ST::encoding_context_t::encoding_input_t;

    BOLEReceiverOutput<enc_input_t> output;
    output = BOLEReceiver::online(input, sk, scheme, chl);
    return output;
}

template <ui64 p, ui32 logn, ui32 numLimbs, typename SchemeType>
void SenderOnline(
    BOLESenderInput<typename SchemeType::encoding_context_t::encoding_input_t>& input,
    const typename SchemeType::PublicKey& pk,
    const SchemeType& scheme_origin,
    osuCryptoNew::Channel& chl)
{
    typedef DCRT_Poly_Ring<params<ui64>, logn> PT;
    typedef EncodingContext<PT, p> EncCtx;
    typedef DCRT_Ring<fast_four_limb_reduction_params> ICR;
    typedef DCRT_Fast_Four_Limb_Reduction_Params<ICR, p> DP;
    typedef BFV_DCRT<EncCtx, DP> ST;

    ST scheme(BOLE_STD_DEV);
    using enc_input_t = typename ST::encoding_context_t::encoding_input_t;

    BOLESender::online(input, pk, scheme, chl);
}

} // namespace yyh26
