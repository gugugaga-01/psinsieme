#pragma once

#include "Crypto/PRNG.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <time.h>


#include "../libOLE/third_party/cryptoTools/cryptoTools/Common/Timer.h"
#include "../libOLE/third_party/cryptoTools/cryptoTools/Common/Log.h"

#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/Channel.h"
#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/Session.h"
#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/IOService.h"

#include "../libOLE/src/lib/pke/ole.h"
#include "../libOLE/src/lib/pke/gazelle-network.h"
#include "../libOLE/src/lib/utils/debug.h"
using namespace lbcrypto;
using namespace osuCryptoNew;

std::vector<NTL::ZZ_p> ShareSecret(const NTL::ZZ_p secret,u64 numShares, u64 threshold, u64 numParty, NTL::ZZ p);
std::vector<NTL::ZZ_p> GenerateUpdateValues(u64 numShares, u64 threshold, u64 numParty , NTL::ZZ p);
void partial_gcd(NTL::ZZ_pX &r, NTL::ZZ_pX &u, NTL::ZZ_pX &v, NTL::ZZ_pX &p0, NTL::ZZ_pX &p1, int threshold);
bool gao_interpolate(NTL::vec_ZZ_p &res_vec, NTL::vec_ZZ_p &err_vec,
                     NTL::vec_ZZ_p &x_vec, NTL::vec_ZZ_p &y_vec, int k, int n);
void tparty(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 nTrials);
void tparty_mt(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 nTrials);
__uint128_t ZZ_to_ui128(const NTL::ZZ& zz_value);

ui128 Chinese_Remainder_Theorem(const ui128 share, const std::vector<ui128> Mi, const std::vector<ui128> Ti,  const std::vector<ui64> FourModulo, const ui128 p);


template<ui64 p, ui32 logn, ui32 numLimbs, typename SchemeType1>
BOLEReceiverOutput<typename SchemeType1::encoding_context_t::encoding_input_t> ReceiverOnline(
    const BOLEReceiverInput<typename SchemeType1::encoding_context_t::encoding_input_t>& input,
    const typename SchemeType1::SecretKey& sk,
    const SchemeType1& scheme_origin, 
    osuCryptoNew::Channel& chl
);


template <typename SchemeType>
void bole_receiver();
template <typename SchemeType>
void bole_sender();
template <typename SchemeType>
void launch_ole_batch();
template <typename ptT, ptT p, ui32 numLimbs>
void run_bole(const bool comm_optimized) ;

